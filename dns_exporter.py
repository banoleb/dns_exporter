#!/usr/bin/env python3
"""
DNS Exporter
============
Polls configured DNS modules on a fixed interval and exposes Prometheus-format
metrics at a single /metrics endpoint.

Metrics
-------
dnsexp_dns_query_success   gauge   — 1.0 if ALL modules succeeded in the last
                                     2 scrape cycles, otherwise 0.0
dnsexp_dns_query_failed    counter — cumulative total of failed queries since start
dnsexp_dns_errors          counter — per-module/query/reason failure count
dnsexp_dns_metrics         counter — per-query/rcode/answer successful response count
"""

import socket
import sys
import threading
import time
import logging
from collections import defaultdict, deque
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse

import yaml
import dns.exception
import dns.message
import dns.name
import dns.query
import dns.rcode
import dns.rdatatype

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger("dns_exporter")


# ---------------------------------------------------------------------------
# Prometheus text-format helpers
# ---------------------------------------------------------------------------

def _fmt_labels(label_pairs: tuple) -> str:
    """
    Convert a sorted tuple of (name, value) pairs into a Prometheus label string.
    E.g. (('module','m1'),('protocol','udp')) → 'module="m1",protocol="udp"'
    """
    return ",".join(f'{k}="{v}"' for k, v in label_pairs)


def _label_key(**labels: str) -> tuple:
    """Return a hashable, deterministically-ordered label key."""
    return tuple(sorted(labels.items()))


# ---------------------------------------------------------------------------
# Thread-safe metrics store
# ---------------------------------------------------------------------------

class MetricsStore:
    """
    Holds all runtime counters/gauges and renders them as Prometheus exposition text.

    Two counter dicts use a sorted-tuple key so that rendering is deterministic
    without any extra sorting step on the key itself.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        # {label_key: float}  —  cumulative counts
        self._errors: dict[tuple, float] = defaultdict(float)
        self._metrics: dict[tuple, float] = defaultdict(float)
        self._total_failed: float = 0.0
        # True = the scrape cycle had zero errors; False otherwise
        self._cycles: deque[bool] = deque(maxlen=2)

    # ------------------------------------------------------------------
    # Write API
    # ------------------------------------------------------------------

    def record_success(self, **labels: str) -> None:
        key = _label_key(**labels)
        with self._lock:
            self._metrics[key] += 1.0

    def record_error(self, **labels: str) -> None:
        key = _label_key(**labels)
        with self._lock:
            self._errors[key] += 1.0
            self._total_failed += 1.0

    def push_cycle(self, all_ok: bool) -> None:
        with self._lock:
            self._cycles.append(all_ok)

    # ------------------------------------------------------------------
    # Read API
    # ------------------------------------------------------------------

    def render(self) -> str:
        with self._lock:
            lines: list[str] = []

            # ---- dnsexp_dns_query_success --------------------------------
            success = 1.0 if (self._cycles and all(self._cycles)) else 0.0
            lines += [
                "# HELP dnsexp_dns_query_success "
                "1 if every module in the last 2 scrape cycles had no errors, else 0",
                "# TYPE dnsexp_dns_query_success gauge",
                f"dnsexp_dns_query_success {success}",
            ]

            # ---- dnsexp_dns_query_failed ---------------------------------
            lines += [
                "# HELP dnsexp_dns_query_failed "
                "Total number of DNS query failures since process start",
                "# TYPE dnsexp_dns_query_failed counter",
                f"dnsexp_dns_query_failed_total {self._total_failed}",
            ]

            # ---- dnsexp_dns_errors ---------------------------------------
            lines += [
                "# HELP dnsexp_dns_errors "
                "Cumulative DNS query error count by module, server, query, and failure reason",
                "# TYPE dnsexp_dns_errors counter",
            ]
            for key in sorted(self._errors):
                lines.append(
                    f"dnsexp_dns_errors{{{_fmt_labels(key)}}} {self._errors[key]}"
                )

            # ---- dnsexp_dns_metrics --------------------------------------
            lines += [
                "# HELP dnsexp_dns_metrics "
                "Cumulative successful DNS query count by server, query, rcode, and answer count",
                "# TYPE dnsexp_dns_metrics counter",
            ]
            for key in sorted(self._metrics):
                lines.append(
                    f"dnsexp_dns_metrics{{{_fmt_labels(key)}}} {self._metrics[key]}"
                )

            return "\n".join(lines) + "\n"


# Global singleton
store = MetricsStore()


# ---------------------------------------------------------------------------
# DNS query execution
# ---------------------------------------------------------------------------

def _resolve_host(hostname: str) -> str:
    """Resolve a hostname to an IP address string (IPv4 preferred)."""
    try:
        info = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_DGRAM)
        return info[0][4][0]
    except socket.gaierror:
        return hostname  # pass-through; will fail at query time


def parse_server_url(server_url: str) -> tuple[str, str, int]:
    """
    Parse a server URL such as ``udp://9.9.9.9:53`` or ``tcp://1.1.1.1:53``
    and return ``(protocol, ip_address, port)``.
    """
    parsed = urlparse(server_url)
    protocol = (parsed.scheme or "udp").lower()
    hostname = parsed.hostname or server_url
    port = parsed.port or 53
    ip = _resolve_host(hostname)
    return protocol, ip, port


def do_dns_query(
    *,
    module: str,
    server: str,
    query_name: str,
    query_type: str,
    timeout: float,
    custom_labels: dict[str, str],
) -> bool:
    """
    Execute one DNS query using *dns.query* (bypassing the system resolver so
    we talk directly to the configured server).

    Records either a success sample in *dnsexp_dns_metrics* or an error sample
    in *dnsexp_dns_errors* and returns *True* / *False* accordingly.
    """
    protocol, ip, port = parse_server_url(server)
    qtype_upper = query_type.upper()

    try:
        qname = dns.name.from_text(query_name)
        rdtype = dns.rdatatype.from_text(qtype_upper)
        request = dns.message.make_query(qname, rdtype)

        if protocol == "tcp":
            response = dns.query.tcp(request, ip, port=port, timeout=timeout)
        else:
            response = dns.query.udp(request, ip, port=port, timeout=timeout)

        rcode_val = response.rcode()
        rcode_text = dns.rcode.to_text(rcode_val)

        if rcode_val == dns.rcode.NOERROR:
            answer_count = len(response.answer)
            store.record_success(
                answer=str(answer_count),
                protocol=protocol,
                query_name=query_name,
                query_type=qtype_upper,
                rcode=rcode_text,
                server=server,
                **custom_labels,
            )
            logger.debug(
                "OK  %s %s via %s → rcode=%s answers=%d",
                qtype_upper, query_name, server, rcode_text, answer_count,
            )
            return True

        # Non-NOERROR DNS response counts as an error
        _record_query_error(
            module, protocol, server, query_name, qtype_upper,
            rcode_text, custom_labels,
        )
        return False

    except dns.exception.Timeout:
        _record_query_error(
            module, protocol, server, query_name, qtype_upper,
            "timeout", custom_labels,
        )
        logger.warning("TIMEOUT  %s %s via %s", qtype_upper, query_name, server)
        return False

    except OSError as exc:
        _record_query_error(
            module, protocol, server, query_name, qtype_upper,
            "network_error", custom_labels,
        )
        logger.warning("NETWORK ERROR  %s %s via %s: %s", qtype_upper, query_name, server, exc)
        return False

    except dns.exception.DNSException as exc:
        reason = type(exc).__name__
        _record_query_error(
            module, protocol, server, query_name, qtype_upper,
            reason, custom_labels,
        )
        logger.warning("DNS ERROR  %s %s via %s: %s", qtype_upper, query_name, server, exc)
        return False

    except Exception as exc:  # noqa: BLE001
        _record_query_error(
            module, protocol, server, query_name, qtype_upper,
            "unknown", custom_labels,
        )
        logger.error(
            "UNEXPECTED  %s %s via %s: %s", qtype_upper, query_name, server, exc
        )
        return False


def _record_query_error(
    module: str,
    protocol: str,
    server: str,
    query_name: str,
    query_type: str,
    reason: str,
    custom_labels: dict[str, str],
) -> None:
    store.record_error(
        module=module,
        protocol=protocol,
        server=server,
        query_name=query_name,
        query_type=query_type,
        reason=reason,
        **custom_labels,
    )


# ---------------------------------------------------------------------------
# Scrape loop
# ---------------------------------------------------------------------------

def run_cycle(config: dict) -> None:
    """Run one scrape cycle — query every module and push the cycle result."""
    modules = config.get("modules", {})
    all_ok = True

    for module_name, mod_cfg in modules.items():
        server = mod_cfg.get("server", "")
        timeout = float(mod_cfg.get("timeout", 5))
        custom_labels = {
            str(k): str(v) for k, v in mod_cfg.get("custom_labels", {}).items()
        }

        for query in mod_cfg.get("queries", []):
            ok = do_dns_query(
                module=module_name,
                server=server,
                query_name=query.get("query_name", ""),
                query_type=query.get("query_type", "A"),
                timeout=timeout,
                custom_labels=custom_labels,
            )
            if not ok:
                all_ok = False

    store.push_cycle(all_ok)
    logger.info("Cycle complete — all_ok=%s", all_ok)


def scrape_loop(config: dict) -> None:
    """Background thread: poll all modules every *scrape_interval* seconds."""
    interval = float(config.get("exporter", {}).get("scrape_interval", 30))
    while True:
        try:
            run_cycle(config)
        except Exception as exc:  # noqa: BLE001
            logger.error("Unhandled error in scrape cycle: %s", exc)
        time.sleep(interval)


# ---------------------------------------------------------------------------
# HTTP server
# ---------------------------------------------------------------------------

class MetricsHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/metrics":
            body = store.render().encode("utf-8")
            self.send_response(200)
            self.send_header(
                "Content-Type", "text/plain; version=0.0.4; charset=utf-8"
            )
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()

    def log_message(self, fmt: str, *args) -> None:  # noqa: ANN002
        logger.debug("HTTP %s", fmt % args)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    config_path = sys.argv[1] if len(sys.argv) > 1 else "config.yaml"

    with open(config_path) as fh:
        config = yaml.safe_load(fh)

    port = int(config.get("exporter", {}).get("port", 9253))

    logger.info("Starting DNS exporter — port=%d  config=%s", port, config_path)

    scraper = threading.Thread(target=scrape_loop, args=(config,), daemon=True)
    scraper.start()

    server = HTTPServer(("0.0.0.0", port), MetricsHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Shutting down")


if __name__ == "__main__":
    main()
