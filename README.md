# dns_exporter

A lightweight Prometheus exporter that periodically queries DNS servers and
exposes the results at a single `/metrics` endpoint.

Built with **Python 3.12** and **dnspython 2.8.0**.

---

## Features

- Single `/metrics` endpoint — compatible with any Prometheus scrape config.
- Polls all configured modules every `scrape_interval` seconds (default 30 s).
- Supports **UDP** and **TCP** DNS protocols.
- Per-module **custom labels** (e.g. `env`, `custom_label_1`, …) propagated to
  every metric emitted by that module.
- Detects timeouts, network errors, and non-NOERROR DNS responses separately.

---

## Metrics

| Metric | Type | Description |
|---|---|---|
| `dnsexp_dns_query_success` | gauge | `1.0` if every module in the last **2 scrape cycles** had no errors; `0.0` otherwise |
| `dnsexp_dns_query_failed_total` | counter | Cumulative total of all failed queries since process start |
| `dnsexp_dns_errors` | counter | Per-module / server / query / reason failure count |
| `dnsexp_dns_metrics` | counter | Per-server / query / rcode / answer-count success count |

### Example output

```
dnsexp_dns_query_success 1.0

dnsexp_dns_query_failed_total 3044.0

dnsexp_dns_errors{module="dns-query-adns1",protocol="udp",query_name="5.114.223.11.in-addr.arpa",query_type="PTR",reason="timeout",server="udp://rs2.example.org:53"} 3044.0

dnsexp_dns_metrics{answer="5",protocol="udp",query_name="gmail.com",query_type="MX",rcode="NOERROR",server="udp://dns.quad9.net:53"} 479.0
```

---

## Configuration

Edit `config.yaml` before starting the exporter.

```yaml
exporter:
  port: 9253          # /metrics HTTP port
  scrape_interval: 30 # seconds between polling cycles

modules:
  my-module:
    server: "udp://9.9.9.9:53"   # udp:// or tcp://
    timeout: 5                    # seconds
    queries:
      - query_name: "example.com"
        query_type: "A"
    custom_labels:
      custom_label_1: "quad9"
      env: "production"
```

Any key/value pair under `custom_labels` is appended as a Prometheus label to
every `dnsexp_dns_errors` and `dnsexp_dns_metrics` sample emitted by that module.

---

## Running

### Directly with Python

```bash
pip install -r requirements.txt
python dns_exporter.py config.yaml
# metrics available at http://localhost:9253/metrics
```

### With Docker

```bash
docker build -t dns-exporter .
docker run -p 9253:9253 -v $(pwd)/config.yaml:/app/config.yaml dns-exporter
```

### With Docker Compose

```bash
docker compose up -d
```

---

## Prometheus scrape config

```yaml
scrape_configs:
  - job_name: dns_exporter
    static_configs:
      - targets: ["localhost:9253"]
```
