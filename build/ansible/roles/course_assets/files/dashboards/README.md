# Course dashboard provenance

Recovered from devb's owner-provided production-reference exports on 2026-11-11.
The export manifest SHA256 is
`55f86319e5e022557c657cd0b0924fab1f3fd360603202c6f35d7eb7f5a21ce9`.
Each source file below was independently hashed before import. Restricted
artifacts and the optional Hedgehog Agent Stats dashboard were not imported.

The files here contain each API response's `dashboard` object, with its local
numeric `id` set to null and datasource variables' `current.text/value` bound to
Prometheus/prometheus or Loki/loki. The source selections contain obsolete
Grafana Cloud import placeholders. The course UIDs, titles and `${datasource}` references are preserved.
Two adaptations follow the 2026-11-12 candidate course run: the Syslog Errors
query filters by the selected switch hostname, and the Fabric BGP Neighbor and
BGP Session State panels use `maxDataPoints: 100` to render a 24-hour view.
At the tested 1440-pixel viewport, the latter requests 15-minute resolution;
brief transitions can be missed. Zoom in for finer detail. Stored metrics and
the Dropped connections panel are unchanged. All other panels and queries are
preserved. These changes were verified in an isolated browser preview and have
not yet been baked into or accepted on a new VM image. Output hashes are
selected in `build/releases/r0.yaml`; this table identifies the original exports.

| Export UID | Source SHA256 |
| --- | --- |
| ab831ceb-cf5c-474a-b7e9-83dcd075c218 | 48874e1a60b82fc179d473669f69926c2befede2ff31abab18103d6c56f9c42c |
| f8a648b9-5510-49ca-9273-952ba6169b7v | 5052eb75b642ddd03320f7bbaf60312a774616013d3602304404628114fb2a0c |
| a5e5b12d-b340-4753-8f83-af8d54304822 | 00b43f46c502abe6cffcb4ea5e9f7ce8e666fa2019aaa2b6a2dc795e42dedc96 |
| c42a51e5-86a8-42a0-b1c9-d1304ae655bv | 0da125c5496ab128dafc0cf70bfd7ce452f0bfd5b4d297feb26a90b8f63b3076 |
| fb08315c-cabb-4da7-9db9-2e17278f1781 | c48683e489867a7ead94ded5495dc65dfea892b12cb9c171537ab90ccd7a1477 |
| rYdddlPWv | 10b84a464cbfee37567366f854f2aa2290ac5bd48337afb0dac6151895386af1 |

The rendering uses the native [kube-prometheus-stack 65.2.0 settings](https://github.com/prometheus-community/helm-charts/blob/kube-prometheus-stack-65.2.0/charts/kube-prometheus-stack/values.yaml)
and [Grafana file provisioning](https://grafana.com/docs/grafana/latest/administration/provisioning/).
File identity and chart rendering do not establish live datasource health or
course completion.
