# Security telemetry playbooks

Working playbooks for the data layer of detection: getting logs off hosts and appliances, into a SIEM, in a shape that detections and auditors can both use.

Each playbook is written to be used rather than read once — exact table names, real limits, the traps that cost days, and the control mappings a regulated organisation has to produce anyway.

| # | Playbook | Covers |
| --- | --- | --- |
| 01 | [Sentinel log onboarding](playbooks/01-sentinel-log-onboarding/) | Windows, Linux and on-prem into Microsoft Sentinel. Azure Monitor Agent, DCRs as code, ASIM and OCSF field mapping, enrichment, cost, completeness, and mappings to CIS v8.1, the Microsoft cloud security benchmark, MITRE ATT&CK and DORA. Includes optional [Logstash and Beats](playbooks/01-sentinel-log-onboarding/logstash-and-beats.md) and [Cribl Stream and Edge](playbooks/01-sentinel-log-onboarding/cribl-stream-and-edge.md) collection paths. |
| 02 | AI and agentic telemetry | Planned. Logging LLM and agent workloads, mapped to MITRE ATLAS. |

## What is in playbook 01

```
playbooks/01-sentinel-log-onboarding/
  README.md                     the playbook
  logstash-and-beats.md         optional collection path
  cribl-stream-and-edge.md      optional collection path
  dcr/                          deployable Data Collection Rules
  xpath/                        Windows event XPath selectors, loaded by the Bicep
  bicep/                        AVM-based deployment
  tests/                        Pester tests that run before deployment
  diagrams/                     architecture diagrams
.github/workflows/              OIDC deployment pipeline
```

## Why DCRs live in git and not in the portal

Editing a DCR in the Azure portal overwrites JSON-only features, including ingest-time transformations, with no warning proportionate to the consequence. Once a rule carries a transformation it is infrastructure-as-code only. Everything here assumes that.

Note that Microsoft Sentinel repositories cannot deploy DCRs — they handle analytics rules, hunting queries, workbooks, parsers, playbooks, automation rules and watchlists. DCRs need their own pipeline, which is what `.github/workflows/` is for.

## Status

Playbook 01 is current as of October 2026. Where a fact carries a date or a version, it is because that fact moves — check it before putting it in a design document.

## Licence

MIT. See [LICENSE](LICENSE).
