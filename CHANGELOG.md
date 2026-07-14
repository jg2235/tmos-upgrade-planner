# Changelog

## v1.2.0 — 2026-07
- Multi-QKView support: --qkview-id is repeatable and accepts comma-separated
  lists; one report pair per QKView named <out-prefix>_<qkview-id>.html/.xlsx
- Release notes parsed once and reused across all QKViews; single OAuth token
  shared across fetches
- Per-QKView failure isolation: a bad ID logs an error and processing
  continues; exit code 3 signals partial failure

## v1.1.0 — 2026-07
- Score-band color scheme inverted to severity-oriented across HTML and Excel:
  exact = red, probable = dark orange, component-level = yellow,
  weak = light green (heat map green->red susceptibility ramp unchanged)

## v1.0.0 — 2026-07
- iHealth live mode (`--qkview-id`): OAuth2 client-credentials, Files API pull of
  bigip.conf / bigip_gtm.conf / bigip_base.conf, 202-retry with exponential
  backoff, device version/hostname auto-detect from diagnostics
- Offline mode (`--offline`) with local config files
- Release-note HTML parser: cumulative fix tables, vulnerability/functional
  categories, known-issue tables, detail blocks (Component/Symptoms/Conditions/
  Impact/Workaround/Fix/Fixed Versions)
- Deterministic matching engine, 0-100 scoring rubric (Conditions-weighted)
- Provisioning gate: `sys provision` is authoritative for module presence;
  default/system objects (e.g. /Common/access, /Common/bot-defense) excluded
- Target-release comparison with residual-risk model and RECOMMENDED verdict
- Configuration susceptibility heat map (post-upgrade bug exposure), HTML + Excel
- Consolidated HTML report + Excel workbook with per-release breakout tabs
- Platform-wide CVE separation (BIND routed to config when DNS/GTM in use)
- Already-remediated detection on the running branch
