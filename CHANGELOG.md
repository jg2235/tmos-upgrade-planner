# Changelog

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
