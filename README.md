# tmos-upgrade-planner

**BIG-IP QKView ↔ TMOS Release-Note association engine.**
Pulls a device's configuration from an F5 iHealth QKView (or local config
files), parses TMOS Release Notes HTML, and produces a scored, color-coded
HTML + Excel advisory that answers: *which target release is safest for
**this** configuration, and which parts of the config are most exposed?*

Built on the iHealth client patterns from
[BIG-IP_iHealth_QKview_Parser](https://github.com/jg2235/BIG-IP_iHealth_QKview_Parser)
(API host `ihealth-api.f5.com`, OAuth2 client-credentials, HTTP 202
retry/backoff).

---

## What it produces

| Output | Contents |
|---|---|
| `*.html` | Self-contained report: release comparison + RECOMMENDED verdict, susceptibility heat map, feature × release matrix, per-release association breakouts, upgrade risks, platform CVEs, already-remediated, unmatched, methodology |
| `*.xlsx` | Sheets: Summary (with comparison + verdict), HeatMap, Associations + UpgradeRisks (consolidated, filterable), `Assoc <ver>` / `Risks <ver>` per-release tabs, PlatformCVEs, AlreadyRemediated, Unmatched |

### Scoring rubric (deterministic, auditable)

| Band | Score | Meaning |
|---|---|---|
| exact | 85–100 | Feature term matched in the item's **Conditions** text — the config required to trigger the defect |
| probable | 60–84 | Feature term in Symptoms/Title only |
| component | 30–59 | Config uses the item's component; no feature-specific term (scaled by severity) |
| weak | 1–29 | Weak lexical hits only |
| none | 0 | No association — listed under Unmatched |

### Release comparison (RECOMMENDED verdict)

Per target release: config-matched bugs **fixed** by upgrading, **residual**
bugs (matched to config, fixed in another target but *not* this one),
known-issue **upgrade risks**, platform CVEs resolved.
**Risk score = residual + known-issue risks; lowest wins**, tie-broken by most
bugs fixed. Caveat noted in-report: newer branches publish shorter known-issue
lists partly from less field exposure — weigh branch maturity alongside counts.

### Susceptibility heat map

Feature × target-release grid, ordered most → least susceptible, continuous
green→red ramp. Cell index = weighted sum of matched items that **remain
present after upgrading** (known issues on the target branch + config-matched
bugs not fixed by the target). Weights: exact ×3, probable ×2, component ×1,
weak ×0.25.

### Module gating (no false positives)

`sys provision` from `bigip_base.conf` is authoritative for module presence —
default/system objects shipped in every bigip.conf (`/Common/access`,
`/Common/bot-defense`, `/Common/dos`, firewall singletons) never count as a
module being "in use." Without provisioning info the denylist still applies
and the tool warns to supply `--base-conf`.

Other logic: BIND/named CVEs route to config-relevant when DNS/GTM is in use,
platform-wide otherwise. Items fixed at or below the running version on the
same branch land in Already Remediated (fixed only in `17.1.3.1` while running
`17.1.3` correctly does **not** count).

---

## Install

```bash
git clone https://github.com/jg2235/tmos-upgrade-planner.git
cd tmos-upgrade-planner
pip install -r requirements.txt
```

Python 3.9+. Tested on WSL/Ubuntu.

## Usage

Download the release-note HTML files for your candidate releases from
my.f5.com and place them anywhere (paths are free-form; `--rn` is repeated
**once per file**).

### Live — pull config from an iHealth QKView

```bash
export IHEALTH_CLIENT_ID="..."        # iHealth GUI -> Settings
export IHEALTH_CLIENT_SECRET="..."

python3 qkview-tmos-planner.py --qkview-id 26497324 \
  --rn BIG-IP-17.5.1.5-0.0.6.html \
  --rn BIG-IP-17.5.1.6-0.0.25.html \
  --rn BIG-IP-21.1.0-0.0.38.html \
  --out-prefix myreport
```

Fetches `bigip.conf`, `bigip_gtm.conf`, `bigip_base.conf` via the Files API;
device hostname and running version auto-detected from diagnostics.

### Offline — local config files

```bash
python3 qkview-tmos-planner.py --offline \
  --bigip-conf /path/bigip.conf --gtm-conf /path/bigip_gtm.conf \
  --base-conf /path/bigip_base.conf \
  --rn BIG-IP-17.5.1.5-0.0.6.html --rn BIG-IP-17.5.1.6-0.0.25.html \
  --rn BIG-IP-21.1.0-0.0.38.html \
  --current-version 17.1.3 --hostname mybigip --out-prefix myreport
```

### Smoke test with bundled synthetic config

```bash
python3 qkview-tmos-planner.py --offline \
  --bigip-conf testdata/bigip.conf --gtm-conf testdata/gtm.conf \
  --base-conf testdata/bigip_base.conf \
  --rn <your-release-notes>.html --out-prefix smoke
```

`testdata/` exercises LTM virtuals/pools/monitors, client/server SSL (OCSP
stapling, cipher groups, TLS1.3-only), HTTP/2, WebSocket, OneConnect, LTM
policies, iRules (HTTP + DNS), cookie/source-addr persistence, SNAT, DNS
profiles (DNS Express, DNSSEC, local BIND), GTM wide-IPs/pools/servers/
topology/listeners, DNSSEC keys/zones — with an LTM/GTM-only provisioning
base conf to exercise the module gate.

## Verifying file integrity after transfer

Paste-transfers corrupt this file (~1,800 lines). Always move it as a file
(`cp` from `/mnt/c/...` in WSL, `scp`, or git clone) and verify:

```bash
python3 -m py_compile qkview-tmos-planner.py && echo CLEAN
```

## Security posture

- Credentials only via env vars (`IHEALTH_CLIENT_ID` / `IHEALTH_CLIENT_SECRET`);
  never CLI args, never on disk; `.gitignore` blocks common credential files
- TLS verification always on; bounded retries; no subprocess/shell/eval
- Matching is fully offline — configuration data never leaves the host
- Reports contain hostnames/IPs/object names: treat them at QKView sensitivity
  (generated `*.html`/`*.xlsx` are git-ignored by default)

## Limitations

- Term taxonomy tuned to TMOS 17.x/21.x release-note vocabulary; extend
  `_feature_defs()` for new features
- Component-band matches are intentionally low-confidence and are collapsed
  in the HTML by design
- Not affiliated with F5, Inc. The iHealth API is not covered by F5 support.
  Verify all upgrade decisions against the linked K-articles.

## License

MIT — see [LICENSE](LICENSE).
