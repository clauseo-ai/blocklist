# Clauseo block list v1: the published format (shared with stage F)
(verbatim from the stage E build thread, iris, 2026-11-07)

## What gets published
- **Repo:** public `clauseo-ai/blocklist`.
- **Workflow:** a scheduled GitHub Actions workflow, every 6 h plus manual dispatch, owned by stage F.
- **Release:** a fixed release tag, `current`. Each run **replaces** its two assets:
  - `blocklist-v1.txt.gz`: the list, gzip;
  - `blocklist-v1.txt.gz.minisig`: a **minisign** signature (ed25519) over the exact `.gz` bytes.
- **The app fetches:**
  - `https://github.com/clauseo-ai/blocklist/releases/download/current/blocklist-v1.txt.gz`
  - `https://github.com/clauseo-ai/blocklist/releases/download/current/blocklist-v1.txt.gz.minisig`

## Signature
- **The tool:** `minisign` or `rsign2`. The app verifies with the `minisign-verify` crate, which is already in Cargo.lock.
- **The key:** stage F makes the keypair. The secret key and its password are repo secrets, never printed. The public key line (`RW…`) is given to stage E, who compiles it into the app.
- **The trusted comment, which the signature covers, MUST be exactly:**
  `clauseo-blocklist v1 generated=<RFC3339 UTC, seconds> entries=<n>`
  The app uses `generated` for rollback protection: it never replaces a list with an older one, or with one older than the bundled snapshot. `entries` must match the line count.

## The list (after gunzip): UTF-8, LF line endings, no BOM
```
# clauseo-blocklist v1
# generated: 2026-11-07T06:00:00Z
# sources: urlhaus=<feed timestamp or etag>; phishing-database=<git commit sha>
<host> <tag>
<host> <tag>
...
```
- **Comment lines:** lines starting with `#` are comments; only the 3 above are written.
- **`<host>`:**
  - lowercase ASCII;
  - IDNs in punycode (`xn--…`);
  - **no** scheme, port, path, user info or trailing dot;
  - an IP literal is allowed (IPv4 dotted, or IPv6 in brackets, e.g. `[2001:db8::1]`).
- **`<tag>`:** `m` (malware, from URLhaus) or `p` (phishing, from Phishing.Database). A host in both gets `m`.
- **Order:** lines are **sorted** byte-wise by host, with **no duplicates**.
- **Matching (app side):** a request host matches if it equals a listed host or is a subdomain of one. So the workflow should list the most specific registrable host the feed gives, and **must not** list public suffixes or bare TLDs (drop entries in the Public Suffix List).
- **Size bound:** at most 2,000,000 entries and 64 MiB uncompressed. If a feed would push past that, the workflow fails without publishing, so the last good list stays.

## Feeds (both clear for commercial use)
- **URLhaus** (abuse.ch, CC0): the hosts of **online** malware URLs (`urlhaus.abuse.ch/downloads/text_online/`, or the hostfile). Take the host part.
- **Phishing.Database** (mitchellkrogza, MIT): `phishing-domains-ACTIVE.txt`.
- **No other feed** unless its terms allow commercial use in writing.

## Failure rules (workflow)
- **Any fetch, parse, normalise or size failure:** no publish; the old assets stay.
- **A sudden drop of more than 50 % in entries compared with the current asset:** no publish (feed breakage), and flag it in the run summary.

## Amendments from stage E (2026-11-07)
These amend the text above; where they differ, they win.
- **URLhaus is off.** Its downloads return HTTP 410 and need an Auth-Key, and abuse.ch's terms (§4.1, effective 4 November 2025) put commercial use of URLhaus behind a paid Spamhaus subscription. The sources line carries `urlhaus=none`.
- **Feodo Tracker is added** (abuse.ch, CC0 for commercial use): `https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt`, falling back to `ipblocklist.txt`. Each IP is an IP literal tagged `m`.
- **The sources line** is `# sources: urlhaus=none; feodo=<the feed's "Last updated" stamp, else Last-Modified/ETag>; phishing-database=<git commit sha>`. The app treats the sources values as opaque.
- **Phishing.Database** now lives at `Phishing-Database/Phishing.Database` (it moved from `mitchellkrogza`).
