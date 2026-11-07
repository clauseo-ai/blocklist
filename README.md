# Clauseo block list

A signed list of hosts that serve malware or phishing. The
[Clauseo](https://clauseo.chat) app uses it to block them. A scheduled GitHub
Actions workflow rebuilds it every 6 hours from public feeds. Each build is
signed with [minisign](https://jedisct1.github.io/minisign/) and replaces the
two assets on the release tagged `current`.

## What the app fetches

- https://github.com/clauseo-ai/blocklist/releases/download/current/blocklist-v1.txt.gz
- https://github.com/clauseo-ai/blocklist/releases/download/current/blocklist-v1.txt.gz.minisig

The app checks the signature with a public key compiled into it, and it never
replaces its list with an older one.

## Format

[SPEC.md](SPEC.md) has the full specification (v1). In short, after gunzip
the list is UTF-8 with LF line endings and no BOM:

```
# clauseo-blocklist v1
# generated: 2026-11-07T06:00:00Z
# sources: urlhaus=none; feodo=<feed timestamp>; phishing-database=<git commit sha>
<host> <tag>
...
```

- `<host>` is a lowercase ASCII host name (IDNs in punycode) or an IP literal
  (IPv4 dotted, IPv6 in brackets).
- `<tag>` is `m` for malware or `p` for phishing. A host on both lists gets `m`.
- Lines are sorted byte-wise by host, with no duplicates.
- A host also matches all of its subdomains. For that reason entries in the
  [Public Suffix List](https://publicsuffix.org/) (bare TLDs, `co.uk`,
  `blogspot.com`, …) are never listed. Every longer host is kept exactly as
  the feed gives it.

The signature's trusted comment is exactly
`clauseo-blocklist v1 generated=<same time as the header> entries=<number of host lines>`.

## Verifying by hand

The public key is in [`minisign.pub`](minisign.pub) at the root of this repo.
<!-- minisign.pub: the maintainers commit the real public key file here (repo root). The workflow refuses to run without it. -->

```sh
curl -LO https://github.com/clauseo-ai/blocklist/releases/download/current/blocklist-v1.txt.gz
curl -LO https://github.com/clauseo-ai/blocklist/releases/download/current/blocklist-v1.txt.gz.minisig
minisign -V -p minisign.pub -m blocklist-v1.txt.gz
# -> Signature and comment signature verified
# -> Trusted comment: clauseo-blocklist v1 generated=... entries=...
gzip -dc blocklist-v1.txt.gz | grep -vc '^#'   # equals entries=
```

## How a build works and when it fails

[`build.py`](build.py) uses only the Python 3 standard library. It fetches the
feeds and the Public Suffix List, normalises and filters the hosts, writes the
list, gzips it deterministically (`mtime` 0, no file name) and prints the
trusted comment. The workflow ([`.github/workflows/publish.yml`](.github/workflows/publish.yml))
then signs the `.gz`, checks the signature against `minisign.pub` and uploads
both assets.

Nothing is published, and the current assets stay as they are, when:

- any fetch fails, or the Public Suffix List doesn't look like one;
- more than 5 % of a feed's non-comment lines are invalid hosts (that means
  the feed's format changed);
- the list would have more than 2,000,000 entries or be over 64 MiB
  uncompressed;
- the new list has fewer than 50 % of the entries in the current asset. The
  current asset's count is trusted only after its signature verifies with
  `minisign.pub`, and if it doesn't verify the run fails. The first publish
  (the asset returns 404) skips this check;
- `minisign.pub` is missing, signing fails, or the new signature or its
  trusted comment doesn't verify.

Each run's summary gives the entry counts per tag, the drops per reason
(invalid, IDN failure, public suffix, duplicate, overlap between tags), the
source stamps, or the reason the run failed.

Local run, and the tests (no network needed for the tests):

```sh
python3 build.py --out-dir out              # live feeds
python3 -m unittest discover -s tests
python3 build.py --help                     # local feed/PSL files for offline runs
```

## Sources and licences

| Feed | Tag | Licence |
|---|---|---|
| [Phishing.Database](https://github.com/Phishing-Database/Phishing.Database), `phishing-domains-ACTIVE.txt`, fetched at a pinned commit | `p` | MIT. The copyright notice and licence text are in [`LICENSES/Phishing.Database-MIT.txt`](LICENSES/Phishing.Database-MIT.txt). |
| [abuse.ch Feodo Tracker](https://feodotracker.abuse.ch/), `ipblocklist_recommended.txt` (falls back to `ipblocklist.txt`) | `m` | CC0 for commercial and non-commercial use, per the [abuse.ch terms of use](https://abuse.ch/terms-of-use/) §3 |
| [Public Suffix List](https://publicsuffix.org/) | n/a | MPL-2.0. Used only for filtering: nothing from it appears in the list. `tests/fixtures/psl.dat` is a small subset of it, under MPL-2.0. |

**What Feodo Tracker covers:** its entries are botnet command-and-control IP
addresses. The app only catches connections made straight to those IPs, not
host names that resolve to them.

**No other feed is added unless its terms allow commercial use in writing.**

### Considered and not used (checked 2026-11-07)

- **URLhaus (abuse.ch).** It was meant to be the malware feed (`urlhaus=` in
  the sources line). Its downloads, `downloads/text_online/` included, now
  return HTTP 410 Gone and need a personal Auth-Key. The
  [abuse.ch terms of use](https://abuse.ch/terms-of-use/) (effective 4 November
  2025) also list URLhaus in §4.1 among the platforms whose commercial use "may
  require a paid subscription" through Spamhaus. It is off, and the sources
  line says `urlhaus=none`. `build.py` keeps its parser and tests
  (`--urlhaus`, `--urlhaus-file`). Once the terms are cleared, turning it back
  on means adding `--urlhaus fetch` to the workflow's build step (one line),
  plus pointing `URLHAUS_URL` in `build.py` at the Auth-Key export URL with the
  key held in a secret.
- **The Block List Project** ([`blocklistproject/Lists`](https://github.com/blocklistproject/Lists),
  "malware" and "phishing"):
  - The repo is archived on GitHub, and `malware.txt` was last modified on
    2026-07-18.
  - Its licences conflict: the repo's LICENSE is the Unlicense, but the
    header of `malware.txt` says MIT.
  - It re-hosts restricted feeds. Its malware list pulls
    `zachlagden/Pi-hole-Optimized-Blocklists` `malicious.txt`, whose own README
    names URLhaus (abuse.ch terms) and Phishing Army (CC BY-NC 4.0,
    non-commercial) among its sources.
  - At 2.66 million entries, it is over the 2,000,000 limit on its own.

## Licence

The code in this repo is licensed under `GPL-3.0-or-later` (see [LICENSE](LICENSE)),
like Clauseo. The published list is built from the feeds above, under their
own licences.
