#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Build the Clauseo block list v1 (see SPEC.md).

fetch -> normalise -> filter -> write list -> gzip -> print the trusted comment.

Python 3 standard library only. Signing is the workflow's job.

Exit status: 0 on success, 1 on any failure (nothing is written to the
output directory unless every check passed).
"""

from __future__ import annotations

import argparse
import datetime as _dt
import email.utils
import gzip
import io
import ipaddress
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

FORMAT_LINE = "# clauseo-blocklist v1"
LIST_NAME = "blocklist-v1.txt"
GZ_NAME = LIST_NAME + ".gz"

MAX_ENTRIES = 2_000_000
MAX_BYTES = 64 * 1024 * 1024
MAX_INVALID_FRACTION = 0.05
MIN_KEEP_FRACTION = 0.5

URLHAUS_URL = "https://urlhaus.abuse.ch/downloads/text_online/"
FEODO_URLS = (
    "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt",
    "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
)
PHISHING_REPO = "Phishing-Database/Phishing.Database"
PHISHING_FILE = "phishing-domains-ACTIVE.txt"
PSL_URL = "https://publicsuffix.org/list/public_suffix_list.dat"

USER_AGENT = "clauseo-blocklist/1 (+https://github.com/clauseo-ai/blocklist)"
TIMEOUT = 120

TAG_PRIORITY = {"m": 0, "p": 1}  # lower wins: m beats p

_LABEL_RE = re.compile(r"^[a-z0-9_-]{1,63}$")
_LAST_UPDATED_RE = re.compile(r"^#\s*Last updated:\s*(.+?)\s*#*\s*$", re.IGNORECASE)


class BuildError(Exception):
    """A failure: no output, non-zero exit."""


# --------------------------------------------------------------------------
# Fetching
# --------------------------------------------------------------------------

class Fetched:
    def __init__(self, text: str, headers: dict[str, str], url: str):
        self.text = text
        self.headers = {k.lower(): v for k, v in headers.items()}
        self.url = url


def fetch(url: str, accept: str | None = None) -> Fetched:
    headers = {"User-Agent": USER_AGENT}
    if accept:
        headers["Accept"] = accept
    token = os.environ.get("GITHUB_TOKEN")
    if token and urllib.parse.urlsplit(url).hostname == "api.github.com":
        headers["Authorization"] = "Bearer " + token
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            body = resp.read()
            hdrs = dict(resp.headers.items())
    except urllib.error.HTTPError as e:
        raise BuildError(f"fetch {url}: HTTP {e.code}") from None
    except (urllib.error.URLError, OSError) as e:
        raise BuildError(f"fetch {url}: {e}") from None
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        raise BuildError(f"fetch {url}: body is not UTF-8") from None
    return Fetched(text, hdrs, url)


def read_file(path: str) -> str:
    try:
        with open(path, "rb") as f:
            return f.read().decode("utf-8")
    except (OSError, UnicodeDecodeError) as e:
        raise BuildError(f"read {path}: {e}") from None


def stamp_from(text: str, headers: dict[str, str] | None) -> str:
    """The feed's own "Last updated" comment, else Last-Modified, else ETag."""
    for line in text.splitlines()[:50]:
        m = _LAST_UPDATED_RE.match(line.strip())
        if m:
            return _rfc3339(m.group(1))
    headers = headers or {}
    if headers.get("last-modified"):
        try:
            dt = email.utils.parsedate_to_datetime(headers["last-modified"])
            return dt.astimezone(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        except (TypeError, ValueError):
            return _opaque(headers["last-modified"])
    if headers.get("etag"):
        return _opaque(headers["etag"])
    raise BuildError("feed has no Last updated comment, Last-Modified or ETag")


def _rfc3339(value: str) -> str:
    """'2026-03-04 14:28:39 UTC' -> '2026-03-04T14:28:39Z'; anything else kept, opaque."""
    m = re.match(r"^(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2})\s*(UTC|Z|GMT)?$", value.strip())
    if m:
        return f"{m.group(1)}T{m.group(2)}Z"
    return _opaque(value)


def _opaque(value: str) -> str:
    # keep the sources line parseable: no ';' and no whitespace runs
    return re.sub(r"\s+", "_", value.strip().replace(";", ",")).strip('"') or "unknown"


def fetch_phishing() -> tuple[str, str]:
    """Return (content, sha) with the content fetched at exactly that commit."""
    repo = json.loads(fetch(f"https://api.github.com/repos/{PHISHING_REPO}",
                            accept="application/vnd.github+json").text)
    full_name = repo.get("full_name")
    branch = repo.get("default_branch")
    if not full_name or not branch:
        raise BuildError("Phishing.Database: GitHub API gave no full_name/default_branch")
    commit = json.loads(fetch(
        f"https://api.github.com/repos/{full_name}/commits/{urllib.parse.quote(branch)}",
        accept="application/vnd.github+json").text)
    sha = commit.get("sha", "")
    if not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise BuildError("Phishing.Database: GitHub API gave no commit sha")
    text = fetch(f"https://raw.githubusercontent.com/{full_name}/{sha}/{PHISHING_FILE}").text
    return text, sha


def fetch_feodo() -> tuple[str, str, str]:
    errors = []
    for url in FEODO_URLS:
        try:
            f = fetch(url)
        except BuildError as e:
            errors.append(str(e))
            continue
        return f.text, stamp_from(f.text, f.headers), url
    raise BuildError("Feodo Tracker: " + "; ".join(errors))


# --------------------------------------------------------------------------
# Normalising
# --------------------------------------------------------------------------

def normalise_host(raw: str) -> tuple[str | None, str | None]:
    """Return (host, None) or (None, reason) where reason is 'idna' or 'invalid'."""
    h = raw.strip().lower()
    if h.startswith("[") and h.endswith("]"):
        h = h[1:-1]
    if h.endswith("."):
        h = h[:-1]
    if not h:
        return None, "invalid"
    if ":" in h:
        try:
            ip6 = ipaddress.IPv6Address(h)
        except ValueError:
            return None, "invalid"
        return f"[{ip6.compressed}]", None
    if not h.isascii():
        try:
            h = h.encode("idna").decode("ascii").lower()
        except (UnicodeError, ValueError):
            return None, "idna"
    try:
        return str(ipaddress.IPv4Address(h)), None
    except ValueError:
        pass
    if len(h) > 253:
        return None, "invalid"
    labels = h.split(".")
    if len(labels) < 2:
        return None, "invalid"
    if not all(_LABEL_RE.match(lab) for lab in labels):
        return None, "invalid"
    if labels[-1].isdigit():
        # all-numeric TLD that isn't a valid IPv4 (e.g. 001.2.3.4, 1.2.3)
        return None, "invalid"
    return h, None


def host_from_url(line: str) -> tuple[str | None, str | None]:
    s = line.strip()
    if "://" not in s:
        s = "http://" + s
    try:
        parts = urllib.parse.urlsplit(s)
        hostname = parts.hostname
        parts.port  # raises ValueError on a bad port
    except ValueError:
        return None, "invalid"
    if not hostname:
        return None, "invalid"
    if ":" in hostname:  # urlsplit strips the brackets from IPv6
        hostname = f"[{hostname}]"
    return normalise_host(hostname)


# --------------------------------------------------------------------------
# Public Suffix List
# --------------------------------------------------------------------------

class PublicSuffixList:
    """The PSL algorithm (https://github.com/publicsuffix/list/wiki/Format):
    normal, wildcard and exception rules; ICANN and private sections alike."""

    def __init__(self, text: str):
        self.rules: set[str] = set()
        self.wildcards: set[str] = set()   # "*.ck" stored as "ck"
        self.exceptions: set[str] = set()  # "!www.ck" stored as "www.ck"
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("//"):
                continue
            rule = line.split()[0]
            kind = None
            if rule.startswith("!"):
                kind, rule = "exception", rule[1:]
            elif rule.startswith("*."):
                kind, rule = "wildcard", rule[2:]
            rule = self._ascii(rule)
            if rule is None:
                continue
            {"exception": self.exceptions, "wildcard": self.wildcards}.get(kind, self.rules).add(rule)
        if ("===BEGIN ICANN DOMAINS===" not in text or "===BEGIN PRIVATE DOMAINS===" not in text
                or not self.rules):
            raise BuildError("Public Suffix List looks wrong: section markers or rules missing")

    @staticmethod
    def _ascii(rule: str) -> str | None:
        rule = rule.lower().rstrip(".")
        if not rule:
            return None
        if rule.isascii():
            return rule
        try:
            return ".".join(lab.encode("idna").decode("ascii") for lab in rule.split("."))
        except (UnicodeError, ValueError):
            return None

    def suffix_label_count(self, host: str) -> int:
        labels = host.split(".")
        n = len(labels)
        for i in range(n):  # longest first; any exception rule wins
            if ".".join(labels[i:]) in self.exceptions:
                return n - i - 1
        best = 1  # the implicit "*" rule
        for i in range(n):
            cand = ".".join(labels[i:])
            k = n - i
            if cand in self.rules:
                best = max(best, k)
            if i >= 1 and cand in self.wildcards:
                best = max(best, k + 1)
        return min(best, n)

    def is_public_suffix(self, host: str) -> bool:
        if host.startswith("[") or _is_ipv4(host):
            return False
        return self.suffix_label_count(host) >= len(host.split("."))


def _is_ipv4(host: str) -> bool:
    try:
        ipaddress.IPv4Address(host)
        return True
    except ValueError:
        return False


# --------------------------------------------------------------------------
# Building
# --------------------------------------------------------------------------

class Feed:
    def __init__(self, name: str, tag: str, text: str, kind: str):
        self.name, self.tag, self.text, self.kind = name, tag, text, kind


def parse_feed(feed: Feed, psl: PublicSuffixList, drops: dict[str, int]) -> set[str]:
    """Return the feed's hosts; count drops; fail on > 5 % invalid lines."""
    hosts: set[str] = set()
    lines = 0
    invalid = 0
    for raw in feed.text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        lines += 1
        if feed.kind == "url":
            host, reason = host_from_url(line)
        elif feed.kind == "ip":
            host, reason = normalise_host(line)
            if host is not None and not (host.startswith("[") or _is_ipv4(host)):
                host, reason = None, "invalid"
        else:
            host, reason = normalise_host(line)
        if host is None:
            invalid += 1
            key = f"{feed.name}:{reason}"
            drops[key] = drops.get(key, 0) + 1
            continue
        if psl.is_public_suffix(host):
            key = f"{feed.name}:public_suffix"
            drops[key] = drops.get(key, 0) + 1
            continue
        if host in hosts:
            key = f"{feed.name}:duplicate"
            drops[key] = drops.get(key, 0) + 1
            continue
        hosts.add(host)
    if lines == 0:
        raise BuildError(f"{feed.name}: feed has no entries")
    if invalid > MAX_INVALID_FRACTION * lines:
        raise BuildError(
            f"{feed.name}: {invalid} of {lines} lines invalid "
            f"({100 * invalid / lines:.2f} % > 5 %); the feed's format may have changed")
    return hosts


def merge(per_feed: list[tuple[str, set[str]]], drops: dict[str, int]) -> dict[str, str]:
    entries: dict[str, str] = {}
    for tag, hosts in sorted(per_feed, key=lambda t: TAG_PRIORITY[t[0]]):
        for h in hosts:
            if h in entries:
                if entries[h] != tag:
                    key = f"overlap:{tag}_lost_to_{entries[h]}"
                    drops[key] = drops.get(key, 0) + 1
                continue
            entries[h] = tag
    return entries


def render(entries: dict[str, str], generated: str, sources: str) -> bytes:
    hosts = sorted(entries, key=lambda h: h.encode("utf-8"))
    out = [FORMAT_LINE, f"# generated: {generated}", f"# sources: {sources}"]
    out.extend(f"{h} {entries[h]}" for h in hosts)
    return ("\n".join(out) + "\n").encode("utf-8")


def gzip_bytes(data: bytes) -> bytes:
    buf = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=buf, compresslevel=9, mtime=0) as gz:
        gz.write(data)
    return buf.getvalue()


def check_limits(entries: int, size: int) -> None:
    if entries > MAX_ENTRIES:
        raise BuildError(f"{entries} entries exceeds the limit of {MAX_ENTRIES}")
    if size > MAX_BYTES:
        raise BuildError(f"{size} bytes uncompressed exceeds the limit of {MAX_BYTES}")


def check_drop(entries: int, previous: int | None) -> None:
    if previous is None:
        return
    if entries < MIN_KEEP_FRACTION * previous:
        raise BuildError(
            f"entries fell from {previous} to {entries} (below 50 % of the current asset); "
            "possible feed breakage, not publishing")


def trusted_comment(generated: str, entries: int) -> str:
    return f"clauseo-blocklist v1 generated={generated} entries={entries}"


def utc_now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def write_summary(lines: list[str]) -> None:
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not path:
        return
    with open(path, "a", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def summary_lines(entries: dict[str, str], drops: dict[str, int], stamps: dict[str, str],
                  gz_size: int, comment: str) -> list[str]:
    per_tag: dict[str, int] = {}
    for t in entries.values():
        per_tag[t] = per_tag.get(t, 0) + 1
    out = ["## Clauseo block list build", "", f"Trusted comment: `{comment}`", "",
           "| tag | entries |", "|---|---|"]
    out += [f"| {t} | {per_tag.get(t, 0)} |" for t in ("m", "p")]
    out += [f"| total | {len(entries)} |", "", "| drop reason | count |", "|---|---|"]
    out += [f"| {k} | {v} |" for k, v in sorted(drops.items())] or ["| (none) | 0 |"]
    out += ["", "| source | stamp |", "|---|---|"]
    out += [f"| {k} | {v} |" for k, v in stamps.items()]
    out += ["", f"gzip size: {gz_size} bytes"]
    return out


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--out-dir", required=True, help="where blocklist-v1.txt(.gz) go")
    p.add_argument("--psl-file", help="local public_suffix_list.dat instead of fetching")
    p.add_argument("--phishing-file", help="local phishing-domains-ACTIVE.txt instead of fetching")
    p.add_argument("--phishing-sha", help="commit sha for --phishing-file (required with it)")
    p.add_argument("--feodo-file", help="local Feodo Tracker ip blocklist instead of fetching")
    p.add_argument("--no-feodo", action="store_true", help="leave Feodo Tracker out (tests only)")
    p.add_argument("--urlhaus", choices=("off", "fetch"), default="off",
                   help="URLhaus is off by default: its download is gone (HTTP 410) and its "
                        "terms need a commercial subscription; see README")
    p.add_argument("--urlhaus-file", help="local URLhaus text_online file (parser tests)")
    p.add_argument("--previous-entries", type=int,
                   help="entry count of the current, verified asset (the 50 %% drop rule)")
    p.add_argument("--generated", help="override the generated time (tests only)")
    args = p.parse_args(argv)

    drops: dict[str, int] = {}
    stamps: dict[str, str] = {}
    try:
        if args.phishing_file and not args.phishing_sha:
            raise BuildError("--phishing-file needs --phishing-sha")
        psl = PublicSuffixList(read_file(args.psl_file) if args.psl_file else fetch(PSL_URL).text)

        feeds: list[Feed] = []
        # urlhaus
        if args.urlhaus_file:
            text = read_file(args.urlhaus_file)
            stamps["urlhaus"] = stamp_from(text, None)
            feeds.append(Feed("urlhaus", "m", text, "url"))
        elif args.urlhaus == "fetch":
            f = fetch(URLHAUS_URL)
            stamps["urlhaus"] = stamp_from(f.text, f.headers)
            feeds.append(Feed("urlhaus", "m", f.text, "url"))
        else:
            stamps["urlhaus"] = "none"
        # feodo
        if args.feodo_file:
            text = read_file(args.feodo_file)
            stamps["feodo"] = stamp_from(text, None)
            feeds.append(Feed("feodo", "m", text, "ip"))
        elif args.no_feodo:
            stamps["feodo"] = "none"
        else:
            text, stamps["feodo"], url = fetch_feodo()
            print(f"feodo: using {url}", file=sys.stderr)
            feeds.append(Feed("feodo", "m", text, "ip"))
        # phishing.database
        if args.phishing_file:
            text, sha = read_file(args.phishing_file), args.phishing_sha
        else:
            text, sha = fetch_phishing()
        stamps["phishing-database"] = sha
        feeds.append(Feed("phishing-database", "p", text, "domain"))

        per_feed = [(f.tag, parse_feed(f, psl, drops)) for f in feeds]
        entries = merge(per_feed, drops)

        generated = args.generated or utc_now()
        sources = "; ".join(f"{k}={stamps[k]}" for k in ("urlhaus", "feodo", "phishing-database"))
        data = render(entries, generated, sources)
        check_limits(len(entries), len(data))
        check_drop(len(entries), args.previous_entries)
        gz = gzip_bytes(data)
        comment = trusted_comment(generated, len(entries))

        os.makedirs(args.out_dir, exist_ok=True)
        with open(os.path.join(args.out_dir, LIST_NAME), "wb") as f:
            f.write(data)
        with open(os.path.join(args.out_dir, GZ_NAME), "wb") as f:
            f.write(gz)
    except BuildError as e:
        print(f"error: {e}", file=sys.stderr)
        write_summary(["## Clauseo block list build FAILED", "", f"**Reason:** {e}", "",
                       "Nothing was published; the current assets stay."])
        return 1

    lines = summary_lines(entries, drops, stamps, len(gz), comment)
    print("\n".join(lines), file=sys.stderr)
    write_summary(lines)
    print(comment)
    return 0


if __name__ == "__main__":
    sys.exit(main())
