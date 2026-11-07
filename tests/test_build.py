# SPDX-License-Identifier: GPL-3.0-or-later
"""Unit tests for build.py. No network: every input comes from tests/fixtures/."""

import contextlib
import gzip
import io
import os
import shutil
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

import build  # noqa: E402

FIX = os.path.join(HERE, "fixtures")
PSL = os.path.join(FIX, "psl.dat")
PHISH = os.path.join(FIX, "phishing-domains-ACTIVE.txt")
FEODO = os.path.join(FIX, "feodo-ipblocklist.txt")
URLHAUS = os.path.join(FIX, "urlhaus-text_online.txt")
SHA = "0123456789abcdef0123456789abcdef01234567"
GEN = "2026-11-07T06:00:00Z"


def load_psl():
    with open(PSL, encoding="utf-8") as f:
        return build.PublicSuffixList(f.read())


class NormaliseTest(unittest.TestCase):
    def test_upper_case_and_trailing_dot(self):
        self.assertEqual(build.normalise_host("WWW.Example.COM."), ("www.example.com", None))

    def test_only_one_trailing_dot_stripped(self):
        self.assertEqual(build.normalise_host("example.com..")[0], None)

    def test_idn_to_punycode(self):
        self.assertEqual(build.normalise_host("Bücher.example")[0], "xn--bcher-kva.example")
        self.assertEqual(build.normalise_host("пример.рф")[0], "xn--e1afmkfd.xn--p1ai")

    def test_idn_failure_is_counted_as_idna(self):
        # a label longer than 63 octets after encoding fails the idna codec
        self.assertEqual(build.normalise_host("ü" * 70 + ".com"), (None, "idna"))

    def test_ipv4_and_ipv6(self):
        self.assertEqual(build.normalise_host("198.51.100.7")[0], "198.51.100.7")
        self.assertEqual(build.normalise_host("2001:DB8:0:0::1")[0], "[2001:db8::1]")
        self.assertEqual(build.normalise_host("[2001:db8::1]")[0], "[2001:db8::1]")

    def test_invalid_hosts(self):
        for bad in ("localhost", "a..b", "-" * 64 + ".com", "%20x.com", "x y.com",
                    "1.2.3", "001.2.3.4", ("a" * 60 + ".") * 5 + "com", ""):
            self.assertEqual(build.normalise_host(bad), (None, "invalid"), bad)

    def test_underscore_and_hyphen_allowed(self):
        self.assertEqual(build.normalise_host("_dmarc.ex-ample.com")[0], "_dmarc.ex-ample.com")

    def test_host_from_url_ports_userinfo_ipv6(self):
        cases = {
            "http://MALWARE.Example.COM:8080/x": "malware.example.com",
            "https://user:pass@creds.example.org/p": "creds.example.org",
            "http://[2001:db8::2]:81/bin": "[2001:db8::2]",
            "http://dot.example.net./y": "dot.example.net",
            "http://bücher.example/dl": "xn--bcher-kva.example",
            "example.com:443/path": "example.com",
        }
        for url, want in cases.items():
            self.assertEqual(build.host_from_url(url), (want, None), url)

    def test_host_from_url_bad_port(self):
        self.assertEqual(build.host_from_url("http://example.com:99999/"), (None, "invalid"))


class PslTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.psl = load_psl()

    def test_normal_rule(self):
        self.assertTrue(self.psl.is_public_suffix("co.uk"))
        self.assertFalse(self.psl.is_public_suffix("evil.co.uk"))

    def test_bare_tld(self):
        self.assertTrue(self.psl.is_public_suffix("com"))
        # not in the list: the implicit "*" rule still makes a bare TLD a suffix
        self.assertTrue(self.psl.is_public_suffix("zz"))

    def test_wildcard_rule(self):
        self.assertTrue(self.psl.is_public_suffix("bar.kawasaki.jp"))
        self.assertFalse(self.psl.is_public_suffix("foo.bar.kawasaki.jp"))
        self.assertTrue(self.psl.is_public_suffix("nope.ck"))
        self.assertTrue(self.psl.is_public_suffix("ck"))

    def test_exception_rule(self):
        self.assertFalse(self.psl.is_public_suffix("city.kawasaki.jp"))
        self.assertFalse(self.psl.is_public_suffix("www.ck"))

    def test_private_section(self):
        self.assertTrue(self.psl.is_public_suffix("blogspot.com"))
        self.assertFalse(self.psl.is_public_suffix("x.blogspot.com"))

    def test_idn_rule(self):
        self.assertTrue(self.psl.is_public_suffix("xn--p1ai"))
        self.assertFalse(self.psl.is_public_suffix("xn--e1afmkfd.xn--p1ai"))

    def test_ip_never_a_suffix(self):
        self.assertFalse(self.psl.is_public_suffix("1.2.3.4"))
        self.assertFalse(self.psl.is_public_suffix("[2001:db8::1]"))

    def test_broken_list_rejected(self):
        with self.assertRaises(build.BuildError):
            build.PublicSuffixList("<html>not a psl</html>")


def run_cli(*extra, phish=PHISH, feodo=FEODO):
    out = tempfile.mkdtemp()
    args = ["--out-dir", out, "--psl-file", PSL, "--phishing-file", phish,
            "--phishing-sha", SHA, "--generated", GEN]
    args += ["--feodo-file", feodo] if feodo else ["--no-feodo"]
    args += list(extra)
    stdout, stderr = io.StringIO(), io.StringIO()
    env_summary = os.environ.pop("GITHUB_STEP_SUMMARY", None)
    try:
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = build.main(args)
    finally:
        if env_summary is not None:
            os.environ["GITHUB_STEP_SUMMARY"] = env_summary
    return code, out, stdout.getvalue(), stderr.getvalue()


class OutputTest(unittest.TestCase):
    def setUp(self):
        self.dirs = []

    def tearDown(self):
        for d in self.dirs:
            shutil.rmtree(d, ignore_errors=True)

    def cli(self, *a, **kw):
        r = run_cli(*a, **kw)
        self.dirs.append(r[1])
        return r

    def read_list(self, out):
        with open(os.path.join(out, build.LIST_NAME), "rb") as f:
            return f.read()

    def test_full_list_exact(self):
        code, out, stdout, _ = self.cli("--urlhaus-file", URLHAUS)
        self.assertEqual(code, 0)
        data = self.read_list(out)
        expected = (
            "# clauseo-blocklist v1\n"
            "# generated: 2026-11-07T06:00:00Z\n"
            "# sources: urlhaus=2026-11-07T05:00:01Z; feodo=2026-03-04T14:28:39Z; "
            f"phishing-database={SHA}\n"
            "1.2.3.4 m\n"
            "198.51.100.7 m\n"
            "50.16.16.211 m\n"
            "[2001:db8::1] m\n"
            "[2001:db8::2] m\n"
            "b.example.com p\n"
            "both.example.net m\n"
            "city.kawasaki.jp p\n"
            "creds.example.org m\n"
            "deep.nope.ck p\n"
            "dot.example.net m\n"
            "evil.co.uk p\n"
            "example.com p\n"
            "foo.bar.kawasaki.jp p\n"
            "malware.example.com m\n"
            "trailing.example.org p\n"
            "under_score.example.com p\n"
            "upper.example.com p\n"
            "www.ck p\n"
            "x.blogspot.com p\n"
            "xn--bcher-kva.example m\n"
            "xn--e1afmkfd.xn--p1ai p\n"
        ).encode()
        self.assertEqual(data, expected)
        self.assertEqual(stdout, f"clauseo-blocklist v1 generated={GEN} entries=22\n")

    def test_header_exact_with_urlhaus_off(self):
        code, out, stdout, _ = self.cli()
        self.assertEqual(code, 0)
        lines = self.read_list(out).decode().split("\n")
        self.assertEqual(lines[:3], [
            "# clauseo-blocklist v1",
            "# generated: 2026-11-07T06:00:00Z",
            f"# sources: urlhaus=none; feodo=2026-03-04T14:28:39Z; phishing-database={SHA}",
        ])

    def test_sorted_unique_m_over_p_lf_no_bom(self):
        code, out, stdout, _ = self.cli()
        data = self.read_list(out)
        self.assertFalse(data.startswith(b"\xef\xbb\xbf"))
        self.assertNotIn(b"\r", data)
        self.assertTrue(data.endswith(b"\n"))
        body = [ln for ln in data.split(b"\n") if ln and not ln.startswith(b"#")]
        hosts = [ln.split(b" ")[0] for ln in body]
        self.assertEqual(hosts, sorted(set(hosts)))
        # 1.2.3.4 is in both the phishing (p) and Feodo (m) fixtures
        self.assertIn(b"1.2.3.4 m", body)
        self.assertNotIn(b"1.2.3.4 p", body)
        n = int(stdout.strip().rsplit("entries=", 1)[1])
        self.assertEqual(n, len(body))

    def test_merge_m_wins_regardless_of_order(self):
        drops = {}
        e = build.merge([("p", {"a.com", "b.com"}), ("m", {"a.com"})], drops)
        self.assertEqual(e, {"a.com": "m", "b.com": "p"})
        self.assertEqual(drops, {"overlap:p_lost_to_m": 1})

    def test_drops_counted(self):
        code, out, _, stderr = self.cli()
        self.assertEqual(code, 0)
        self.assertIn("| phishing-database:public_suffix | 4 |", stderr)
        # a bare "com" fails the two-label rule first, so it is counted as invalid
        self.assertIn("| phishing-database:invalid | 1 |", stderr)
        self.assertIn("| phishing-database:duplicate | 1 |", stderr)

    def test_deterministic_gzip(self):
        a = build.gzip_bytes(b"hello\n")
        self.assertEqual(a, build.gzip_bytes(b"hello\n"))
        self.assertEqual(a[4:8], b"\x00\x00\x00\x00")  # mtime 0
        self.assertEqual(a[3] & 0x08, 0)              # no FNAME
        _, out1, _, _ = self.cli()
        _, out2, _, _ = self.cli()
        with open(os.path.join(out1, build.GZ_NAME), "rb") as f1, \
                open(os.path.join(out2, build.GZ_NAME), "rb") as f2:
            g1 = f1.read()
            self.assertEqual(g1, f2.read())
        self.assertEqual(gzip.decompress(g1), self.read_list(out1))


class FailureTest(unittest.TestCase):
    def test_more_than_5_percent_invalid_fails(self):
        tmp = tempfile.mkdtemp()
        try:
            path = os.path.join(tmp, "p.txt")
            # 100 lines, 6 invalid -> 6 % > 5 %
            with open(path, "w") as f:
                f.write("".join(f"host{i}.example.com\n" for i in range(94)))
                f.write("bad host\n" * 6)
            code, out, stdout, stderr = run_cli(phish=path, feodo=None)
            self.assertEqual(code, 1)
            self.assertEqual(stdout, "")
            self.assertIn("invalid", stderr)
            self.assertFalse(os.path.exists(os.path.join(out, build.GZ_NAME)))
            shutil.rmtree(out)
            # exactly 5 % passes
            with open(path, "w") as f:
                f.write("".join(f"host{i}.example.com\n" for i in range(95)))
                f.write("bad host\n" * 5)
            code, out, _, _ = run_cli(phish=path, feodo=None)
            self.assertEqual(code, 0)
            shutil.rmtree(out)
        finally:
            shutil.rmtree(tmp)

    def test_5_percent_rule_applies_to_feodo(self):
        tmp = tempfile.mkdtemp()
        try:
            path = os.path.join(tmp, "f.txt")
            with open(path, "w") as f:
                f.write("# Last updated: 2026-11-07 00:00:00 UTC\n1.2.3.4\nnot-an-ip.example.com\n")
            code, out, _, stderr = run_cli(feodo=path)
            self.assertEqual(code, 1)
            self.assertIn("feodo", stderr)
            shutil.rmtree(out)
        finally:
            shutil.rmtree(tmp)

    def test_limits(self):
        build.check_limits(build.MAX_ENTRIES, build.MAX_BYTES)
        with self.assertRaises(build.BuildError):
            build.check_limits(build.MAX_ENTRIES + 1, 10)
        with self.assertRaises(build.BuildError):
            build.check_limits(10, build.MAX_BYTES + 1)

    def test_drop_rule(self):
        build.check_drop(50, None)   # first publish: skipped
        build.check_drop(50, 100)    # exactly 50 % kept: ok
        with self.assertRaises(build.BuildError):
            build.check_drop(49, 100)

    def test_drop_rule_via_cli_writes_summary(self):
        tmp = tempfile.mkdtemp()
        summary = os.path.join(tmp, "summary.md")
        old = os.environ.get("GITHUB_STEP_SUMMARY")
        os.environ["GITHUB_STEP_SUMMARY"] = summary
        try:
            out = os.path.join(tmp, "out")
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                code = build.main(["--out-dir", out, "--psl-file", PSL, "--phishing-file", PHISH,
                                   "--phishing-sha", SHA, "--feodo-file", FEODO,
                                   "--generated", GEN, "--previous-entries", "1000"])
            self.assertEqual(code, 1)
            self.assertFalse(os.path.exists(os.path.join(out, build.GZ_NAME)))
            with open(summary) as f:
                text = f.read()
            self.assertIn("FAILED", text)
            self.assertIn("below 50 %", text)
        finally:
            if old is None:
                os.environ.pop("GITHUB_STEP_SUMMARY", None)
            else:
                os.environ["GITHUB_STEP_SUMMARY"] = old
            shutil.rmtree(tmp)

    def test_stamp_fallbacks(self):
        self.assertEqual(build.stamp_from("x\n", {"last-modified": "Tue, 30 Jun 2026 04:53:05 GMT"}),
                         "2026-06-30T04:53:05Z")
        self.assertEqual(build.stamp_from("x\n", {"etag": '"1f7-65"'}), "1f7-65")
        with self.assertRaises(build.BuildError):
            build.stamp_from("x\n", {})


if __name__ == "__main__":
    unittest.main()
