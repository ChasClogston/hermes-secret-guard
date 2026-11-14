"""Static inventory tests. Synthetic homes only: no Hermes, no keychain, no network.

    python tests/test_inventory.py        (needs PyYAML or Hermes's bundled YAML reader)
"""
import argparse
import hashlib
import importlib.util
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import types
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, REPO)
import inventory as inv  # noqa: E402

CANARY = "synthetic--inventory-canary-7f3a"
NAME_CANARY = "zq-name-canary-91"            # a valid profile id, so it becomes a home
SKIP_CANARY = "ZQ skipped canary 55"         # not a valid id, so it is skipped
ENABLED = "plugins:\n  enabled:\n    - other-plugin\n    - secret-guard\nsecrets:\n  secret_guard:\n    enabled: true\n"
NOT_LISTED = "plugins:\n  enabled:\n    - other-plugin\nmodel:\n  api_key: %s\n" % CANARY
MANIFEST = ("name: secret-guard\nversion: %s\nplatforms:\n  - macos\nprovides_hooks:\n"
            + "".join("  - %s\n" % h for h in inv.EXPECTED_HOOKS))
IS_ROOT = hasattr(os, "geteuid") and os.geteuid() == 0


def write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as fh:
        fh.write(text)


def plugin(home, version="1.2.0", commit=None, body=None):
    d = os.path.join(home, "plugins", "secret-guard")
    write(os.path.join(d, "plugin.yaml"), body if body is not None else MANIFEST % version)
    if commit:
        write(os.path.join(d, ".git", "HEAD"), "ref: refs/heads/main\n")
        write(os.path.join(d, ".git", "refs", "heads", "main"), commit + "\n")
    return d


def snapshot(root):
    snap = {}
    for base, dirs, files in os.walk(root, followlinks=False):
        for n in dirs + files:
            p = os.path.join(base, n)
            st = os.lstat(p)
            digest = ""
            if os.path.isfile(p) and not os.path.islink(p) and os.access(p, os.R_OK):
                with open(p, "rb") as fh:
                    digest = hashlib.sha256(fh.read()).hexdigest()
            snap[os.path.relpath(p, root)] = (st.st_mode, st.st_size, st.st_mtime_ns, digest)
    return snap


def cli(*argv):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        try:
            code = inv.main(list(argv))
        except SystemExit as exc:
            code = exc.code
    return code, out.getvalue(), err.getvalue()


class Tree(unittest.TestCase):
    def setUp(self):
        self.base = os.path.realpath(tempfile.mkdtemp(prefix="sg-inv-"))
        self.root = os.path.join(self.base, "hermes")
        write(os.path.join(self.root, "config.yaml"), ENABLED)
        plugin(self.root, commit="a" * 40)
        self.other = os.path.join(self.base, "elsewhere")
        write(os.path.join(self.other, "config.yaml"), ENABLED)
        plugin(self.other, commit="a" * 40)

    def tearDown(self):
        for base, dirs, _files in os.walk(self.base):
            for d in dirs:
                try:
                    os.chmod(os.path.join(base, d), 0o700)
                except OSError:
                    pass
        shutil.rmtree(self.base, ignore_errors=True)

    def P(self, name):
        return os.path.join(self.root, "profiles", name)

    def home(self, name, config=ENABLED, with_plugin=True, **kw):
        if config is not None:
            write(os.path.join(self.P(name), "config.yaml"), config)
        else:
            os.makedirs(self.P(name), exist_ok=True)
        if with_plugin:
            plugin(self.P(name), **kw)
        return self.P(name)

    def report(self, system="Darwin", roots=None, **kw):
        return inv.run(roots or [(self.root, "test")], system=system, **kw)

    def rows(self, rep=None):
        return {r["name"]: r for r in (rep or self.report())["homes"]}

    def one(self, name, **kw):
        rep = self.report(**kw)
        return self.rows(rep)[name], rep


class States(Tree):
    def test_each_state_is_told_apart(self):
        self.home("absent", NOT_LISTED, with_plugin=False)
        self.home("disabled", NOT_LISTED, commit="a" * 40)
        self.home("disabled-explicit", ENABLED.replace("secrets:", "  disabled:\n    - secret-guard\nsecrets:"))
        self.home("listed-no-files", ENABLED, with_plugin=False)
        self.home("inherits-nothing", "model:\n  name: x\n")      # the root is enabled; this profile says nothing
        self.home("keysource-off", ENABLED.replace("enabled: true", "enabled: false"))
        self.home("null-lists", "plugins:\n  enabled:\n  disabled:\n")
        self.home("few-hooks", body="name: secret-guard\nversion: 1.2.0\nplatforms: [macos]\nprovides_hooks:\n  - pre_tool_call\n")
        self.home("no-hook-list", body="name: secret-guard\nversion: 1.2.0\n")
        rep = self.report()
        r = self.rows(rep)
        want = {"default": "configured", "absent": "absent", "disabled": "disabled", "disabled-explicit": "disabled",
                "listed-no-files": "absent", "inherits-nothing": "disabled", "keysource-off": "configured",
                "null-lists": "disabled", "few-hooks": "configured", "no-hook-list": "configured"}
        self.assertEqual({k: r[k]["state"] for k in want}, want)
        self.assertTrue(rep["complete"])
        j = lambda k: " | ".join(r[k]["notes"])               # noqa: E731
        self.assertIn("no plugin files at this location", j("listed-no-files"))
        self.assertIn("plugins.disabled and in plugins.enabled", j("disabled-explicit"))
        self.assertIn("key source is off", j("keysource-off"))
        self.assertIn("does not declare", j("few-hooks"))
        self.assertEqual((r["few-hooks"]["hooks_declared"], r["default"]["hooks_declared"]), ("1 of 6", "6 of 6"))
        self.assertIn("declares no hook list", j("no-hook-list"))             # informational, not malformed
        self.assertEqual(r["inherits-nothing"]["listed_enabled"], "no")

    def test_no_state_claims_protection_or_runtime(self):
        rep = self.report()
        text = inv.render(rep) + inv.render(rep, paths=True)
        self.assertNotIn("protected", text.lower())
        self.assertIn("runtime behaviour was not tested", text)
        self.assertIn("Bundled, project and pip-installed plugins are not inspected", text)
        self.assertIn("location inspected: user plugin directory", text)
        self.assertTrue(all(r["runtime"] == "not tested" for r in rep["homes"]))

    def test_versions_and_commits(self):
        self.home("stale", version="1.0.0", commit="b" * 40)
        rep = self.report(expect_version="1.2.0", expect_commit="a" * 12)
        r = self.rows(rep)
        self.assertEqual((r["default"]["version"], r["default"]["commit"]), ("1.2.0", "a" * 40))
        stale = " | ".join(r["stale"]["notes"])
        self.assertIn("version 1.0.0 is not the expected one", stale)
        self.assertIn("commit bbbbbbbbbbbb is not the expected one", stale)
        self.assertIn("differ between homes", stale)
        self.assertNotIn("not the expected", " | ".join(r["default"]["notes"]))

    def test_commit_is_read_from_git_files_or_left_unknown(self):
        d = os.path.join(self.other, "plugins", "secret-guard", ".git")
        get = lambda: self.rows(self.report(roots=[(self.other, "t")]))["default"]["commit"]     # noqa: E731
        os.remove(os.path.join(d, "refs", "heads", "main"))
        write(os.path.join(d, "packed-refs"), "# pack-refs\n" + "c" * 40 + " refs/heads/main\n")
        self.assertEqual(get(), "c" * 40)
        write(os.path.join(d, "HEAD"), "d" * 40 + "\n")
        self.assertEqual(get(), "d" * 40)
        for bad in ("ref: ../../../../etc/x\n", "ref: /etc/passwd\n", "ref: refs/heads/../../x\n", "e" * 41 + "\n", CANARY + "\n"):
            write(os.path.join(d, "HEAD"), bad)
            self.assertEqual(get(), "unknown", bad)
        shutil.rmtree(d)
        self.assertEqual(get(), "unknown")

    def test_unsupported_platform_is_never_configured(self):
        self.home("absent", NOT_LISTED, with_plugin=False)
        for system in ("Linux", "Windows", ""):
            rep = self.report(system=system)
            r = self.rows(rep)
            self.assertEqual((r["default"]["state"], r["absent"]["state"], rep["counts"]["configured"]),
                             ("unsupported", "absent", 0), system)


class I1_RequestedScope(Tree):
    """A root that was asked for and could not be inspected makes the inventory incomplete."""

    def test_missing_root_alone(self):
        rep = self.report(roots=[(os.path.join(self.base, "nope"), "t")])
        self.assertFalse(rep["complete"])
        self.assertEqual(rep["homes"], [])
        self.assertIn("root 1 does not exist", rep["incomplete_reasons"])
        code, out, _ = cli("--root", os.path.join(self.base, "nope"))
        self.assertEqual(code, 1)
        self.assertIn("INCOMPLETE", out)

    def test_valid_root_plus_missing_root(self):
        rep = self.report(roots=[(self.root, "a"), (os.path.join(self.base, "nope"), "b")])
        self.assertFalse(rep["complete"])
        self.assertEqual(rep["counts"]["configured"], 1)           # the valid root is still reported
        self.assertIn("root 2 does not exist", rep["incomplete_reasons"])

    def test_root_that_is_a_file_or_special(self):
        f = os.path.join(self.base, "afile"); write(f, "x")
        fifo = os.path.join(self.base, "afifo"); os.mkfifo(fifo)
        for path in (f, fifo):
            rep = self.report(roots=[(path, "t")])
            self.assertFalse(rep["complete"]); self.assertIn("root 1 is not a folder", rep["incomplete_reasons"])

    def test_root_that_cannot_be_examined(self):
        real = os.stat

        def fake(path, *a, **k):
            if str(path) == self.root:
                raise PermissionError(13, "denied")
            return real(path, *a, **k)
        with mock.patch("os.stat", fake):
            rep = self.report()
        self.assertFalse(rep["complete"])
        self.assertIn("could not be examined (PermissionError)", "; ".join(rep["incomplete_reasons"]))

    def test_unlistable_profiles_folder(self):
        self.home("a")
        real = os.scandir

        def fake(path="."):
            if str(path) == os.path.join(self.root, "profiles"):
                raise PermissionError(13, "denied")
            return real(path)
        with mock.patch("os.scandir", fake):
            rep = self.report()
        self.assertFalse(rep["complete"])
        self.assertIn("profiles folder of root 1 could not be listed", "; ".join(rep["incomplete_reasons"]))

    def test_root_that_disappears_after_discovery(self):
        self.home("a")
        real = inv.discover

        def vanish(roots):
            found = real(roots)
            shutil.rmtree(self.root)
            return found
        with mock.patch.object(inv, "discover", vanish):
            rep = self.report()
        self.assertFalse(rep["complete"])
        self.assertEqual(rep["counts"]["configured"], 0)
        self.assertEqual(rep["counts"]["unknown"], 2)

    @unittest.skipIf(IS_ROOT, "root ignores file modes")
    def test_real_permission_failures(self):
        self.home("a"); self.home("b"); self.home("c")
        os.chmod(os.path.join(self.P("a"), "config.yaml"), 0)
        os.chmod(self.P("b"), 0)
        os.chmod(os.path.join(self.P("c"), "plugins"), 0)
        rep = self.report()
        r = self.rows(rep)
        self.assertEqual([r[k]["state"] for k in "abc"], ["unreadable"] * 3)
        self.assertFalse(rep["complete"])
        os.chmod(os.path.join(self.root, "profiles"), 0)
        self.assertFalse(self.report()["complete"])
        os.chmod(os.path.join(self.root, "profiles"), 0o700)
        os.chmod(self.root, 0)
        rep = self.report()
        self.assertFalse(rep["complete"]); self.assertEqual(rep["counts"]["configured"], 0)


class I2_Discovery(Tree):
    """Hermes's own profile rules: valid id, an identity marker, no tombstone."""

    def kinds(self, rep):
        return {os.path.basename(s["path"]): s["kind"] for s in rep["skipped"]}

    def test_every_identity_marker_makes_a_home(self):
        for i, marker in enumerate(inv.IDENTITY_MARKERS):
            if marker != "config.yaml":
                write(os.path.join(self.P("m%d" % i), marker), "")
        os.makedirs(self.P("dangling")); os.symlink(os.path.join(self.base, "gone"), os.path.join(self.P("dangling"), ".env"))
        rep = self.report()
        r = self.rows(rep)
        for name in ["m%d" % i for i in range(1, len(inv.IDENTITY_MARKERS))] + ["dangling"]:
            self.assertEqual(r[name]["state"], "unknown", name)           # a home, visible, config missing
            self.assertIn("no config.yaml", " | ".join(r[name]["notes"]))
        self.assertFalse(rep["complete"])
        self.assertEqual(rep["unique_homes"], 1 + len(inv.IDENTITY_MARKERS))

    def test_markers_are_checked_for_existence_only(self):
        write(os.path.join(self.P("envonly"), ".env"), "API_KEY=%s\n" % CANARY)
        write(os.path.join(self.P("envonly"), "auth.json"), '{"k": "%s"}' % CANARY)
        opened, real = [], os.open

        def spy(path, *a, **k):
            opened.append(os.path.basename(str(path)))
            return real(path, *a, **k)
        with mock.patch("os.open", spy), mock.patch("builtins.open", side_effect=AssertionError("no buffered opens")):
            rep = self.report()
        self.assertEqual(sorted(set(opened) - {"config.yaml", "plugin.yaml", "HEAD", "main", "packed-refs"}), [])
        self.assertNotIn(CANARY, json.dumps(rep))

    def test_config_only_markerless_invalid_and_deleted(self):
        self.home("config-only", with_plugin=False)
        os.makedirs(os.path.join(self.P("markerless"), "logs"))                 # cron or log side effect
        os.makedirs(os.path.join(self.P("markerless-plugin"), "plugins", "secret-guard"))
        for bad in ("Upper", "has space", "default", "x" * 65, "-lead"):
            write(os.path.join(self.P(bad), "config.yaml"), ENABLED)
        os.makedirs(self.P("Bad-No-Marker"))
        self.home("gone", with_plugin=True)
        write(os.path.join(self.root, "profiles", ".deleted", "gone"), "")
        write(os.path.join(self.root, "profiles", "stray.txt"), "x")
        os.symlink(os.path.join(self.base, "nowhere"), self.P("dangling-link"))
        rep = self.report()
        self.assertEqual(sorted(self.rows(rep)), ["config-only", "default"])
        k = self.kinds(rep)
        self.assertEqual(k["markerless"], "not-a-profile")
        self.assertEqual(k["markerless-plugin"], "ambiguous")                  # plugin files in a non-profile
        for bad in ("Upper", "has space", "default", "x" * 65, "-lead"):
            self.assertEqual(k[bad], "ambiguous", bad)                           # a marker under an invalid id
        self.assertEqual((k["Bad-No-Marker"], k["gone"], k[".deleted"], k["stray.txt"], k["dangling-link"]),
                         ("not-a-profile", "deleted", "not-a-profile", "not-a-profile", "not-a-profile"))
        self.assertEqual(rep["skipped_counts"], {"ambiguous": 6, "deleted": 1, "not-a-profile": 5})
        self.assertIn("NEEDS ATTENTION: 6 ambiguous entries", inv.render(rep)); self.assertEqual(rep["needs_attention"], 6)
        self.assertEqual(rep["counts"]["configured"], 1)                         # the deleted profile is not counted

    def test_tombstones_follow_links_markers_do_not(self):
        """Hermes: a tombstone counts when `Path(tombstone).exists()`, which follows symlinks.
        A dangling tombstone link deletes nothing. Markers are the opposite on purpose."""
        dd = os.path.join(self.root, "profiles", ".deleted")
        for name in ("plain", "linked", "dangling", "looped", "alive"):
            self.home(name, with_plugin=False)
        write(os.path.join(dd, "plain"), "")
        target = os.path.join(self.base, "real-tombstone"); write(target, "")
        os.symlink(target, os.path.join(dd, "linked"))
        os.symlink(os.path.join(self.base, "no-such-target"), os.path.join(dd, "dangling"))
        os.symlink(os.path.join(dd, "looped"), os.path.join(dd, "looped"))
        os.makedirs(self.P("marker-dangling")); os.symlink(os.path.join(self.base, "gone"), os.path.join(self.P("marker-dangling"), ".env"))
        rep = self.report()
        from pathlib import Path
        hermes = {n: Path(dd, n).exists() for n in ("plain", "linked", "dangling", "looped", "alive")}
        self.assertEqual(hermes, {"plain": True, "linked": True, "dangling": False, "looped": False, "alive": False})
        k = self.kinds(rep)
        self.assertEqual((k.get("plain"), k.get("linked")), ("deleted", "deleted"))
        r = self.rows(rep)
        for live in ("dangling", "looped", "alive", "marker-dangling"):
            self.assertIn(live, r, live)                                         # counted as a home
            self.assertNotIn(live, k)
        self.assertEqual(rep["unique_homes"], 5)

    def test_a_tombstone_that_cannot_be_examined_is_not_a_deletion(self):
        self.home("alpha", with_plugin=False)
        tomb = os.path.join(self.root, "profiles", ".deleted", "alpha")
        real = os.stat

        def fake(path, *a, **k):
            if str(path) == tomb:
                raise PermissionError(13, "denied")
            return real(path, *a, **k)
        with mock.patch("os.stat", fake):
            rep = self.report()
        self.assertEqual(self.rows(rep)["alpha"]["state"], "unreadable")
        self.assertFalse(rep["complete"])
        self.assertEqual(self.kinds(rep), {})

    @unittest.skipIf(IS_ROOT, "root ignores file modes")
    def test_a_tombstone_link_to_an_inaccessible_target(self):
        self.home("alpha", with_plugin=False)
        locked = os.path.join(self.base, "locked"); write(os.path.join(locked, "t"), "")
        dd = os.path.join(self.root, "profiles", ".deleted"); os.makedirs(dd)
        os.symlink(os.path.join(locked, "t"), os.path.join(dd, "alpha"))
        os.chmod(locked, 0)
        rep = self.report()
        self.assertEqual(self.rows(rep)["alpha"]["state"], "unreadable")       # neither deleted nor silently live
        self.assertFalse(rep["complete"])

    def test_ambiguous_entries_are_reported_separately_from_completeness(self):
        write(os.path.join(self.P("Upper"), "config.yaml"), ENABLED)
        rep = self.report()
        self.assertEqual((rep["complete"], rep["needs_attention"]), (True, 1))
        code, out, _ = cli("--root", self.root, "--json")
        self.assertEqual((code, json.loads(out)["needs_attention"]), (0, 1))
        text = cli("--root", self.root)[1]
        self.assertIn("NEEDS ATTENTION: 1 ambiguous entry", text)
        self.assertIn("fixed baseline", text); self.assertIn("installed Hermes is not detected", text)

    def test_duplicates_are_counted_once(self):
        self.home("real", NOT_LISTED)
        os.symlink(self.P("real"), self.P("alias"))
        rep = self.report()
        r = self.rows(rep)
        dup = [x for x in (r["real"], r["alias"]) if "duplicate_of" in x]
        self.assertEqual(len(dup), 1); self.assertTrue(r["alias"]["symlink"])
        self.assertEqual(rep["unique_homes"], len(rep["homes"]) - 1)
        self.assertEqual(sum(rep["counts"].values()), rep["unique_homes"])
        twice = self.report(roots=[(self.root, "a"), (self.root, "b")])
        self.assertEqual(twice["unique_homes"], rep["unique_homes"])

    def test_home_outside_the_default_root_and_env(self):
        rep = self.report(roots=[(self.root, "first"), (self.other, "second")])
        self.assertEqual([(h["name"], h["root_no"], h["state"]) for h in rep["homes"]],
                         [("default", 1, "configured"), ("default", 2, "configured")])
        with mock.patch.dict(os.environ, {"HERMES_HOME": self.other}):
            self.assertEqual(inv.default_roots(), [(self.other, "HERMES_HOME")])
        with mock.patch.dict(os.environ, {k: v for k, v in os.environ.items() if k != "HERMES_HOME"}, clear=True):
            self.assertEqual(inv.default_roots()[0][1], "default root")

    def test_enumeration_is_bounded(self):
        for i in range(8):
            self.home("p%d" % i, with_plugin=False)
        with mock.patch.object(inv, "MAX_ENTRIES", 3):
            rep = self.report()
        self.assertFalse(rep["complete"]); self.assertLessEqual(len(rep["homes"]), 4)
        self.assertIn("more than 3 entries", "; ".join(rep["incomplete_reasons"]))
        with mock.patch.object(inv, "MAX_HOMES", 3):
            rep = self.report()
        self.assertFalse(rep["complete"]); self.assertEqual(len(rep["homes"]), 3)


class I3_MalformedNeverPositive(Tree):
    def test_malformed_plugin_lists(self):
        cases = {
            "disabled-scalar": "plugins:\n  enabled: [secret-guard]\n  disabled: secret-guard\n",
            "disabled-mapping": "plugins:\n  enabled: [secret-guard]\n  disabled: {secret-guard: true}\n",
            "disabled-nonstring": "plugins:\n  enabled: [secret-guard]\n  disabled: [1, secret-guard]\n",
            "enabled-scalar": "plugins:\n  enabled: secret-guard\n",
            "enabled-mapping": "plugins:\n  enabled: {secret-guard: true}\n",
            "enabled-nonstring": "plugins:\n  enabled: [secret-guard, {a: 1}]\n",
            "enabled-nested": "plugins:\n  enabled: [[secret-guard]]\n",
            "plugins-list": "plugins: [secret-guard]\n",
            "plugins-scalar": "plugins: secret-guard\n",
            "secrets-scalar": ENABLED.split("secrets:")[0] + "secrets: yes\n",
            "keysource-scalar": ENABLED.split("secrets:")[0] + "secrets:\n  secret_guard: on\n",
            "keysource-string": ENABLED.replace("enabled: true", "enabled: 'true'"),
            "top-list": "- a\n- b\n",
            "top-scalar": "just text\n",
            "broken-yaml": "plugins: [unclosed\n  enabled: {\n",
        }
        for name, cfg in cases.items():
            self.home(name, cfg)
        rep = self.report()
        r = self.rows(rep)
        self.assertEqual({n: r[n]["state"] for n in cases}, {n: "unknown" for n in cases})
        self.assertFalse(rep["complete"])
        self.assertEqual(rep["counts"]["configured"], 1)                          # only the root
        self.assertIn("`plugins.disabled` is not a list", " | ".join(r["disabled-scalar"]["notes"]))

    def test_malformed_manifest_fields(self):
        cases = {
            "ver-list": "name: secret-guard\nversion: [1, 2]\n",
            "ver-mapping": "name: secret-guard\nversion: {a: 1}\n",
            "ver-text": "name: secret-guard\nversion: \"%s and more text\"\n" % CANARY,
            "ver-long": "name: secret-guard\nversion: %s\n" % ("9" * 60),
            "ver-bool": "name: secret-guard\nversion: true\n",
            "hooks-scalar": "name: secret-guard\nversion: 1.2.0\nprovides_hooks: pre_tool_call\n",
            "hooks-nonstring": "name: secret-guard\nversion: 1.2.0\nprovides_hooks: [pre_tool_call, 3]\n",
            "platforms-scalar": "name: secret-guard\nversion: 1.2.0\nplatforms: macos\n",
            "other-name": "name: %s\nversion: 1.2.0\n" % CANARY,
            "broken": ": : :\n\t- [",
            "top-list": "- x\n",
        }
        for name, body in cases.items():
            self.home(name, body=body)
        self.home("no-manifest", with_plugin=False); os.makedirs(os.path.join(self.P("no-manifest"), "plugins", "secret-guard"))
        self.home("plugin-is-file", with_plugin=False); write(os.path.join(self.P("plugin-is-file"), "plugins", "secret-guard"), "x")
        self.home("ver-number", body="name: secret-guard\nversion: 1.2\nplatforms: [macos]\n")
        rep = self.report()
        r = self.rows(rep)
        for name in list(cases) + ["no-manifest", "plugin-is-file"]:
            self.assertEqual(r[name]["state"], "unknown", name)
            self.assertEqual(r[name]["version"], "unknown", name)
        self.assertEqual((r["ver-number"]["state"], r["ver-number"]["version"]), ("configured", "1.2"))
        self.assertNotIn(CANARY, json.dumps(rep) + inv.render(rep, paths=True))    # manifest text is not echoed

    def test_no_yaml_reader_and_a_reader_that_raises(self):
        rep = self.report(loader=None)
        self.assertEqual((rep["counts"]["configured"], rep["counts"]["disabled"], rep["complete"]), (0, 0, False))
        self.assertIn("no YAML reader", "; ".join(rep["incomplete_reasons"]))

        def boom(_text):
            raise RuntimeError(CANARY)
        rep = self.report(loader=boom)
        self.assertEqual(rep["counts"]["configured"], 0)
        self.assertNotIn(CANARY, json.dumps(rep) + inv.render(rep))


class I4_BoundedReads(Tree):
    def fifo_home(self, name, which):
        home = self.home(name, commit="a" * 40)
        write(os.path.join(home, "SOUL.md"), "")                   # still a home once config.yaml is not a file
        target = {"config": os.path.join(home, "config.yaml"),
                  "manifest": os.path.join(home, "plugins", "secret-guard", "plugin.yaml"),
                  "head": os.path.join(home, "plugins", "secret-guard", ".git", "HEAD"),
                  "ref": os.path.join(home, "plugins", "secret-guard", ".git", "refs", "heads", "main")}[which]
        os.remove(target)
        return home, target

    def test_special_files_do_not_block_and_are_never_positive(self):
        for which in ("config", "manifest"):
            _h, t = self.fifo_home("fifo-" + which, which); os.mkfifo(t)
            _h, t = self.fifo_home("dir-" + which, which); os.makedirs(t)
            _h, t = self.fifo_home("linkfifo-" + which, which)
            f = os.path.join(self.base, "fifo-" + which); os.mkfifo(f); os.symlink(f, t)
            _h, t = self.fifo_home("devzero-" + which, which); os.symlink("/dev/zero", t)
            _h, t = self.fifo_home("loop-" + which, which); os.symlink(t, t)
        for which in ("head", "ref"):
            _h, t = self.fifo_home("git-" + which, which); os.mkfifo(t)
        os.remove(os.path.join(self.other, "config.yaml")); os.mkfifo(os.path.join(self.other, "config.yaml"))
        # run it as a real process with a deadline: a blocking read would hang here
        r = subprocess.run([sys.executable, os.path.join(REPO, "inventory.py"), "--root", self.root, "--root", self.other,
                            "--json", "--names"],
                           capture_output=True, text=True, timeout=20)
        data = json.loads(r.stdout)
        rows = {h["name"]: h for h in data["homes"] if not h["default_home"]}
        for name, h in rows.items():
            if name.startswith("git-"):
                want = "configured" if sys.platform == "darwin" else "unsupported"
                self.assertEqual((h["state"], h["commit"]), (want, "unknown"), name)
            else:
                self.assertEqual(h["state"], "unknown", name)
                self.assertIn("not a regular file", " | ".join(h["notes"]), name)
        self.assertEqual(len(rows), 12)
        second = [h for h in data["homes"] if h["default_home"] and h["root_no"] == 2][0]
        self.assertEqual(second["state"], "unknown")               # a FIFO as the root's own config.yaml
        self.assertEqual((r.returncode, data["complete"]), (1, False))

    def test_a_file_that_keeps_growing_is_cut_off(self):
        real = os.read
        with mock.patch.object(inv, "MAX_FILE_BYTES", 5000), mock.patch("os.read", lambda fd, n: b"#" * n):
            row, rep = self.one("default")
        self.assertEqual(row["state"], "unknown")
        self.assertIn("larger than the size this tool parses", " | ".join(row["notes"]))
        self.assertIs(os.read, real)

    def test_oversized_and_invalid_encoding(self):
        self.home("big", "# " + "x" * 4000 + "\n" + ENABLED)
        home = self.home("latin1")
        with open(os.path.join(home, "config.yaml"), "wb") as fh:
            fh.write(ENABLED.encode() + b"note: caf\xe9\n")
        with mock.patch.object(inv, "MAX_FILE_BYTES", 3000):
            r = self.rows()
        self.assertEqual(r["big"]["state"], "unknown")
        self.assertEqual(r["latin1"]["state"], "unknown")
        self.assertIn("not valid UTF-8", " | ".join(r["latin1"]["notes"]))

    def test_unreadable_by_error(self):
        real = os.open
        blocked = {os.path.join(self.root, "config.yaml")}

        def fake(path, *a, **k):
            if str(path) in blocked:
                raise PermissionError(13, "denied", str(path))
            return real(path, *a, **k)
        with mock.patch("os.open", fake):
            row, rep = self.one("default")
        self.assertEqual((row["state"], rep["complete"]), ("unreadable", False))


class Output(Tree):
    def build(self):
        self.home(NAME_CANARY, NOT_LISTED, with_plugin=False)
        write(os.path.join(self.P(SKIP_CANARY), "config.yaml"), ENABLED)
        os.makedirs(self.P("odd\nname\x1b[31m"))
        self.home("meta", body="name: secret-guard\nversion: \"%s\"\n" % CANARY)

    def test_default_output_has_no_names_paths_or_values(self):
        self.build()
        for args in ([], ["--json"]):
            code, out, err = cli("--root", self.root, *args)
            for bad in (CANARY, NAME_CANARY, SKIP_CANARY, self.base, "other-plugin", "api_key", "\x1b", "odd"):
                self.assertNotIn(bad, out + err, (args, bad))
        self.assertIn("home-2", cli("--root", self.root)[1])

    def test_names_only_with_names_paths_only_with_paths(self):
        self.build()
        for args in (["--names"], ["--names", "--json"]):
            _c, out, _e = cli("--root", self.root, *args)
            self.assertIn(NAME_CANARY, out); self.assertIn(SKIP_CANARY, out)
            self.assertNotIn(self.base, out); self.assertNotIn(CANARY, out); self.assertNotIn("\x1b", out)
            self.assertIn("odd\\\\x0aname" if "--json" in args else "odd\\x0aname", out)
        for args in (["--paths"], ["--paths", "--json"]):
            _c, out, _e = cli("--root", self.root, *args)
            self.assertIn(self.root, out); self.assertIn(NAME_CANARY, out); self.assertNotIn(CANARY, out)

    def test_expected_values_are_validated_not_echoed(self):
        code, out, err = cli("--root", self.root, "--expect-version", CANARY + " x")
        self.assertEqual(code, 2); self.assertNotIn(CANARY, out + err)
        code, out, err = cli("--root", self.root, "--expect-commit", "not-a-sha")
        self.assertEqual(code, 2)
        code, out, _ = cli("--root", self.root, "--expect-version", "1.2.0", "--expect-commit", "a" * 40)
        self.assertEqual(code, 0); self.assertNotIn("not the expected", out)


class ReadOnly(Tree):
    def test_nothing_on_disk_changes(self):
        self.home("a"); self.home("b", NOT_LISTED, with_plugin=False); os.makedirs(self.P("markerless"))
        before = snapshot(self.base)
        for args in ([], ["--json"], ["--names"], ["--paths"], ["--paths", "--json"]):
            cli("--root", self.root, "--root", self.other, "--root", os.path.join(self.base, "nope"), *args)
        self.assertEqual(snapshot(self.base), before)

    def test_standalone_does_no_subprocess_socket_or_plugin_import(self):
        def forbidden(*a, **k):
            raise AssertionError("the inventory must not do this")
        loaded = set(sys.modules)
        with mock.patch("subprocess.run", forbidden), mock.patch("subprocess.Popen", forbidden), \
                mock.patch("os.system", forbidden), mock.patch("socket.socket", forbidden), \
                mock.patch("socket.create_connection", forbidden):
            self.report()
        new = {m.split(".")[0] for m in set(sys.modules) - loaded}
        self.assertFalse(new & {"keychain", "registry", "guard", "intake", "agent", "hermes_cli", "doctor"})
        with open(os.path.join(REPO, "inventory.py")) as fh:
            src = fh.read()
        banned = ("import subprocess", "\nfrom .", "import keychain", "security find", "urllib", "requests", "os.remove",
                  "os.makedirs", "os.rename", "shutil", "O_WRONLY", "O_RDWR", "O_CREAT", "os.chmod", "open(")
        self.assertEqual([w for w in banned if w in src.replace("os.open(", "")], [])

    def test_runs_as_a_plain_script(self):
        r = subprocess.run([sys.executable, os.path.join(REPO, "inventory.py"), "--root", self.other, "--json"],
                           capture_output=True, text=True, timeout=30,
                           env={**os.environ, "HERMES_HOME": os.path.join(self.base, "unused")})
        data = json.loads(r.stdout)
        self.assertEqual((len(data["homes"]), r.returncode, r.stderr), (1, 0, ""))

    def test_through_the_plugin_command_with_credential_operations_trapped(self):
        """`hermes secret inventory` goes through cli.py, which imports the keychain modules at
        load. This runs that path, in a stub Hermes, with every way of running a program trapped."""
        base = types.ModuleType("agent.secret_sources.base")
        anything = type("Anything", (type,), {"__getattr__": lambda cls, n: n})
        for n in ("ErrorKind", "FetchResult", "SecretSource"):
            setattr(base, n, anything(n, (), {}))
        base.run_secret_cli = lambda *a, **k: (_ for _ in ()).throw(AssertionError("credential backend called"))
        stubs = {"agent": types.ModuleType("agent"), "agent.secret_sources": types.ModuleType("agent.secret_sources"),
                 "agent.secret_sources.base": base}

        def forbidden(*a, **k):
            raise AssertionError("a program was run")
        with mock.patch.dict(sys.modules, stubs), mock.patch("subprocess.run", forbidden), \
                mock.patch("subprocess.Popen", forbidden), mock.patch("subprocess.check_output", forbidden), \
                mock.patch("os.system", forbidden), mock.patch("socket.create_connection", forbidden), \
                mock.patch.dict(os.environ, {"HERMES_HOME": self.other}):
            spec = importlib.util.spec_from_file_location("sg_inv_cli", os.path.join(REPO, "__init__.py"),
                                                          submodule_search_locations=[REPO])
            pkg = importlib.util.module_from_spec(spec); sys.modules["sg_inv_cli"] = pkg; spec.loader.exec_module(pkg)
            try:
                from sg_inv_cli import cli as plugin_cli
                parser = argparse.ArgumentParser(); plugin_cli.register_cli(parser)
                before = snapshot(self.base)
                buf = io.StringIO()
                with redirect_stdout(buf):
                    code = plugin_cli.secret_command(parser.parse_args(["inventory", "--root", self.root, "--json"]))
                self.assertEqual(snapshot(self.base), before)
            finally:
                for m in [m for m in sys.modules if m.startswith("sg_inv_cli")]:
                    del sys.modules[m]
        data = json.loads(buf.getvalue())
        self.assertEqual((code, data["counts"]["configured" if sys.platform == "darwin" else "unsupported"]), (0, 1))


if __name__ == "__main__":
    unittest.main(verbosity=1)
