"""Static inventory tests. Synthetic homes only: no Hermes, no keychain, no network.

    python tests/test_inventory.py
"""
import builtins
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import inventory as inv  # noqa: E402

CANARY = "synthetic--inventory-canary-7f3a"
ENABLED = "plugins:\n  enabled:\n    - other-plugin\n    - secret-guard\nsecrets:\n  secret_guard:\n    enabled: true\n"
NOT_LISTED = "plugins:\n  enabled:\n    - other-plugin\nmodel:\n  api_key: %s\n" % CANARY
PLUGIN_YAML = ("name: secret-guard\nversion: %s\nplatforms:\n  - macos\nprovides_hooks:\n"
               + "".join("  - %s\n" % h for h in inv.EXPECTED_HOOKS))


def write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as fh:
        fh.write(text)


def plugin(home, version="1.1.0", commit=None, body=None):
    d = os.path.join(home, "plugins", "secret-guard")
    write(os.path.join(d, "plugin.yaml"), body if body is not None else PLUGIN_YAML % version)
    if commit:
        write(os.path.join(d, ".git", "HEAD"), "ref: refs/heads/main\n")
        write(os.path.join(d, ".git", "refs", "heads", "main"), commit + "\n")


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


class Tree(unittest.TestCase):
    def setUp(self):
        self.base = os.path.realpath(tempfile.mkdtemp(prefix="sg-inv-"))
        r = self.root = os.path.join(self.base, "hermes")
        P = lambda n: os.path.join(r, "profiles", n)          # noqa: E731
        self.P = P
        # root: enabled, plugin present, commit known
        write(os.path.join(r, "config.yaml"), ENABLED); plugin(r, commit="a" * 40)
        # absent: no plugin files, not listed. Its config holds a canary that must never be printed
        write(os.path.join(P("absent"), "config.yaml"), NOT_LISTED)
        # disabled: files present, not listed
        write(os.path.join(P("disabled"), "config.yaml"), NOT_LISTED); plugin(P("disabled"), commit="a" * 40)
        # explicitly disabled wins over enabled
        write(os.path.join(P("disabled-explicit"), "config.yaml"), ENABLED.replace("secrets:", "  disabled:\n    - secret-guard\nsecrets:"))
        plugin(P("disabled-explicit"), commit="a" * 40)
        # listed but files missing
        write(os.path.join(P("listed-no-files"), "config.yaml"), ENABLED)
        # no inheritance: the root is enabled, this profile has no plugins section at all
        write(os.path.join(P("inherits-nothing"), "config.yaml"), "model:\n  name: x\n"); plugin(P("inherits-nothing"), commit="a" * 40)
        # override: enabled here, key source switched off
        write(os.path.join(P("keysource-off"), "config.yaml"), ENABLED.replace("enabled: true", "enabled: false")); plugin(P("keysource-off"), commit="a" * 40)
        # stale copy: older version and another commit
        write(os.path.join(P("stale"), "config.yaml"), ENABLED); plugin(P("stale"), version="1.0.0", commit="b" * 40)
        # malformed config, malformed plugin.yaml, plugin folder without plugin.yaml, config that is a list
        write(os.path.join(P("bad-config"), "config.yaml"), "plugins: [unclosed\n  enabled: {\n"); plugin(P("bad-config"))
        write(os.path.join(P("bad-plugin-yaml"), "config.yaml"), ENABLED); plugin(P("bad-plugin-yaml"), body=": : :\n\t- [")
        write(os.path.join(P("no-plugin-yaml"), "config.yaml"), ENABLED); os.makedirs(os.path.join(P("no-plugin-yaml"), "plugins", "secret-guard"))
        write(os.path.join(P("list-config"), "config.yaml"), "- a\n- b\n"); plugin(P("list-config"))
        write(os.path.join(P("enabled-not-a-list"), "config.yaml"), "plugins:\n  enabled: secret-guard\n"); plugin(P("enabled-not-a-list"))
        # hook declarations incomplete
        write(os.path.join(P("few-hooks"), "config.yaml"), ENABLED)
        plugin(P("few-hooks"), body="name: secret-guard\nversion: 1.1.0\nplatforms: [macos]\nprovides_hooks:\n  - pre_tool_call\n")
        # duplicate: a symlink to another home, and a symlinked plugin folder
        os.symlink(P("disabled"), P("link-to-disabled"))
        write(os.path.join(P("linked-plugin"), "config.yaml"), ENABLED); os.makedirs(os.path.join(P("linked-plugin"), "plugins"))
        os.symlink(os.path.join(r, "plugins", "secret-guard"), os.path.join(P("linked-plugin"), "plugins", "secret-guard"))
        # things that are not homes
        os.makedirs(P("empty-dir")); write(os.path.join(r, "profiles", "stray-file.txt"), "x\n")
        # a name with control characters
        write(os.path.join(P("odd\nname\x1b[31m"), "config.yaml"), NOT_LISTED)
        # a home outside the default root
        self.other = os.path.join(self.base, "elsewhere")
        write(os.path.join(self.other, "config.yaml"), ENABLED); plugin(self.other, commit="a" * 40)

    def tearDown(self):
        for base, dirs, _files in os.walk(self.base):
            for d in dirs:
                try:
                    os.chmod(os.path.join(base, d), 0o700)
                except OSError:
                    pass
        shutil.rmtree(self.base, ignore_errors=True)

    def report(self, system="Darwin", roots=None, **kw):
        return inv.run(roots or [(self.root, "test")], system=system, **kw)

    def state(self, rep):
        return {r["id"]: r for r in rep["homes"]}


class States(Tree):
    def test_each_state_is_told_apart(self):
        rep = self.report()
        s = self.state(rep)
        want = {"default": "configured", "profiles/absent": "absent", "profiles/disabled": "disabled",
                "profiles/disabled-explicit": "disabled", "profiles/listed-no-files": "absent",
                "profiles/inherits-nothing": "disabled", "profiles/keysource-off": "configured",
                "profiles/stale": "configured", "profiles/bad-config": "unknown", "profiles/bad-plugin-yaml": "unknown",
                "profiles/no-plugin-yaml": "unknown", "profiles/list-config": "unknown",
                "profiles/enabled-not-a-list": "unknown", "profiles/few-hooks": "configured",
                "profiles/link-to-disabled": "disabled", "profiles/linked-plugin": "configured"}
        got = {k: s[k]["state"] for k in want}
        self.assertEqual(got, want)
        self.assertFalse(rep["complete"])                      # unknown homes make it incomplete
        self.assertNotIn("protected", inv.render(rep).lower())

    def test_runtime_is_never_claimed(self):
        rep = self.report()
        self.assertTrue(all(r["runtime"] == "not tested" for r in rep["homes"]))
        self.assertIn("runtime behaviour was not tested", inv.render(rep))

    def test_notes_carry_the_detail(self):
        s = self.state(self.report())
        j = lambda k: " | ".join(s[k]["notes"])               # noqa: E731
        self.assertIn("plugin files are missing", j("profiles/listed-no-files"))
        self.assertIn("plugins.disabled", j("profiles/disabled-explicit"))
        self.assertIn("key source is off", j("profiles/keysource-off"))
        self.assertIn("does not declare", j("profiles/few-hooks"))
        self.assertEqual(s["profiles/few-hooks"]["hooks_declared"], "1 of 6")
        self.assertEqual(s["default"]["hooks_declared"], "6 of 6")
        self.assertIn("symlink", j("profiles/linked-plugin"))
        self.assertEqual(s["profiles/inherits-nothing"]["listed_enabled"], "no")   # nothing inherited from the root

    def test_duplicates_are_counted_once(self):
        rep = self.report()
        s = self.state(rep)
        self.assertEqual(s["profiles/link-to-disabled"].get("duplicate_of"), "profiles/disabled")
        self.assertTrue(s["profiles/link-to-disabled"]["symlink"])
        self.assertEqual(rep["unique_homes"], len(rep["homes"]) - 1)
        self.assertEqual(sum(rep["counts"].values()), rep["unique_homes"])
        # the same root given twice is not counted twice either
        twice = self.report(roots=[(self.root, "a"), (self.root, "b")])
        self.assertEqual(twice["unique_homes"], rep["unique_homes"])
        buf = io.StringIO()
        with redirect_stdout(buf):
            inv.main(["--root", self.root, "--root", self.root]); inv.main(["--root", self.root, "--root", self.root, "--json"])
        self.assertNotIn(self.base, buf.getvalue())            # the duplicate note names a root by number, not by path
        self.assertIn("under root 1", buf.getvalue())

    def test_versions_and_commits(self):
        rep = self.report(expect_version="1.1.0", expect_commit="a" * 12)
        s = self.state(rep)
        self.assertEqual((s["default"]["version"], s["default"]["commit"]), ("1.1.0", "a" * 40))
        self.assertEqual((s["profiles/stale"]["version"], s["profiles/stale"]["commit"]), ("1.0.0", "b" * 40))
        stale = " | ".join(s["profiles/stale"]["notes"])
        self.assertIn("not the expected 1.1.0", stale); self.assertIn("commit bbbbbbbbbbbb is not the expected", stale)
        self.assertIn("differ between homes", stale)
        self.assertNotIn("not the expected", " | ".join(s["default"]["notes"]))
        self.assertEqual(s["profiles/few-hooks"]["commit"], "unknown")             # no .git: not guessed
        self.assertIn("commit unknown", " | ".join(s["profiles/few-hooks"]["notes"]))

    def test_packed_refs_and_detached_head(self):
        d = os.path.join(self.other, "plugins", "secret-guard", ".git")
        os.remove(os.path.join(d, "refs", "heads", "main"))
        write(os.path.join(d, "packed-refs"), "# pack-refs\n" + "c" * 40 + " refs/heads/main\n")
        self.assertEqual(self.state(self.report(roots=[(self.other, "t")]))["default"]["commit"], "c" * 40)
        write(os.path.join(d, "HEAD"), "d" * 40 + "\n")
        self.assertEqual(self.state(self.report(roots=[(self.other, "t")]))["default"]["commit"], "d" * 40)
        write(os.path.join(d, "HEAD"), "ref: ../../../../etc/x\n")
        self.assertEqual(self.state(self.report(roots=[(self.other, "t")]))["default"]["commit"], "unknown")


class Discovery(Tree):
    def test_searched_and_skipped_are_listed(self):
        rep = self.report(roots=[(self.root, "first"), (self.other, "second"), (os.path.join(self.base, "nope"), "third")])
        self.assertEqual([s["source"] for s in rep["searched"]], ["first", "second", "third"])
        reasons = {os.path.basename(s["path"]): s["reason"] for s in rep["skipped"]}
        self.assertIn("not a Hermes home", reasons["empty-dir"])
        self.assertEqual(reasons["stray-file.txt"], "not a directory")
        self.assertIn("does not exist", reasons["nope"])
        ids = [(r["id"], r["source"]) for r in rep["homes"]]
        self.assertIn(("default", "second"), ids)                                   # the home outside the default root
        self.assertEqual(self.state(self.report(roots=[(self.other, "x")]))["default"]["state"], "configured")

    def test_default_root_follows_hermes_home(self):
        with mock.patch.dict(os.environ, {"HERMES_HOME": self.other}):
            self.assertEqual(inv.default_roots(), [(self.other, "HERMES_HOME")])
        env = {k: v for k, v in os.environ.items() if k != "HERMES_HOME"}
        with mock.patch.dict(os.environ, env, clear=True):
            self.assertEqual(inv.default_roots()[0][1], "default root")

    def test_control_characters_in_names_are_escaped(self):
        rep = self.report()
        text = inv.render(rep, show_paths=True) + json.dumps(rep)
        self.assertNotIn("\x1b", text)
        self.assertTrue(any("odd\\x0aname\\x1b[31m" in r["id"] for r in rep["homes"]))
        for line in inv.render(rep).splitlines():
            self.assertFalse(line.startswith("name"))                                # the newline did not split a row


class NeverGreen(Tree):
    """Unreadable, unsupported and unparsed states must not turn into a positive result."""

    def test_unsupported_platform(self):
        for system in ("Linux", "Windows", ""):
            rep = self.report(system=system)
            s = self.state(rep)
            self.assertEqual(s["default"]["state"], "unsupported", system)
            self.assertEqual(rep["counts"]["configured"], 0, system)
            self.assertEqual(s["profiles/absent"]["state"], "absent", system)

    def test_no_yaml_reader(self):
        rep = self.report(loader=None)
        self.assertEqual(rep["counts"]["configured"], 0)
        self.assertEqual(rep["counts"]["disabled"], 0)
        self.assertFalse(rep["complete"])
        self.assertIn("no YAML reader", "; ".join(rep["incomplete_reasons"]))
        self.assertEqual(self.state(rep)["default"]["state"], "unknown")

    def test_reader_that_raises(self):
        def boom(_text):
            raise RuntimeError(CANARY)
        rep = self.report(loader=boom)
        self.assertEqual(rep["counts"]["configured"], 0)
        self.assertNotIn(CANARY, json.dumps(rep) + inv.render(rep))                  # the exception text is not echoed

    def test_unreadable_files_by_permission_error(self):
        real_open = builtins.open
        blocked = {os.path.join(self.root, "config.yaml"), os.path.join(self.P("stale"), "plugins", "secret-guard", "plugin.yaml")}

        def fake_open(path, *a, **k):
            if str(path) in blocked:
                raise PermissionError(13, "denied", str(path))
            return real_open(path, *a, **k)
        with mock.patch("builtins.open", fake_open):
            rep = self.report()
        s = self.state(rep)
        self.assertEqual(s["default"]["state"], "unreadable")
        self.assertEqual(s["profiles/stale"]["state"], "unreadable")
        self.assertFalse(rep["complete"])

    def test_unlistable_profiles_folder(self):
        real = os.listdir

        def fake(path="."):
            if str(path) == os.path.join(self.root, "profiles"):
                raise PermissionError(13, "denied")
            return real(path)
        with mock.patch("os.listdir", fake):
            rep = self.report()
        self.assertEqual(self.state(rep)["profiles/*"]["state"], "unreadable")
        self.assertFalse(rep["complete"])

    @unittest.skipIf(hasattr(os, "geteuid") and os.geteuid() == 0, "root ignores file modes")
    def test_unreadable_by_real_file_modes(self):
        os.chmod(os.path.join(self.P("stale"), "config.yaml"), 0)
        os.chmod(self.P("disabled"), 0)
        os.chmod(os.path.join(self.P("keysource-off"), "plugins"), 0)
        s = self.state(self.report())
        self.assertEqual(s["profiles/stale"]["state"], "unreadable")
        self.assertEqual(s["profiles/disabled"]["state"], "unreadable")
        self.assertEqual(s["profiles/keysource-off"]["state"], "unreadable")

    def test_oversized_config_is_unknown(self):
        with mock.patch.object(inv, "MAX_FILE_BYTES", 10):
            rep = self.report()
        self.assertEqual(rep["counts"]["configured"], 0)
        self.assertEqual(self.state(rep)["default"]["state"], "unknown")

    def test_too_many_homes_is_incomplete(self):
        with mock.patch.object(inv, "MAX_HOMES", 3):
            rep = self.report()
        self.assertEqual(len(rep["homes"]), 3)
        self.assertFalse(rep["complete"])


class ReadOnly(Tree):
    def test_nothing_on_disk_changes(self):
        before = snapshot(self.base)
        rep = self.report(roots=[(self.root, "a"), (self.other, "b")], expect_version="1.1.0")
        inv.render(rep); inv.render(rep, show_paths=True)
        with redirect_stdout(io.StringIO()):
            inv.main(["--root", self.root, "--json"]); inv.main(["--root", self.root, "--paths"])
        self.assertEqual(snapshot(self.base), before)

    def test_no_subprocess_no_network_no_credential_code(self):
        def forbidden(*a, **k):
            raise AssertionError("the inventory must not do this")
        loaded_before = set(sys.modules)
        with mock.patch("subprocess.run", forbidden), mock.patch("subprocess.Popen", forbidden), \
                mock.patch("os.system", forbidden), mock.patch("socket.socket", forbidden), \
                mock.patch("socket.create_connection", forbidden):
            self.report()
        new = set(sys.modules) - loaded_before
        self.assertFalse([m for m in new if m.split(".")[0] in ("keychain", "registry", "guard", "intake", "agent", "hermes_cli")])
        with open(os.path.join(os.path.dirname(HERE), "inventory.py")) as fh:
            src = fh.read()
        banned = ("import subprocess", "\nfrom .", "import keychain", "security find", "urllib", "requests",
                  "os.remove", "os.makedirs", "os.rename", "shutil", ', "w"', ', "a"', "os.chmod")
        self.assertEqual([w for w in banned if w in src], [])

    def test_only_status_fields_are_printed(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            inv.main(["--root", self.root]); inv.main(["--root", self.root, "--json"])
            inv.main(["--root", self.root, "--paths"]); inv.main(["--root", self.root, "--json", "--paths"])
        out = buf.getvalue()
        self.assertNotIn(CANARY, out)                         # a value sitting in config.yaml
        self.assertNotIn("other-plugin", out)                 # unrelated configuration
        self.assertNotIn("api_key", out)

    def test_paths_are_hidden_unless_asked(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            inv.main(["--root", self.root]); inv.main(["--root", self.root, "--json"])
        self.assertNotIn(self.base, buf.getvalue())
        buf = io.StringIO()
        with redirect_stdout(buf):
            inv.main(["--root", self.root, "--paths"])
        self.assertIn(self.root, buf.getvalue())

    def test_runs_as_a_plain_script(self):
        script = os.path.join(os.path.dirname(HERE), "inventory.py")
        r = subprocess.run([sys.executable, script, "--root", self.other, "--json"], capture_output=True, text=True,
                           timeout=30, env={**os.environ, "HERMES_HOME": os.path.join(self.base, "unused")})
        data = json.loads(r.stdout)
        self.assertEqual(len(data["homes"]), 1)
        self.assertEqual(r.returncode, 0 if data["complete"] else 1)
        self.assertEqual(r.stderr, "")


if __name__ == "__main__":
    unittest.main(verbosity=1)
