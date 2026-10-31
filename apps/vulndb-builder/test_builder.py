"""
Tests of the builder with stand-ins for vunnel and grype-db (no network, no real feeds).
Run with `python3 -m unittest -v` in this directory.
"""

from __future__ import annotations

import http.client
import json
import os
import socket
import sqlite3
import stat
import sys
import tempfile
import textwrap
import threading
import time
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import builder  # noqa: E402 - the module under test, after the path is set

FAKE_VUNNEL = textwrap.dedent(
    """\
    #!/usr/bin/env python3
    import json, os, sqlite3, sys
    from pathlib import Path
    switch = Path(__file__).parent / "providers.txt"
    providers = (switch.read_text() if switch.exists() else "alpine,github,nvd,broken").split(",")
    if sys.argv[1] == "list":
        print("\\n".join(providers))
        sys.exit(0)
    name = sys.argv[2]
    root = Path(os.environ["VUNNEL_ROOT"])
    seen = root.parent / "seen-env.jsonl"
    with seen.open("a") as fh:
        fh.write(json.dumps({"provider": name, "github": os.environ.get("GITHUB_TOKEN"),
                             "nvd": os.environ.get("NVD_API_KEY"), "home": os.environ.get("HOME")}) + "\\n")
    if name == "broken":
        print("requests.exceptions.HTTPError: 429 Client Error: Too Many Requests for url: https://feed.example.com/secret?token=abc")
        sys.exit(1)
    work = root / name / "results"
    work.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(work / "results.db") as con:
        con.execute("create table if not exists results (id text)")
        con.execute("delete from results")
        con.executemany("insert into results values (?)", [(f"CVE-{i}",) for i in range(3)])
    (root / name / "metadata.json").write_text("{}")
    """
)

FAKE_GRYPE_DB = textwrap.dedent(
    """\
    #!/usr/bin/env python3
    import json, os, sys
    from pathlib import Path
    config = Path(sys.argv[sys.argv.index("-c") + 1]).read_text()
    build = Path([l.split(": ", 1)[1] for l in config.splitlines() if l.strip().startswith("dir:")][0])
    names = [l.split("name: ", 1)[1] for l in config.splitlines() if "- name:" in l]
    fail = Path(__file__).parent / "fail.txt"
    if fail.exists() and fail.read_text() == sys.argv[1]:
        sys.exit(1)
    build.mkdir(parents=True, exist_ok=True)
    if sys.argv[1] == "build":
        (build / "vulnerability.db").write_text(",".join(names))
    else:
        (build / "vulnerability-db_v6.1.10_2026-10-31T18:42:10Z_1793472135.tar.zst").write_bytes(
            ("archive of " + (build / "vulnerability.db").read_text()).encode())
        (build / "latest.json").write_text(json.dumps({"built": "2026-10-31T18:42:15Z", "schemaVersion": "v6.1.10"}))
    """
)


def executable(path: Path, text: str) -> str:
    path.write_text(text)
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return str(path)


class Base(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())
        self.work = self.tmp / "work"
        self.out = self.tmp / "out"
        builder.WORK_DIR = self.work
        builder.OUTPUT_DIR = self.out
        builder.VUNNEL = executable(self.tmp / "vunnel", FAKE_VUNNEL)
        builder.GRYPE_DB = executable(self.tmp / "grype-db", FAKE_GRYPE_DB)
        os.environ.pop("GARNETOPS_VULNDB_PROVIDERS", None)

    def providers(self, names: str) -> None:
        """The providers the stand-in vunnel lists (the tools see none of the test's environment)."""
        (self.tmp / "providers.txt").write_text(names)

    def seen(self) -> list[dict]:
        path = self.work / "seen-env.jsonl"
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []


class Environment(Base):
    def test_the_tools_see_nothing_of_the_callers_environment(self) -> None:
        os.environ["DATABASE_URL"] = "postgres://secret@db/garnetops"
        os.environ["VUNNEL_PROVIDERS_NVD_REQUEST_TIMEOUT"] = "30"
        try:
            env = builder.tool_env()
        finally:
            del os.environ["DATABASE_URL"], os.environ["VUNNEL_PROVIDERS_NVD_REQUEST_TIMEOUT"]
        self.assertNotIn("DATABASE_URL", env)
        self.assertEqual(env["VUNNEL_PROVIDERS_NVD_REQUEST_TIMEOUT"], "30")
        self.assertEqual(env["VUNNEL_ROOT"], str(self.work / "data"))


class Codes(unittest.TestCase):
    def test_reason_codes_never_carry_output(self) -> None:
        self.assertEqual(builder.reason_of("HTTPError: 429 Too Many Requests", 1), "rate_limited")
        self.assertEqual(builder.reason_of("401 Client Error: Unauthorized", 1), "unauthorized")
        self.assertEqual(builder.reason_of("Max retries exceeded with url", 1), "network")
        self.assertEqual(builder.reason_of("OSError: No space left on device", 1), "disk_full")
        self.assertEqual(builder.reason_of("", None), "timeout")
        self.assertEqual(builder.reason_of("something odd https://feed.example.com", 2), "failed")

    def test_providers_to_run(self) -> None:
        available = ["alpine", "github", "nvd"]
        self.assertEqual(builder.providers_to_run(available, {"githubToken": None}),
                         [("alpine", None), ("github", "no_key"), ("nvd", None)])
        self.assertEqual(builder.providers_to_run(available, {"githubToken": "t"})[1], ("github", None))
        os.environ["GARNETOPS_VULNDB_PROVIDERS"] = "nvd, ../etc,unknown,alpine"
        try:
            self.assertEqual(builder.providers_to_run(available, {}), [("nvd", None), ("alpine", None)])
        finally:
            del os.environ["GARNETOPS_VULNDB_PROVIDERS"]


class Build(Base):
    def test_builds_from_every_provider_with_data_and_reports_each(self) -> None:
        status = builder.build({"githubToken": None, "nvdApiKey": None}, builder.Status(), self.out)
        self.assertEqual(status.state, "succeeded")
        rows = {p.name: p for p in status.providers}
        self.assertEqual((rows["alpine"].result, rows["alpine"].records), ("ok", 3))
        self.assertEqual((rows["github"].result, rows["github"].reason), ("skipped", "no_key"))
        self.assertEqual((rows["broken"].result, rows["broken"].reason), ("failed", "rate_limited"))
        assert status.archive is not None
        archive = self.out / status.archive.file
        self.assertEqual(archive.read_bytes(), b"archive of alpine,nvd")
        self.assertIn(status.archive.sha256, (self.out / f"{status.archive.file}.sha256").read_text())
        self.assertEqual((status.archive.built, status.archive.schemaVersion), ("2026-10-31T18:42:15Z", "v6.1.10"))
        # Nothing a feed printed is kept anywhere.
        self.assertNotIn("feed.example.com", json.dumps(status.to_json()))

    def test_each_key_reaches_only_its_own_provider(self) -> None:
        builder.build({"githubToken": "ghp_" + "a" * 36, "nvdApiKey": "nvd-key"}, builder.Status(), self.out)
        seen = {row["provider"]: row for row in self.seen()}
        self.assertEqual(seen["github"]["github"], "ghp_" + "a" * 36)
        self.assertIsNone(seen["github"]["nvd"])
        self.assertEqual(seen["nvd"]["nvd"], "nvd-key")
        self.assertIsNone(seen["nvd"]["github"])
        self.assertTrue(all(row["github"] is None and row["nvd"] is None
                            for name, row in seen.items() if name not in ("github", "nvd")))
        self.assertFalse(any("nvd-key" in p.read_text(errors="ignore")
                             for p in self.work.rglob("*") if p.is_file() and p.name != "seen-env.jsonl"))

    def test_a_provider_that_fails_later_keeps_its_earlier_data(self) -> None:
        builder.build({}, builder.Status(), self.out)
        self.providers("alpine,nvd,broken")
        (self.work / "data" / "alpine" / "metadata.json").unlink()  # a broken workspace is left out
        status = builder.build({}, builder.Status(), self.out)
        self.assertEqual(status.state, "succeeded")
        assert status.archive is not None
        self.assertEqual((self.out / status.archive.file).read_bytes(), b"archive of alpine,nvd")

    def test_only_the_newest_archive_stays(self) -> None:
        self.out.mkdir(parents=True)
        (self.out / "vulnerability-db_v6.1.9_2026-10-01T00:00:00Z_1.tar.zst").write_text("old")
        (self.out / "vulnerability-db_v6.1.9_2026-10-01T00:00:00Z_1.tar.zst.sha256").write_text("old")
        status = builder.build({}, builder.Status(), self.out)
        assert status.archive is not None
        self.assertEqual(sorted(p.name for p in self.out.iterdir()),
                         [status.archive.file, f"{status.archive.file}.sha256"])

    def test_a_failed_build_says_why_and_keeps_the_previous_archive(self) -> None:
        self.out.mkdir(parents=True)
        previous = self.out / "vulnerability-db_v6.1.9_2026-10-01T00:00:00Z_1.tar.zst"
        previous.write_text("old")
        (self.tmp / "fail.txt").write_text("build")
        status = builder.build({}, builder.Status(), self.out)
        self.assertEqual((status.state, status.reason, status.archive), ("failed", "build_failed", None))
        self.assertTrue(previous.exists())

    def test_no_data_at_all(self) -> None:
        self.providers("broken")
        status = builder.build({}, builder.Status(), self.out)
        self.assertEqual((status.state, status.reason), ("failed", "no_data"))

    def test_an_output_it_may_not_write_to_ends_the_build_with_a_code(self) -> None:
        self.out.mkdir(parents=True)
        self.out.chmod(0o500)
        try:
            if os.access(self.out, os.W_OK):
                self.skipTest("running as root: permissions are not enforced")
            status = builder.build({}, builder.Status(), self.out)
        finally:
            self.out.chmod(0o700)
        self.assertEqual((status.state, status.reason), ("failed", "storage"))

    def test_without_vunnel(self) -> None:
        builder.VUNNEL = str(self.tmp / "missing")
        status = builder.build({}, builder.Status(), self.out)
        self.assertEqual((status.state, status.reason), ("failed", "vunnel_unavailable"))

    def test_export_writes_archive_and_report(self) -> None:
        os.environ["NVD_API_KEY"] = "nvd-key"
        code = builder.export(str(self.out))
        self.assertEqual(code, 0)
        self.assertNotIn("NVD_API_KEY", os.environ)
        report = json.loads((self.out / "report.json").read_text())
        self.assertEqual(report["state"], "succeeded")
        self.assertNotIn("nvd-key", json.dumps(report))


class Socket(Base):
    def setUp(self) -> None:
        super().setUp()
        builder.SOCKET = str(self.tmp / "sock" / "builder.sock")
        self.thread = threading.Thread(target=builder.serve, daemon=True)
        self.thread.start()
        for _ in range(100):
            if Path(builder.SOCKET).exists():
                break
            time.sleep(0.02)

    def call(self, method: str, path: str, body: bytes | None = None) -> tuple[int, dict]:
        class Conn(http.client.HTTPConnection):
            def connect(self) -> None:
                self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                self.sock.connect(builder.SOCKET)

        conn = Conn("localhost")
        conn.request(method, path, body=body, headers={"content-type": "application/json"})
        res = conn.getresponse()
        data = json.loads(res.read() or b"{}")
        conn.close()
        return res.status, data

    def test_build_over_the_socket(self) -> None:
        self.assertEqual(stat.S_IMODE(os.stat(builder.SOCKET).st_mode) & 0o077, 0)
        self.assertEqual(self.call("GET", "/v1/health")[0], 200)
        self.assertEqual(builder.health(), 0)
        code, _ = self.call("POST", "/v1/build", json.dumps({"nvdApiKey": "nvd-key"}).encode())
        self.assertEqual(code, 202)
        for _ in range(200):
            code, status = self.call("GET", "/v1/build")
            if status["state"] != "running":
                break
            time.sleep(0.05)
        self.assertEqual(status["state"], "succeeded")
        self.assertTrue(status["archive"]["sha256"])
        self.assertNotIn("nvd-key", (self.work / "status.json").read_text())

    def test_refuses_what_it_does_not_know(self) -> None:
        self.assertEqual(self.call("GET", "/v1/other")[0], 404)
        self.assertEqual(self.call("POST", "/v1/build", b"[1]")[0], 400)
        self.assertEqual(self.call("POST", "/v1/build", b"x" * (builder.MAX_BODY + 1))[0], 413)

    def test_one_build_at_a_time(self) -> None:
        assert builder.SERVICE is not None
        with builder.SERVICE.lock:
            builder.SERVICE.status.state = "running"
        self.assertEqual(self.call("POST", "/v1/build", b"{}")[0], 409)


class Restart(Base):
    def test_a_build_cut_short_by_a_restart_is_reported_as_interrupted(self) -> None:
        self.work.mkdir(parents=True)
        (self.work / "status.json").write_text(json.dumps({"state": "running", "startedAt": "2026-10-31T00:00:00Z"}))
        self.assertEqual((builder.Service().status.state, builder.Service().status.reason), ("failed", "interrupted"))

    def test_a_damaged_status_file_starts_idle(self) -> None:
        self.work.mkdir(parents=True)
        (self.work / "status.json").write_text("{not json")
        self.assertEqual(builder.Service().status.state, "idle")


if __name__ == "__main__":
    unittest.main()
