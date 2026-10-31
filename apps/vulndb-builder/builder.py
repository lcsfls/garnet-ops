"""
The GarnetOps vulnerability database builder (ADR 0044).

It downloads the public vulnerability feeds with vunnel, builds a grype database from them with
grype-db and packages it as an archive that grype imports. Two ways to run it:

- ``python builder.py serve``: the Compose service ``vulndb-builder``. It listens on a Unix socket on
  a volume only it and the worker mount, and builds when the worker asks (once a day). The worker
  hands it the optional GitHub token and NVD API key for that one build; they live in memory and in
  the environment of the one vunnel run that needs them, never on disk and never in a log.
- ``python builder.py export DIR``: one build on a machine with internet access, for installations
  without it. The keys come from ``GITHUB_TOKEN`` and ``NVD_API_KEY``. Writes the archive, its
  SHA-256 and a report to DIR.

Feed content is hostile input (AGENTS.md rule 1): it is parsed only by vunnel and grype-db, in this
container, which has no database, no vault key and no route into the stack. Nothing a feed or a tool
prints is passed on: results are reported as short codes.

Standard library only; the tools are separate programs.
"""

from __future__ import annotations

import hashlib
import http.server
import json
import os
import re
import shutil
import socketserver
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path

VERSION = os.environ.get("APP_VERSION", "dev")
SOCKET = os.environ.get("GARNETOPS_VULNDB_BUILDER_SOCKET", "/run/garnetops-vulndb/builder.sock")
WORK_DIR = Path(os.environ.get("GARNETOPS_VULNDB_WORK_DIR", "/var/lib/garnetops-vulndb"))
OUTPUT_DIR = Path(os.environ.get("GARNETOPS_VULNDB_OUTPUT_DIR", "/builds"))
VUNNEL = os.environ.get("GARNETOPS_VUNNEL_BIN", "vunnel")
GRYPE_DB = os.environ.get("GARNETOPS_GRYPE_DB_BIN", "grype-db")

#: Providers that only run with a key; without it they are skipped, not failed.
NEEDS_KEY = {"github": "githubToken"}
#: The environment variable each key reaches vunnel through, and the one provider that gets it.
KEY_ENV = {"github": ("githubToken", "GITHUB_TOKEN"), "nvd": ("nvdApiKey", "NVD_API_KEY")}
#: How long one provider may take. The first NVD download without a key takes many hours.
PROVIDER_TIMEOUT_S = int(os.environ.get("GARNETOPS_VULNDB_PROVIDER_TIMEOUT_MINUTES", "720")) * 60
BUILD_TIMEOUT_S = 4 * 3600
NAME = re.compile(r"^[a-z0-9][a-z0-9-]{0,39}$")
ARCHIVE = re.compile(r"^vulnerability-db_v\d+\.\d+\.\d+_[0-9TZ:.-]+_\d+\.tar\.zst$")
MAX_BODY = 8 * 1024


@dataclass
class ProviderResult:
    name: str
    lastRunAt: str | None = None
    result: str | None = None  # "ok" | "failed" | "skipped"
    records: int | None = None
    durationMs: int | None = None
    reason: str | None = None


@dataclass
class Archive:
    file: str
    sha256: str
    size: int
    built: str | None
    schemaVersion: str | None


@dataclass
class Status:
    state: str = "idle"  # "idle" | "running" | "succeeded" | "failed"
    startedAt: str | None = None
    finishedAt: str | None = None
    reason: str | None = None
    providers: list[ProviderResult] = field(default_factory=list)
    archive: Archive | None = None

    def to_json(self) -> dict:
        return asdict(self)


def now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def reason_of(output: str, returncode: int | None) -> str:
    """A short code for a failed run. The output itself is never kept: it may quote feed content."""
    if returncode is None:
        return "timeout"
    text = output.lower()
    for code, needles in (
        ("unauthorized", ("401", "unauthorized", "bad credentials")),
        ("forbidden", ("403 client error", "forbidden")),
        ("rate_limited", ("429", "rate limit")),
        ("network", ("connectionerror", "name or service not known", "temporary failure in name resolution",
                     "connection refused", "max retries exceeded", "timed out", "proxyerror")),
        ("disk_full", ("no space left on device",)),
    ):
        if any(n in text for n in needles):
            return code
    return "failed"


def providers_to_run(available: list[str], keys: dict[str, str | None]) -> list[tuple[str, str | None]]:
    """The providers this build runs, with the reason a provider is skipped (None when it runs)."""
    wanted = os.environ.get("GARNETOPS_VULNDB_PROVIDERS", "all").strip()
    if wanted and wanted != "all":
        names = [n.strip() for n in wanted.split(",") if n.strip()]
        chosen = [n for n in names if NAME.match(n) and n in available]
    else:
        chosen = list(available)
    out: list[tuple[str, str | None]] = []
    for name in chosen:
        key = NEEDS_KEY.get(name)
        out.append((name, "no_key" if key and not keys.get(key) else None))
    return out


def count_records(provider_dir: Path) -> int | None:
    db = provider_dir / "results" / "results.db"
    if not db.is_file():
        return None
    try:
        with sqlite3.connect(f"file:{db}?mode=ro", uri=True) as con:
            return int(con.execute("select count(*) from results").fetchone()[0])
    except sqlite3.Error:
        return None


def has_data(provider_dir: Path) -> bool:
    """A provider with a complete workspace from this or an earlier run goes into the database."""
    return (provider_dir / "metadata.json").is_file() and (provider_dir / "results").is_dir()


def tool_env(extra: dict[str, str] | None = None) -> dict[str, str]:
    """
    A small environment for the tools: the proxy settings of the container and the operator's own vunnel
    settings (`VUNNEL_*`), nothing else. The keys are added per provider by the caller.
    """
    env = {k: v for k, v in os.environ.items() if k in ("PATH", "LANG", "LC_ALL", "TZ") or k.upper() in (
        "HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY", "SSL_CERT_FILE", "REQUESTS_CA_BUNDLE") or (
        k.startswith("VUNNEL_") and k != "VUNNEL_ROOT")}
    home = WORK_DIR / "home"
    home.mkdir(parents=True, exist_ok=True)
    env.update({"HOME": str(home), "TMPDIR": str(WORK_DIR / "tmp"), "VUNNEL_ROOT": str(WORK_DIR / "data"),
                "VUNNEL_LOG_LEVEL": "WARNING"})
    (WORK_DIR / "tmp").mkdir(parents=True, exist_ok=True)
    if extra:
        env.update(extra)
    return env


def run(args: list[str], env: dict[str, str], timeout: int, cwd: Path | None = None) -> tuple[int | None, str]:
    """Runs a tool; returns its exit code (None on timeout) and the end of its output, for `reason_of` only."""
    try:
        proc = subprocess.run(args, env=env, cwd=cwd, capture_output=True, text=True, timeout=timeout,
                              errors="replace", check=False)
        return proc.returncode, (proc.stdout[-4000:] + proc.stderr[-4000:])
    except subprocess.TimeoutExpired:
        return None, ""
    except OSError as error:
        return 127, str(error)


def list_providers() -> list[str]:
    code, out = run([VUNNEL, "list"], tool_env(), 120)
    if code != 0:
        raise RuntimeError("vunnel_unavailable")
    return [line.strip() for line in out.splitlines() if NAME.match(line.strip())]


def build(keys: dict[str, str | None], status: Status, output: Path) -> Status:
    """One complete build. Updates `status` in place as it goes; never raises."""
    status.state, status.startedAt, status.finishedAt, status.reason = "running", now(), None, None
    status.providers, status.archive = [], None
    try:
        return run_build(keys, status, output)
    except OSError as error:
        # A full disk or a volume it may not write to; the message may name paths, so only a code is kept.
        print(f"vulndb-builder: storage problem: {type(error).__name__}", file=sys.stderr)
        return finish(status, "failed", "storage")
    except Exception as error:  # noqa: BLE001 - a build must always end with a state
        print(f"vulndb-builder: unexpected error: {type(error).__name__}", file=sys.stderr)
        return finish(status, "failed", "internal")


def run_build(keys: dict[str, str | None], status: Status, output: Path) -> Status:
    data = WORK_DIR / "data"
    data.mkdir(parents=True, exist_ok=True)
    try:
        available = list_providers()
    except RuntimeError as error:
        return finish(status, "failed", str(error))

    for name, skipped in providers_to_run(available, keys):
        entry = ProviderResult(name=name)
        status.providers.append(entry)
        if skipped:
            entry.result, entry.reason = "skipped", skipped
            entry.records = count_records(data / name) if has_data(data / name) else None
            continue
        extra = {}
        if name in KEY_ENV and keys.get(KEY_ENV[name][0]):
            extra[KEY_ENV[name][1]] = keys[KEY_ENV[name][0]]  # only this provider's run sees its key
        started = time.monotonic()
        entry.lastRunAt = now()
        code, out = run([VUNNEL, "run", name], tool_env(extra), PROVIDER_TIMEOUT_S)
        entry.durationMs = int((time.monotonic() - started) * 1000)
        if code == 0:
            entry.result = "ok"
        else:
            entry.result, entry.reason = "failed", reason_of(out, code)
        entry.records = count_records(data / name)

    usable = [p.name for p in status.providers if has_data(data / p.name)]
    if not usable:
        return finish(status, "failed", "no_data")
    archive = package(usable, output)
    if isinstance(archive, str):
        return finish(status, "failed", archive)
    status.archive = archive
    return finish(status, "succeeded", None)


def package(providers: list[str], output: Path) -> Archive | str:
    """Builds and packages the database from the providers' workspaces; returns the archive or a code."""
    work = Path(tempfile.mkdtemp(prefix="build-", dir=WORK_DIR))
    try:
        config = work / "grype-db.yaml"
        lines = ["log:", "  level: warn", "provider:", f"  root: {WORK_DIR / 'data'}", "  vunnel:",
                 "    executor: local", "    generate-configs: false", "  configs:"]
        lines += [f"    - name: {p}" for p in providers]
        lines += ["build:", f"  dir: {work / 'build'}", "  schema-version: 6"]
        config.write_text("\n".join(lines) + "\n")
        for step in (["build"], ["package"]):
            code, out = run([GRYPE_DB, *step, "-c", str(config)], tool_env(), BUILD_TIMEOUT_S, cwd=work)
            if code != 0:
                return "build_failed" if step[0] == "build" else "package_failed"
        archives = [p for p in (work / "build").iterdir() if ARCHIVE.match(p.name)]
        if len(archives) != 1:
            return "package_failed"
        meta = {}
        try:
            meta = json.loads((work / "build" / "latest.json").read_text())
        except (OSError, ValueError):
            pass
        return publish(archives[0], output, meta)
    finally:
        shutil.rmtree(work, ignore_errors=True)


def publish(source: Path, output: Path, meta: dict) -> Archive:
    """Moves the archive into the output directory atomically and removes older ones."""
    output.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256()
    with source.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    archive = Archive(file=source.name, sha256=digest.hexdigest(), size=source.stat().st_size,
                      built=meta.get("built") if isinstance(meta.get("built"), str) else None,
                      schemaVersion=meta.get("schemaVersion") if isinstance(meta.get("schemaVersion"), str) else None)
    partial = output / f".{source.name}.partial"
    shutil.copyfile(source, partial)
    os.replace(partial, output / source.name)
    (output / f"{source.name}.sha256").write_text(f"{archive.sha256}  {source.name}\n")
    for old in output.iterdir():
        if old.name.startswith("vulnerability-db_") and not old.name.startswith(source.name):
            old.unlink(missing_ok=True)
    return archive


def finish(status: Status, state: str, reason: str | None) -> Status:
    status.state, status.reason, status.finishedAt = state, reason, now()
    return status


# ---------------------------------------------------------------------------------------------- service

class Service:
    """The build state of the Compose service; one build at a time."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.status = self.load()

    @staticmethod
    def status_file() -> Path:
        return WORK_DIR / "status.json"

    def load(self) -> Status:
        try:
            raw = json.loads(self.status_file().read_text())
            status = Status(**{k: v for k, v in raw.items() if k in ("state", "startedAt", "finishedAt", "reason")})
            status.providers = [ProviderResult(**p) for p in raw.get("providers", [])]
            status.archive = Archive(**raw["archive"]) if raw.get("archive") else None
            if status.state == "running":  # the container stopped during a build
                finish(status, "failed", "interrupted")
            return status
        except (OSError, ValueError, TypeError, KeyError):
            return Status()

    def save(self) -> None:
        WORK_DIR.mkdir(parents=True, exist_ok=True)
        tmp = self.status_file().with_suffix(".tmp")
        tmp.write_text(json.dumps(self.status.to_json()))
        os.replace(tmp, self.status_file())

    def start(self, keys: dict[str, str | None]) -> bool:
        with self.lock:
            if self.status.state == "running":
                return False
            self.status = Status(state="running", startedAt=now())
            self.save()

        def work() -> None:
            build(keys, self.status, OUTPUT_DIR)
            keys.clear()
            with self.lock:
                self.save()

        threading.Thread(target=work, name="build", daemon=True).start()
        return True


SERVICE: Service | None = None


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "garnetops-vulndb"
    sys_version = ""

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002 - the base class's name
        pass  # requests are not logged; there is nothing in them worth keeping

    def address_string(self) -> str:
        return "socket"

    def answer(self, status: int, body: dict) -> None:
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:  # noqa: N802 - the base class's name
        assert SERVICE is not None
        if self.path == "/v1/health":
            self.answer(200, {"version": VERSION})
        elif self.path == "/v1/build":
            with SERVICE.lock:
                self.answer(200, SERVICE.status.to_json())
        else:
            self.answer(404, {"error": "not_found"})

    def do_POST(self) -> None:  # noqa: N802 - the base class's name
        assert SERVICE is not None
        if self.path != "/v1/build":
            self.answer(404, {"error": "not_found"})
            return
        try:
            length = int(self.headers.get("content-length", "0"))
        except ValueError:
            length = -1
        if length < 0 or length > MAX_BODY:
            self.answer(413, {"error": "too_large"})
            return
        try:
            body = json.loads(self.rfile.read(length) or b"{}")
            if not isinstance(body, dict):
                raise ValueError
            keys = {k: body.get(k) if isinstance(body.get(k), str) and body.get(k) else None
                    for k in ("githubToken", "nvdApiKey")}
        except ValueError:
            self.answer(400, {"error": "bad_request"})
            return
        if SERVICE.start(keys):
            self.answer(202, {"state": "running"})
        else:
            self.answer(409, {"error": "busy"})


class UnixServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True

    def get_request(self):  # type: ignore[no-untyped-def]
        request, _ = super().get_request()
        return request, ("socket", 0)


def serve() -> None:
    global SERVICE
    SERVICE = Service()
    SERVICE.save()
    path = Path(SOCKET)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.unlink(missing_ok=True)
    os.umask(0o077)  # the socket: owner only
    with UnixServer(str(path), Handler) as server:
        print(f"vulndb-builder {VERSION}: listening on {path}", flush=True)
        server.serve_forever()


def health() -> int:
    """Exit code 0 when the service answers on its socket (the Compose health check)."""
    import socket

    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.settimeout(5)
            s.connect(SOCKET)
            s.sendall(b"GET /v1/health HTTP/1.0\r\n\r\n")
            return 0 if s.recv(64).startswith(b"HTTP/1.0 200") else 1
    except OSError:
        return 1


def export(target: str) -> int:
    """One build on a machine with internet access; writes the archive for an offline import."""
    keys = {"githubToken": os.environ.pop("GITHUB_TOKEN", None) or None,
            "nvdApiKey": os.environ.pop("NVD_API_KEY", None) or None}
    out = Path(target)
    out.mkdir(parents=True, exist_ok=True)
    status = build(keys, Status(), out)
    (out / "report.json").write_text(json.dumps(status.to_json(), indent=2) + "\n")
    for p in status.providers:
        print(f"  {p.name:<22} {p.result or '-':<8} {p.records if p.records is not None else '-':>8}  {p.reason or ''}")
    if status.archive is None:
        print(f"vulndb-builder: no database was built ({status.reason})", file=sys.stderr)
        return 1
    print(f"vulndb-builder: wrote {out / status.archive.file} (sha256 {status.archive.sha256})")
    return 0


def main(argv: list[str]) -> int:
    if len(argv) >= 2 and argv[1] == "serve":
        serve()
        return 0
    if len(argv) >= 2 and argv[1] == "health":
        return health()
    if len(argv) == 3 and argv[1] == "export":
        return export(argv[2])
    print("usage: builder.py serve | health | export DIR", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
