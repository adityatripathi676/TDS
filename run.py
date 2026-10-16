from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from importlib import metadata
from pathlib import Path
from socket import socket
from socket import AF_INET
from socket import SOCK_STREAM


ROOT_DIR = Path(__file__).resolve().parent
REQUIREMENTS_FILE = ROOT_DIR / "requirements.txt"
FRONTEND_DIR = ROOT_DIR / "frontend"
FRONTEND_PACKAGE_FILE = FRONTEND_DIR / "package.json"
FRONTEND_DIST_DIR = FRONTEND_DIR / "dist"
ENV_FILE = ROOT_DIR / ".env"


def print_step(message: str) -> None:
    print(f"[run.py] {message}")


def run_command(command: list[str], cwd: Path | None = None) -> int:
    process = subprocess.Popen(command, cwd=cwd or ROOT_DIR)
    try:
        return process.wait()
    except KeyboardInterrupt:
        print()
        print_step("Shutdown requested. Stopping running services cleanly...")
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
        return 0


def check_call(command: list[str], cwd: Path | None = None) -> None:
    subprocess.check_call(command, cwd=cwd or ROOT_DIR)


def load_env_file() -> None:
    if not ENV_FILE.exists():
        return

    loaded_keys: list[str] = []
    for raw_line in ENV_FILE.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value
            loaded_keys.append(key)

    if loaded_keys:
        printable = ", ".join(sorted(loaded_keys))
        print_step(f"Loaded environment variables from .env: {printable}")


def print_ai_mode_status() -> None:
    api_key = os.getenv("GEMINI_API_KEY", "").strip()
    if api_key:
        print_step("AI suspicious-process analysis is enabled via GEMINI_API_KEY.")
    else:
        print_step(
            "Warning: GEMINI_API_KEY is not set. AI suspicious-process analysis is OFF and fallback logic will be used."
        )


def parse_requirements() -> list[tuple[str, str | None]]:
    requirements: list[tuple[str, str | None]] = []
    for raw_line in REQUIREMENTS_FILE.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        # Strip PEP 508 environment markers (e.g. "; sys_platform == 'win32'")
        line = line.split(";", 1)[0].strip()
        if "==" in line:
            package_name, required_version = line.split("==", 1)
            requirements.append((package_name.strip(), required_version.strip()))
        else:
            requirements.append((line, None))
    return requirements


def get_installed_version(package_name: str) -> str | None:
    try:
        return metadata.version(package_name)
    except metadata.PackageNotFoundError:
        return None


def find_missing_or_mismatched_python_packages() -> list[str]:
    issues: list[str] = []
    for package_name, required_version in parse_requirements():
        installed_version = get_installed_version(package_name)
        if installed_version is None:
            issues.append(f"{package_name} is not installed")
            continue
        if required_version and installed_version != required_version:
            issues.append(
                f"{package_name} version mismatch: installed {installed_version}, required {required_version}"
            )
    return issues


def install_python_requirements() -> None:
    print_step("Installing Python requirements...")
    check_call([sys.executable, "-m", "pip", "install", "-r", str(REQUIREMENTS_FILE)])


def npm_command() -> str:
    return "npm.cmd" if sys.platform.startswith("win") else "npm"


def command_exists(name: str) -> bool:
    return shutil.which(name) is not None


def ensure_node_tooling() -> bool:
    npm = npm_command()
    if not command_exists(npm):
        print_step("npm was not found. Frontend steps cannot run until Node.js and npm are installed.")
        return False
    return True


def ensure_frontend_dependencies(force_install: bool = False) -> bool:
    if not FRONTEND_PACKAGE_FILE.exists():
        print_step("frontend/package.json was not found. Skipping frontend dependency setup.")
        return False
    if not ensure_node_tooling():
        return False

    node_modules_dir = FRONTEND_DIR / "node_modules"
    package_lock = FRONTEND_DIR / "package-lock.json"
    should_install = force_install or (not node_modules_dir.exists()) or (not package_lock.exists())

    if should_install:
        print_step("Installing frontend dependencies...")
        check_call([npm_command(), "install"], cwd=FRONTEND_DIR)
    else:
        print_step("Frontend dependencies are already installed.")
    return True


def frontend_build_needed() -> bool:
    if not FRONTEND_PACKAGE_FILE.exists():
        return False

    index_file = FRONTEND_DIST_DIR / "index.html"
    if not index_file.exists():
        return True

    dist_mtime = index_file.stat().st_mtime
    for source_file in FRONTEND_DIR.rglob("*"):
        if "node_modules" in source_file.parts or "dist" in source_file.parts:
            continue
        if source_file.is_file() and source_file.stat().st_mtime > dist_mtime:
            return True
    return False


def build_frontend() -> None:
    print_step("Building React frontend...")
    check_call([npm_command(), "run", "build"], cwd=FRONTEND_DIR)


def port_in_use(host: str, port: int) -> bool:
    with socket(AF_INET, SOCK_STREAM) as sock:
        sock.settimeout(1)
        return sock.connect_ex((host, port)) == 0


def _find_port_owner(port: int) -> tuple[int, str, str] | None:
    """
    Return (pid, process_name, cmdline_snippet) of the process listening on
    *port*, or None if it cannot be determined.
    Requires psutil (already in requirements.txt).
    """
    try:
        import psutil
        for conn in psutil.net_connections(kind="inet"):
            if conn.laddr and conn.laddr.port == port and conn.status in ("LISTEN", ""):
                pid = conn.pid
                if pid is None:
                    return None
                try:
                    proc = psutil.Process(pid)
                    name = proc.name()
                    try:
                        cmd = " ".join(proc.cmdline())[:80]
                    except (psutil.AccessDenied, psutil.ZombieProcess):
                        cmd = "<access denied>"
                    return pid, name, cmd
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    return None
    except Exception:
        pass
    return None


def _kill_port_owner(pid: int) -> bool:
    """Terminate the process with *pid*. Returns True on success."""
    try:
        import psutil, signal as _signal
        proc = psutil.Process(pid)
        print_step(f"Sending SIGTERM to PID {pid}...")
        proc.terminate()
        try:
            proc.wait(timeout=5)
            return True
        except psutil.TimeoutExpired:
            print_step(f"Process {pid} did not exit in 5 s — sending SIGKILL...")
            proc.kill()
            proc.wait(timeout=5)
            return True
    except Exception as exc:
        print_step(f"Could not kill PID {pid}: {exc}")
        return False


def _find_free_port() -> int:
    """Ask the OS for any available TCP port and return it."""
    import socket as _sock
    with _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        s.setsockopt(_sock.SOL_SOCKET, _sock.SO_REUSEADDR, 1)
        return s.getsockname()[1]


def _prompt_override(port: int) -> str:
    """
    Find what is using *port*, warn the user, and ask whether to override it.

    Returns:
        'freed'    -- user said Y and the port was successfully freed.
        'declined' -- user said N; caller should find an alternate port.
        'failed'   -- user said Y but the process could not be killed.
    """
    owner = _find_port_owner(port)

    print()
    print_step(f"WARNING: Port {port} is already in use!")

    if owner:
        pid, name, cmd = owner
        print_step(f"   Occupied by : {name}  (PID {pid})")
        print_step(f"   Command     : {cmd}")
    else:
        print_step("   Could not identify the owning process (may need elevated privileges).")

    print()
    try:
        answer = input(f"[run.py] Override and take port {port}? [y/N]: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        answer = "n"

    if answer not in ("y", "yes"):
        return "declined"

    if owner:
        pid, name, _ = owner
        print_step(f"Stopping '{name}' (PID {pid})...")
        if not _kill_port_owner(pid):
            return "failed"
        import time
        time.sleep(1)
        if port_in_use("127.0.0.1", port):
            print_step(f"Port {port} is still busy after killing the process. Cannot continue.")
            return "failed"
        print_step(f"Port {port} is now free.")
    else:
        print_step("Could not identify process -- cannot free the port automatically.")
        return "failed"

    return "freed"


def start_backend(host: str, port: int, reload_enabled: bool) -> int:
    if port_in_use(host, port):
        result = _prompt_override(port)
        if result == "declined":
            port = _find_free_port()
            print_step(f"Auto-selected available port {port}.")
        elif result == "failed":
            return 1
        # result == "freed": continue with the original port

    command = [
        sys.executable,
        "-m",
        "uvicorn",
        "app.main:app",
        "--host",
        host,
        "--port",
        str(port),
    ]
    if reload_enabled:
        command.append("--reload")
    print_step(f"Starting FastAPI backend on http://{host}:{port}")
    return run_command(command)


def start_frontend_dev() -> int:
    print_step("Starting React development server on http://127.0.0.1:5173")
    return run_command([npm_command(), "run", "dev"], cwd=FRONTEND_DIR)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Launch the AI-driven HIDS stack with dependency checks for Python and React."
    )
    parser.add_argument("--host", default="127.0.0.1", help="Host interface for the backend server.")
    parser.add_argument("--port", type=int, default=8000, help="Port for the backend server.")
    parser.add_argument("--no-reload", action="store_true", help="Disable backend auto-reload mode.")
    parser.add_argument(
        "--frontend-mode",
        choices=("build", "dev", "skip"),
        default="build",
        help="Choose whether to build the frontend for FastAPI, start Vite dev server, or skip frontend steps.",
    )
    parser.add_argument(
        "--force-install",
        action="store_true",
        help="Force reinstall frontend dependencies before running.",
    )
    parser.add_argument(
        "--backend-only",
        action="store_true",
        help="Run only the backend and skip all frontend dependency/build steps.",
    )
    return parser


def main() -> int:
    if not REQUIREMENTS_FILE.exists():
        print_step("requirements.txt was not found. Cannot continue.")
        return 1

    load_env_file()
    print_ai_mode_status()
    args = build_parser().parse_args()

    print_step("Checking Python dependencies...")
    python_issues = find_missing_or_mismatched_python_packages()
    if python_issues:
        print_step("Python dependency issues found:")
        for issue in python_issues:
            print(f"  - {issue}")
        install_python_requirements()
    else:
        print_step("Python dependencies are ready.")

    if args.backend_only or args.frontend_mode == "skip":
        print_step("Skipping frontend setup.")
        return start_backend(host=args.host, port=args.port, reload_enabled=not args.no_reload)

    frontend_available = ensure_frontend_dependencies(force_install=args.force_install)
    if not frontend_available and args.frontend_mode != "skip":
        return 1

    if args.frontend_mode == "dev":
        print_step("Frontend dev mode selected. Start the backend in another terminal with `python run.py --backend-only`.")
        return start_frontend_dev()

    if frontend_build_needed():
        build_frontend()
    else:
        print_step("Frontend build is already up to date.")

    return start_backend(host=args.host, port=args.port, reload_enabled=not args.no_reload)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print()
        print_step("Launch cancelled by user.")
        raise SystemExit(0)
