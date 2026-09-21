import importlib.util
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

try:
    import pytest
except ImportError:
    pytest = None


def _find_sequence_server():
    """
    Locate sequence_server.py by walking up from this test file's
    directory until it is found, or fall back to searching the
    current working directory tree.
    """
    here = Path(__file__).resolve().parent
    for candidate_dir in [here, *here.parents]:
        candidate = candidate_dir / "sequence_server.py"
        if candidate.is_file():
            return candidate

    for root, _dirs, files in os.walk(Path.cwd()):
        if "sequence_server.py" in files:
            return Path(root) / "sequence_server.py"

    return None


SEQUENCE_SERVER_PATH = _find_sequence_server()


def _noop_decorator(func):
    return func

fixture = pytest.fixture if pytest is not None else _noop_decorator

@fixture
def isolated_missing_db_env(tmp_path, monkeypatch):
    """
    Sets up a clean working directory with no .sequence/state.db
    present, so sequence_server.py must operate against a missing
    database file.
    """
    work_dir = tmp_path / "workdir"
    work_dir.mkdir()

    sequence_dir = work_dir / ".sequence"
    db_path = sequence_dir / "state.db"

    assert not sequence_dir.exists()
    assert not db_path.exists()

    monkeypatch.chdir(work_dir)
    monkeypatch.setenv("SEQUENCE_DB_PATH", str(db_path))

    yield work_dir, db_path

    if sequence_dir.exists():
        shutil.rmtree(sequence_dir, ignore_errors=True)


def _load_app_from_module(module):
    for attr_name in ("app", "application", "create_app"):
        candidate = getattr(module, attr_name, None)
        if candidate is None:
            continue
        if callable(candidate) and attr_name == "create_app":
            try:
                return candidate()
            except Exception:
                continue
        return candidate
    return None


def _try_http_fail_closed(db_path):
    """
    Attempts to import sequence_server.py as a module and exercise
    it via a WSGI/ASGI test client, asserting a 503 response when
    the database file is missing. Returns True if this path was
    exercised and passed, False if it could not be exercised at
    all (caller should fall back to subprocess), and raises an
    AssertionError if it was exercised but failed the contract.
    """
    if SEQUENCE_SERVER_PATH is None:
        return False

    spec = importlib.util.spec_from_file_location(
        "sequence_server_under_test", SEQUENCE_SERVER_PATH
    )
    if spec is None or spec.loader is None:
        return False

    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except SystemExit:
        return False
    except Exception:
        return False

    app = _load_app_from_module(module)
    if app is None:
        return False

    client = None

    try:
        client = app.test_client()
    except AttributeError:
        pass

    if client is not None:
        response = None
        for path in ("/", "/health", "/status", "/sequence"):
            try:
                response = client.get(path)
            except Exception:
                continue
            if response is not None:
                break

        assert response is not None, (
            "Could not obtain any HTTP response from the app's test client"
        )
        assert response.status_code == 503, (
            f"Expected HTTP 503 when {db_path} is missing, "
            f"got {response.status_code}"
        )
        return True

    try:
        from starlette.testclient import TestClient

        client = TestClient(app)
        response = None
        for path in ("/", "/health", "/status", "/sequence"):
            try:
                response = client.get(path)
            except Exception:
                continue
            if response is not None:
                break

        assert response is not None, (
            "Could not obtain any HTTP response from the app's test client"
        )
        assert response.status_code == 503, (
            f"Expected HTTP 503 when {db_path} is missing, "
            f"got {response.status_code}"
        )
        return True
    except ImportError:
        pass

    return False


def _run_as_subprocess_and_check_exit_code(work_dir, db_path):
    assert SEQUENCE_SERVER_PATH is not None, (
        "sequence_server.py could not be located to run as a subprocess"
    )

    env = os.environ.copy()
    env["SEQUENCE_DB_PATH"] = str(db_path)

    result = subprocess.run(
        [sys.executable, str(SEQUENCE_SERVER_PATH)],
        cwd=str(work_dir),
        env=env,
        capture_output=True,
        text=True,
        timeout=15,
    )

    assert result.returncode == 1, (
        f"Expected sequence_server.py to exit with code 1 when "
        f"{db_path} is missing, got exit code {result.returncode}. "
        f"stdout={result.stdout!r} stderr={result.stderr!r}"
    )


def test_fails_closed_when_state_db_missing(isolated_missing_db_env):
    work_dir, db_path = isolated_missing_db_env

    assert not db_path.exists(), (
        "Test setup failure: .sequence/state.db unexpectedly exists"
    )

    try:
        handled_via_http = _try_http_fail_closed(db_path)
    except AssertionError:
        raise
    except Exception:
        handled_via_http = False

    if handled_via_http:
        return

    _run_as_subprocess_and_check_exit_code(work_dir, db_path)


def test_sequence_server_script_exists():
    assert SEQUENCE_SERVER_PATH is not None, (
        "sequence_server.py could not be located in the repository"
    )
    assert SEQUENCE_SERVER_PATH.is_file()
