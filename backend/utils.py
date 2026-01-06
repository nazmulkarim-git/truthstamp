import hashlib
import subprocess
from typing import Tuple

def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def run_cmd(cmd: list[str], timeout: int = 30) -> Tuple[int, str, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout.strip(), p.stderr.strip()
    except FileNotFoundError:
        return 127, "", f"NOT_FOUND: {cmd[0]}"
    except PermissionError:
        return 126, "", f"PERMISSION_DENIED: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return 124, "", "TIMEOUT"
    except OSError as e:
        return 125, "", f"OSERROR: {type(e).__name__}: {e}"

def which(name: str) -> bool:
    code, out, _ = run_cmd(["/usr/bin/env", "bash", "-lc", f"command -v {name}"], timeout=10)
    return code == 0 and out != ""


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode('utf-8', errors='replace')).hexdigest()
