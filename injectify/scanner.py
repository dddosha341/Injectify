import os
import shutil
import subprocess
from typing import List, Optional

from .utils import logger


def _get_sqlmap_cmd() -> List[str]:
    """Command sqlmap: from PATH (package/venv). Without fallback constant."""
    exe = shutil.which("sqlmap")
    if exe:
        return [exe]
    raise RuntimeError(
        "sqlmap not found: install package (pip install sqlmap)"
    )


def run_sqlmap_scan(
    url: str,
    db_type: Optional[str] = None,
    params: Optional[dict] = None,
    method: Optional[str] = "GET",
    level: int = 3,
    extra_args: Optional[List[str]] = None,
) -> str:
    """
    Starts sqlmap with basic options and arbitrary additional arguments.
    method: GET — parameters are already in url (query string), --data is not added.
    method: POST and others — if params are present, --data and --method=... are added.
    extra_args — list of CLI arguments (e.g. ["--risk=3", "--tamper=space2comment"]).
    """
    cmd = _get_sqlmap_cmd() + [f"--url={url}", "--batch", f"--level={level}"]

    if db_type:
        cmd.append(f"--dbms={db_type}")
    else:
        logger.info("No db_type specified. Sqlmap will attempt auto-detection.")

    effective_method = (method or "GET").upper()
    if effective_method != "GET" and params:
        data = "&".join(f"{k}=test" for k in params)
        cmd.append(f"--data={data}")
        cmd.append(f"--method={effective_method}")

    if extra_args:
        cmd.extend(extra_args)

    logger.info("sqlmap command: %s", cmd)

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        check=False,
    )
    output = result.stdout + result.stderr

    logger.info("sqlmap returncode: %s", result.returncode)
    if result.stdout:
        logger.debug("sqlmap stdout:\n%s", result.stdout)
    if result.stderr:
        logger.debug("sqlmap stderr:\n%s", result.stderr)
    logger.debug("sqlmap full output (length=%s):\n%s", len(output), output)

    if result.returncode != 0:
        logger.error(
            "Sqlmap exited with code %s: %s",
            result.returncode,
            output[-2000:] if len(output) > 2000 else output,
        )

    return output
