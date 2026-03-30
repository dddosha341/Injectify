import shutil
import subprocess
from typing import List, Optional
from urllib.parse import urlencode

from .utils import logger


def _get_sqlmap_cmd() -> List[str]:
    """Command sqlmap: from PATH (package/venv). Without fallback constant."""
    exe = shutil.which("sqlmap")
    if exe:
        return [exe]
    raise RuntimeError(
        "sqlmap not found: install package (pip install sqlmap)"
    )


def _url_with_query_params(url: str, params: dict) -> str:
    """Appends ?k=test or &k=test... for sqlmap to test query injection."""
    query = urlencode({k: "test" for k in params})
    return f"{url}&{query}" if "?" in url else f"{url}?{query}"


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
    method: GET / HEAD — if params are present, they are appended to the URL as a query
    string (?k=test); --data is not used. HEAD also gets --method=HEAD.
    method: POST and other methods — if params are present, --data and --method=... are added.
    extra_args — list of CLI arguments (e.g. ["--risk=3", "--tamper=space2comment"]).
    """
    effective_method = (method or "GET").upper()
    scan_url = url
    if params and effective_method in ("GET", "HEAD"):
        scan_url = _url_with_query_params(url, params)

    cmd = _get_sqlmap_cmd() + [f"--url={scan_url}", "--batch", f"--level={level}"]

    if db_type:
        cmd.append(f"--dbms={db_type}")
    else:
        logger.info("No db_type specified. Sqlmap will attempt auto-detection.")

    if params and effective_method not in ("GET", "HEAD"):
        data = "&".join(f"{k}=test" for k in params)
        cmd.append(f"--data={data}")
        cmd.append(f"--method={effective_method}")
    elif effective_method == "HEAD" and params:
        cmd.append("--method=HEAD")

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
