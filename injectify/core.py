import asyncio
import functools
import re
import urllib.error
import urllib.request
from typing import Any, Generator, List, Optional, Tuple

from fastapi import FastAPI, HTTPException, Request

from .scanner import run_sqlmap_scan
from .utils import VALID_DBMS, InjectionDetectedError, logger
from .validators import infer_params, validate_params

_scanned_routes = {}  # Cache: True = ok, False = vulnerable, "scanning" = scanning
_SCANNING = "scanning"
_route_locks: dict[str, asyncio.Lock] = {}
_locks_meta = asyncio.Lock()


def _is_vulnerable_from_sqlmap_output(result: str) -> bool:
    """Determines vulnerability from sqlmap output (vulnerable or injectable)."""
    lower = result.lower()
    return "vulnerable" in lower or "injectable" in lower


def _collect_injectify_routes(
    routes: List[Any], prefix: str = ""
) -> Generator[Tuple[str, set, Any, dict], None, None]:
    """Recursively traverses app.routes and returns (path, methods, endpoint, opts) for routes with __injectify__."""
    for route in routes:
        if hasattr(route, "path") and hasattr(route, "endpoint"):
            full_path = (prefix + route.path).replace("//", "/")
            if getattr(route.endpoint, "__injectify__", False):
                opts = getattr(route.endpoint, "__injectify_opts__", {}) or {}
                methods = getattr(route, "methods", set()) or set()
                if not methods and hasattr(route, "method"):
                    methods = {route.method}
                yield (full_path, methods, route.endpoint, opts)
        if getattr(route, "routes", None):
            mount_path = getattr(route, "path", "") or ""
            yield from _collect_injectify_routes(route.routes, prefix + mount_path)


def _path_for_scan(path: str) -> str:
    """Substitutes placeholder for path-parameters in URL for sqlmap."""
    return re.sub(r"\{[^}]+\}", "1", path)


def _check_app_reachable(url: str, timeout: float = 2.0) -> bool:
    """Checks if the application responds to the URL (for waiting after startup)."""
    try:
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=timeout):
            return True
    except (urllib.error.URLError, OSError) as e:
        logger.debug("App not ready yet: %s", e)
        return False


async def _wait_for_app_ready(host: str, port: int, max_wait: float = 30.0, interval: float = 0.5) -> None:
    """Waits for the application to start responding (after Application startup complete)."""
    base = f"http://{host}:{port}"
    elapsed = 0.0
    while elapsed < max_wait:
        ok = await asyncio.to_thread(_check_app_reachable, base, timeout=2.0)
        if ok:
            logger.info("Application ready, starting injectify route scan.")
            return
        await asyncio.sleep(interval)
        elapsed += interval
    raise RuntimeError(f"Application at {base} did not become ready within {max_wait}s")


def register_injectify_controller(app: FastAPI, port: int, host: str = "localhost") -> None:
    """
    Registers injectify controller: sets port/host in app.state and at application startup
    checks all routes with @injectify. Without calling this function, routes with @injectify are not checked.
    Scan starts after the application has started (waiting for response on GET by base URL).
    """
    app.state.injectify_controller_registered = True
    app.state.injectify_port = port
    app.state.injectify_host = host

    async def _deferred_injectify_scan() -> None:
        await _wait_for_app_ready(host, port)
        routes_list = list(_collect_injectify_routes(app.routes))
        async with _locks_meta:
            for path, methods, endpoint, opts in routes_list:
                for method in methods:
                    route_key = f"{path}:{method}"
                    if route_key not in _route_locks:
                        _route_locks[route_key] = asyncio.Lock()
                    _scanned_routes[route_key] = _SCANNING
        for path, methods, endpoint, opts in routes_list:
            effective_db_type = opts.get("db_type")
            if effective_db_type and effective_db_type.lower() not in VALID_DBMS:
                effective_db_type = None
            params = opts.get("params")
            scan_level = opts.get("scan_level", 3)
            sqlmap_extra = opts.get("sqlmap_extra")
            validate = opts.get("validate", True)
            underlying = getattr(endpoint, "__wrapped__", endpoint)
            base_url = f"http://{host}:{port}"
            path_for_url = _path_for_scan(path)
            for method in methods:
                route_key = f"{path}:{method}"
                effective_params = params
                if effective_params is None:
                    effective_params = infer_params(underlying, method)
                if validate and effective_params is not None:
                    try:
                        validate_params(effective_params)
                    except Exception as e:
                        logger.warning("Startup scan skip %s: %s", route_key, e)
                        continue
                scan_url = f"{base_url}{path_for_url}"
                try:
                    result = await asyncio.to_thread(
                        run_sqlmap_scan,
                        url=scan_url,
                        db_type=effective_db_type,
                        params=effective_params,
                        method=method,
                        level=scan_level,
                        extra_args=sqlmap_extra,
                    )
                except Exception as e:
                    logger.exception("Startup scan failed for %s: %s", route_key, e)
                    if route_key not in _route_locks:
                        _route_locks[route_key] = asyncio.Lock()
                    _scanned_routes[route_key] = True
                    continue
                vulnerable = _is_vulnerable_from_sqlmap_output(result)
                if route_key not in _route_locks:
                    _route_locks[route_key] = asyncio.Lock()
                _scanned_routes[route_key] = False if vulnerable else True
                if vulnerable:
                    logger.warning("Route %s is vulnerable to SQL injection", route_key)

    @app.on_event("startup")
    async def _startup_injectify_scan() -> None:
        asyncio.create_task(_deferred_injectify_scan())


def injectify(
    db_type: Optional[str] = None,
    params: Optional[dict] = None,
    scan_level: int = 3,
    fail_on_vuln: bool = True,
    validate: bool = True,
    sqlmap_extra: Optional[List[str]] = None,
):
    # Preprocessing db_type
    effective_db_type = db_type

    if effective_db_type and effective_db_type.lower() not in VALID_DBMS:
        logger.warning(f"Invalid db_type '{effective_db_type}'. Proceeding with sqlmap auto-detection (no --dbms).")
        effective_db_type = None

    def decorator(func):
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            request: Request = kwargs.get('request')
            if not request:
                raise ValueError("Request not found in kwargs")

            if not getattr(request.app.state, "injectify_controller_registered", False):
                return await func(*args, **kwargs)

            route_path = request.url.path
            method = request.method.upper()
            route_key = f"{route_path}:{method}"

            async with _locks_meta:
                if route_key not in _route_locks:
                    _route_locks[route_key] = asyncio.Lock()
                route_lock = _route_locks[route_key]

            next_step = None  # "run_scan" | "allow" | "block"
            scan_args = None  # (scan_url, effective_db_type, effective_params, method, scan_level, sqlmap_extra)

            async with route_lock:
                if route_key not in _scanned_routes:
                    effective_params = params
                    if effective_params is None:
                        effective_params = infer_params(func, method)
                        if effective_params is None:
                            logger.warning("No params for scan and infer_params returned nothing for %s", route_key)
                    if validate and effective_params is not None:
                        validate_params(effective_params)
                    host = getattr(request.app.state, "injectify_host", "localhost")
                    port = getattr(request.app.state, "injectify_port", None)
                    if port is None:
                        logger.warning("injectify_port not set in app.state; skip scan for %s", route_key)
                        _scanned_routes[route_key] = True
                        next_step = "allow"
                    else:
                        base_url = f"http://{host}:{port}"
                        scan_url = f"{base_url}{route_path}"
                        _scanned_routes[route_key] = _SCANNING
                        next_step = "run_scan"
                        scan_args = (scan_url, effective_db_type, effective_params, method, scan_level, sqlmap_extra)
                elif _scanned_routes[route_key] == _SCANNING:
                    next_step = "allow"
                elif _scanned_routes[route_key] is False:
                    next_step = "block"
                else:
                    next_step = "allow"

            if next_step == "run_scan" and scan_args:
                scan_url, eff_db, eff_params, scan_method, level, extra = scan_args
                result = await asyncio.to_thread(
                    run_sqlmap_scan,
                    url=scan_url,
                    db_type=eff_db,
                    params=eff_params,
                    method=scan_method,
                    level=level,
                    extra_args=extra,
                )
                vulnerable = _is_vulnerable_from_sqlmap_output(result)
                async with route_lock:
                    _scanned_routes[route_key] = False if vulnerable else True
                if vulnerable and fail_on_vuln:
                    raise InjectionDetectedError(f"SQL injection detected in {route_path} [{method}]!")
                if vulnerable:
                    raise HTTPException(status_code=503, detail="Route blocked due to security issues")
                return await func(*args, **kwargs)
            if next_step == "block":
                raise HTTPException(status_code=503, detail="Route blocked due to security issues")
            return await func(*args, **kwargs)

        wrapper.__injectify__ = True
        wrapper.__injectify_opts__ = {
            "db_type": db_type,
            "params": params,
            "scan_level": scan_level,
            "fail_on_vuln": fail_on_vuln,
            "validate": validate,
            "sqlmap_extra": sqlmap_extra,
        }
        return wrapper
    return decorator
