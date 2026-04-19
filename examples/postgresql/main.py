"""
One-file FastAPI API with direct SELECT to DB and injectify decorator.
Demo: vulnerable endpoints for GET, POST, PUT, DELETE, OPTIONS, HEAD
(intentionally vulnerable for checking sqlmap/injectify).
Plus GET /sqli/* scenarios: reflected/UNION, error-based, boolean/time blind, ORDER BY, LIKE, HAVING.
"""
import asyncio
import contextlib
import os

import psycopg2
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response

from injectify.core import injectify, register_injectify_controller

app = FastAPI(title="Injectify Demo API", version="0.1.0")

PORT = int(os.environ.get("PORT", "8000"))
register_injectify_controller(app, port=PORT)

DATABASE_URL = os.environ.get(
    "DATABASE_URL", "postgresql://user:password@localhost:5432/demo"
)

INJECTIFY_COMMON = dict(
    db_type="PostgreSQL",
    scan_level=3,
    fail_on_vuln=True,
    sqlmap_extra=None,
)


def get_connection():
    return psycopg2.connect(DATABASE_URL)


def _fetch_users_by_id(raw_id: str):
    """Vulnerable SELECT: raw_id is inserted into SQL without sanitization."""
    with contextlib.closing(get_connection()) as conn:
        with conn.cursor() as cur:
            cur.execute(f"SELECT id, name FROM users WHERE id = {raw_id}")
            return cur.fetchall()


def _sqli_error_cast(expr: str):
    """Error-based: CAST of attacker-controlled expression fails and leaks data."""
    with contextlib.closing(get_connection()) as conn:
        with conn.cursor() as cur:
            try:
                cur.execute(f"SELECT CAST(({expr}) AS INTEGER)")
                row = cur.fetchone()
                return False, row[0] if row else None
            except Exception as e:
                return True, str(e)


def _sqli_boolean_exists(raw_id: str):
    with contextlib.closing(get_connection()) as conn:
        with conn.cursor() as cur:
            cur.execute(f"SELECT EXISTS(SELECT 1 FROM users WHERE id = {raw_id})")
            return cur.fetchone()[0]


def _sqli_time_cond(cond: str):
    """Time/boolean blind sink: fixed row + injectable boolean clause."""
    with contextlib.closing(get_connection()) as conn:
        with conn.cursor() as cur:
            cur.execute(f"SELECT id, name FROM users WHERE id = 1 AND ({cond})")
            return cur.fetchall()


def _sqli_orderby(column: str):
    with contextlib.closing(get_connection()) as conn:
        with conn.cursor() as cur:
            cur.execute(f"SELECT id, name FROM users ORDER BY {column}")
            return cur.fetchall()


def _sqli_like(q: str):
    with contextlib.closing(get_connection()) as conn:
        with conn.cursor() as cur:
            cur.execute(f"SELECT id, name FROM users WHERE name LIKE '%{q}%'")
            return cur.fetchall()


def _sqli_having(cond: str):
    with contextlib.closing(get_connection()) as conn:
        with conn.cursor() as cur:
            cur.execute(
                f"SELECT name, COUNT(*) AS c FROM users GROUP BY name "
                f"HAVING COUNT(*) >= 1 AND ({cond})"
            )
            return cur.fetchall()


async def _get_id_from_query_or_body(request: Request) -> str:
    """Reads id from query-parameter or from body (form). For demo vulnerable both in query and in body."""
    raw_id = request.query_params.get("id")
    if raw_id is not None:
        return raw_id
    try:
        form = await request.form()
        raw_id = form.get("id")
    except Exception:
        pass
    if raw_id is not None:
        return raw_id
    return "1"


@app.on_event("startup")
def startup():
    with contextlib.closing(get_connection()) as conn:
        conn.autocommit = True
        with conn.cursor() as cur:
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id SERIAL PRIMARY KEY,
                    name TEXT NOT NULL
                );
                """
            )
            cur.execute("SELECT 1 FROM users LIMIT 1")
            if cur.fetchone() is None:
                cur.execute(
                    "INSERT INTO users (name) VALUES ('Alice'), ('Bob'), ('Charlie')"
                )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS secrets (
                    id SERIAL PRIMARY KEY,
                    token TEXT NOT NULL
                );
                """
            )
            cur.execute("SELECT 1 FROM secrets LIMIT 1")
            if cur.fetchone() is None:
                cur.execute(
                    "INSERT INTO secrets (token) VALUES ('flag{demo_union_secret}')"
                )


@app.get("/")
def root():
    """List of demo routes (all vulnerable intentionally for sqlmap/injectify)."""
    return {
        "message": "Injectify Demo",
        "docs": "/docs",
        "note": "Каждый маршрут с @injectify сканируется sqlmap при старте — больше маршрутов, дольше запуск.",
        "routes": [
            "GET    /users?id=1",
            "POST   /users (query id= или body id=)",
            "PUT    /users (query id= или body id=)",
            "DELETE /users (query id= или body id=)",
            "OPTIONS /users (query id= или body id=)",
            "HEAD   /users/head?id=1",
            "--- SQLi по типам (GET) ---",
            "GET /sqli/reflected?id=1   — reflected + UNION (таблица secrets)",
            "GET /sqli/error?expr=1     — error-based (CAST)",
            "GET /sqli/boolean?id=1     — blind boolean (EXISTS)",
            "GET /sqli/time?cond=1=1    — blind time/boolean (AND cond)",
            "GET /sqli/orderby?column=id — ORDER BY injection",
            "GET /sqli/like?q=a       — LIKE / строковый контекст",
            "GET /sqli/having?cond=1=1  — HAVING injection",
        ],
    }


@app.get("/users")
@injectify(
    **INJECTIFY_COMMON,
    params={"id": ""},
)
async def get_users(request: Request):
    """
    GET /users — vulnerable SELECT by query id.
    Demo for sqlmap/injectify.
    """
    raw_id = request.query_params.get("id", "1")
    rows = await asyncio.to_thread(_fetch_users_by_id, raw_id)
    return JSONResponse(
        content=[{"id": r[0], "name": r[1]} for r in rows]
    )


@app.post("/users")
@injectify(
    **INJECTIFY_COMMON,
    params={"id": ""},
)
async def post_users(request: Request):
    """
    POST /users — vulnerable SELECT: id from query or body (form).
    Demo for sqlmap/injectify.
    """
    raw_id = await _get_id_from_query_or_body(request)
    rows = await asyncio.to_thread(_fetch_users_by_id, raw_id)
    return JSONResponse(
        content=[{"id": r[0], "name": r[1]} for r in rows]
    )


@app.put("/users")
@injectify(
    **INJECTIFY_COMMON,
    params={"id": ""},
)
async def put_users(request: Request):
    """
    PUT /users — vulnerable SELECT: id from query or body (form).
    Demo for sqlmap/injectify.
    """
    raw_id = await _get_id_from_query_or_body(request)
    rows = await asyncio.to_thread(_fetch_users_by_id, raw_id)
    return JSONResponse(
        content=[{"id": r[0], "name": r[1]} for r in rows]
    )


@app.delete("/users")
@injectify(
    **INJECTIFY_COMMON,
    params={"id": ""},
)
async def delete_users(request: Request):
    """
    DELETE /users — vulnerable SELECT: id from query or body (form).
    Demo for sqlmap/injectify.
    """
    raw_id = await _get_id_from_query_or_body(request)
    rows = await asyncio.to_thread(_fetch_users_by_id, raw_id)
    return JSONResponse(
        content=[{"id": r[0], "name": r[1]} for r in rows]
    )


@app.options("/users")
@injectify(
    **INJECTIFY_COMMON,
    params={"id": ""},
)
async def options_users(request: Request):
    """
    OPTIONS /users — vulnerable SELECT: id from query or body (form).
    Demo for sqlmap/injectify.
    """
    raw_id = await _get_id_from_query_or_body(request)
    rows = await asyncio.to_thread(_fetch_users_by_id, raw_id)
    return JSONResponse(
        content=[{"id": r[0], "name": r[1]} for r in rows]
    )


@app.head("/users/head")
@injectify(
    **INJECTIFY_COMMON,
    params={"id": ""},
)
async def head_users(request: Request):
    """
    HEAD /users/head — vulnerable SELECT by query id, response without body.
    Demo for sqlmap/injectify.
    """
    raw_id = request.query_params.get("id", "1")
    await asyncio.to_thread(_fetch_users_by_id, raw_id)
    return Response(status_code=200)


@app.get("/sqli/reflected")
@injectify(
    **{**INJECTIFY_COMMON, "sqlmap_extra": ["--technique=BEU"]},
    params={"id": ""},
)
async def sqli_reflected(request: Request):
    """Reflected numeric + UNION (есть таблица secrets)."""
    raw_id = request.query_params.get("id", "1")
    rows = await asyncio.to_thread(_fetch_users_by_id, raw_id)
    return JSONResponse(content=[{"id": r[0], "name": r[1]} for r in rows])


@app.get("/sqli/error")
@injectify(
    **{**INJECTIFY_COMMON, "sqlmap_extra": ["--technique=BEU"]},
    params={"expr": ""},
)
async def sqli_error(request: Request):
    """Error-based: некорректное приведение типа в сообщении об ошибке."""
    expr = request.query_params.get("expr", "1")
    is_err, payload = await asyncio.to_thread(_sqli_error_cast, expr)
    if is_err:
        return JSONResponse(status_code=500, content={"error": payload})
    return JSONResponse(content={"value": payload})


@app.get("/sqli/boolean")
@injectify(
    **{**INJECTIFY_COMMON, "sqlmap_extra": ["--technique=BEU"]},
    params={"id": ""},
)
async def sqli_boolean(request: Request):
    """Blind boolean: только факт существования строки."""
    raw_id = request.query_params.get("id", "1")
    exists = await asyncio.to_thread(_sqli_boolean_exists, raw_id)
    return JSONResponse(content={"exists": bool(exists)})


@app.get("/sqli/time")
@injectify(
    **{**INJECTIFY_COMMON, "sqlmap_extra": ["--technique=BTU"]},
    params={"cond": ""},
)
async def sqli_time(request: Request):
    """Blind time/boolean: одна строка id=1, условие в AND (pg_sleep в payload)."""
    cond = request.query_params.get("cond", "1=1")
    rows = await asyncio.to_thread(_sqli_time_cond, cond)
    return JSONResponse(content=[{"id": r[0], "name": r[1]} for r in rows])


@app.get("/sqli/orderby")
@injectify(
    **INJECTIFY_COMMON,
    params={"column": ""},
)
async def sqli_orderby(request: Request):
    """ORDER BY injection."""
    column = request.query_params.get("column", "id")
    rows = await asyncio.to_thread(_sqli_orderby, column)
    return JSONResponse(content=[{"id": r[0], "name": r[1]} for r in rows])


@app.get("/sqli/like")
@injectify(
    **INJECTIFY_COMMON,
    params={"q": ""},
)
async def sqli_like(request: Request):
    """LIKE / кавычки."""
    q = request.query_params.get("q", "%")
    rows = await asyncio.to_thread(_sqli_like, q)
    return JSONResponse(content=[{"id": r[0], "name": r[1]} for r in rows])


@app.get("/sqli/having")
@injectify(
    **INJECTIFY_COMMON,
    params={"cond": ""},
)
async def sqli_having(request: Request):
    """HAVING clause injection."""
    cond = request.query_params.get("cond", "1=1")
    rows = await asyncio.to_thread(_sqli_having, cond)
    return JSONResponse(content=[{"name": r[0], "count": r[1]} for r in rows])


@app.get("/health")
def health():
    return {"status": "ok"}
