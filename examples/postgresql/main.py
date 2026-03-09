"""
One-file FastAPI API with direct SELECT to DB and injectify decorator.
Demo: vulnerable endpoints for GET, POST, PUT, DELETE, OPTIONS, HEAD
(intentionally vulnerable for checking sqlmap/injectify).
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


@app.get("/")
def root():
    """List of demo routes (all vulnerable intentionally for sqlmap/injectify)."""
    return {
        "message": "Injectify Demo",
        "docs": "/docs",
        "routes": [
            "GET    /users?id=1",
            "POST   /users (query id= или body id=)",
            "PUT    /users (query id= или body id=)",
            "DELETE /users (query id= или body id=)",
            "OPTIONS /users (query id= или body id=)",
            "HEAD   /users/head?id=1",
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


@app.get("/health")
def health():
    return {"status": "ok"}
