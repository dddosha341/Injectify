import inspect
from typing import Any, Callable, Dict, Optional, get_args, get_origin

# Optional: for output body from Pydantic model
try:
    from pydantic import BaseModel
except ImportError:
    BaseModel = None  # type: ignore[misc, assignment]


def _get_model_field_names(model: type) -> list:
    """Names of fields in Pydantic model (v1 and v2)."""
    if BaseModel is None or not issubclass(model, BaseModel):
        return []
    fields = getattr(model, "model_fields", None) or getattr(model, "__fields__", None)
    if fields is None:
        return []
    return list(fields.keys())


def _is_request(annotation: Any) -> bool:
    """Check if annotation is Request (FastAPI/Starlette)."""
    if annotation is None:
        return False
    try:
        from starlette.requests import Request as StarletteRequest
        return annotation is StarletteRequest or (isinstance(annotation, type) and issubclass(annotation, StarletteRequest))
    except ImportError:
        return False


def infer_params(func: Callable[..., Any], method: str) -> Optional[Dict[str, str]]:
    """
    Outputs parameter names for scan from the handler signature.
    GET: query-parameters (all, except Request and Pydantic model).
    POST: fields body from Pydantic model, if exists; otherwise query-parameters.
    Returns dict {name: ""} or None, if nothing is output.
    """
    try:
        sig = inspect.signature(func)
    except (ValueError, TypeError):
        return None
    query_names: list = []
    body_names: list = []
    for name, param in sig.parameters.items():
        ann = param.annotation
        if ann is inspect.Parameter.empty:
            query_names.append(name)
            continue
        if _is_request(ann):
            continue
        try:
            origin = get_origin(ann)
            args = get_args(ann) or ()
            cls = ann
            if origin is not None:
                cls = args[0] if args else ann
            if isinstance(cls, type) and BaseModel is not None and issubclass(cls, BaseModel):
                body_names.extend(_get_model_field_names(cls))
            else:
                query_names.append(name)
        except (TypeError, AttributeError):
            query_names.append(name)
    method_upper = (method or "GET").upper()
    if method_upper == "GET":
        names = query_names
    else:
        names = body_names if body_names else query_names
    if not names:
        return None
    return {n: "" for n in names}


def validate_params(params=None):
    """
    Checks if params is suitable for forming --data in sqlmap:
    either None, or a dict (keys — names of parameters for test).
    """
    if params is None:
        return
    if not isinstance(params, dict):
        raise ValueError(
            f"params must be None or a dict of parameter names, got {type(params).__name__}"
        )
    for key in params:
        if not isinstance(key, str):
            raise ValueError(
                f"params keys must be strings (parameter names), got key {key!r} of type {type(key).__name__}"
            )
