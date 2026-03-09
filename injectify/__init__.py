# Injectify: decorator FastAPI for automatic checking routes through SQLMap
from .core import injectify, register_injectify_controller

__all__ = ["injectify", "register_injectify_controller"]
