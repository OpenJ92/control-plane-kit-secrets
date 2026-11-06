"""Supported eager ASGI entrypoint; reusable composition lives in application."""
from .application import app_from_environment


app = app_from_environment()
