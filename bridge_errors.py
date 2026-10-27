"""Lightweight shared errors; native credential helpers need no HTTP client imports."""


class CapabilityError(ValueError):
    """Static messages only: request data, credentials and server errors stay private."""
