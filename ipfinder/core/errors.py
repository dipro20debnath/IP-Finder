"""Exceptions shared by core modules and providers (kept free of other imports,
so any module can use them without import cycles)."""


class ProviderError(Exception):
    """A provider could not produce data (network error, bad response, quota...)."""
