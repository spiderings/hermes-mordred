"""Hermes Desktop integration: a setup page (desktop half) and its local API.

``hermes-mordred desktop install`` places a thin ``~/.hermes/plugins/mordred``
folder (``desktop/plugin.js`` + ``dashboard/plugin_api.py`` shim) that Hermes
loads; the real API lives in :mod:`.api` inside this package.
"""
