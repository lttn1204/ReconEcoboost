"""Recon module plugins, organised by domain.

Importing a domain subpackage triggers registration of its modules. Analysis
modules for the same domain (which live under ``reconecoboost.analysis``) are
loaded alongside, if present.
"""

from __future__ import annotations

import importlib


def load_domain(domain: str) -> None:
    """Import a domain's modules (and matching analysis modules) to register them."""
    importlib.import_module(f"reconecoboost.modules.{domain}")
    try:
        importlib.import_module(f"reconecoboost.analysis.{domain}")
    except ModuleNotFoundError:
        pass
