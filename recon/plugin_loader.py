"""Plugin auto-discovery from plugins directory."""

from __future__ import annotations

import importlib.util
import logging
import sys
from pathlib import Path

from recon.plugin_base import ReconPlugin

LOG = logging.getLogger(__name__)


def discover_plugins(plugins_dir: Path) -> dict[str, ReconPlugin]:
    """Discover and instantiate plugins from *_plugin.py modules."""
    plugins: dict[str, ReconPlugin] = {}
    if not plugins_dir.exists():
        LOG.warning("Plugins directory missing: %s", plugins_dir)
        return plugins

    for plugin_file in sorted(plugins_dir.glob("*_plugin.py")):
        module_name = f"plugins.{plugin_file.stem}"
        spec = importlib.util.spec_from_file_location(module_name, plugin_file)
        if spec is None or spec.loader is None:
            continue

        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
        spec.loader.exec_module(module)

        register_fn = getattr(module, "register", None)
        if register_fn is None:
            continue

        plugin = register_fn()
        if not isinstance(plugin, ReconPlugin):
            LOG.warning("Invalid plugin in %s (register() result mismatch)", plugin_file.name)
            continue
        plugins[plugin.name] = plugin
    return plugins
