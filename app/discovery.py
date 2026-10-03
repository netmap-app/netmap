"""Discovery — the front door to the source registry.

Kept as its own module so `from . import discovery` still means what it did
before there was more than one source. The sources themselves live in
`app.sources`; see that package's docstring for the finding shape they share.
"""
from .sources import (INTERVAL, cached, configured, health, loop,  # noqa: F401
                      names, refresh, scan, scan_all, scan_type, summary)
from .sources import (create_instance, delete_instance, drivers, roles,  # noqa: F401
                      interval, schedule, set_interval, set_stale_hours, stale_hours,
                      list_instances, migrate_legacy, pin_defaults, fold_scan_switch, rotate_secrets, test_fields,
                      test_instance, update_instance)


def scan_docker() -> dict:
    """The Docker source by name. Still here because the MCP tool of the same
    name is part of the published surface."""
    return scan_type("docker")

