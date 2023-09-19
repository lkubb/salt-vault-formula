"""
Beacon for the Vault integration. Sends events when a
lease's TTL undercuts a specified value.

.. versionadded:: 3007
"""

import logging
from datetime import datetime

import salt.utils.beacons
import vaultutil as vault

log = logging.getLogger(__name__)


__virtualname__ = "vault_lease"


def __virtual__():
    return __virtualname__


def validate(config):
    """
    Validate the beacon configuration
    """
    if not isinstance(config, list):
        return False, "Configuration for vault_lease must be a list"
    config = salt.utils.beacons.list_to_dict(config)
    if "lease" not in config:
        return False, "Requires monitored lease cache key in `lease`"
    if not isinstance(config["lease"], str):
        return False, "`lease` must be a string"
    return True, "Valid beacon configuration."


def beacon(config):
    """
    Watch the configured lease. Does not account for multiple ones.

    Example configuration:

    beacons:
      vault_write_stuff:
        - beacon_module: vault_lease
        - lease: db.database.dynamic.write_stuff.default
        - min_ttl: 1h
        - meta: write.stuff
        - check_server: true
    """
    config = salt.utils.beacons.list_to_dict(config)
    store = vault.get_lease_store(__opts__, {})
    info = store.list_info(match=config["lease"])
    events = []
    if not info:
        events.append(_enrich_info(config, {"expires_in": -1}))
        return events
    lease = info[config["lease"]]
    if config.get("check_server"):
        try:
            store.lookup(lease["lease_id"])
        except vault.VaultNotFoundError:
            store.revoke(lease["lease_id"], delta=lease.get("revoke_delay"))
            lease["expires_in"] = -1
            events.append(_enrich_info(config, lease))
            return events
    expires_in = int(lease["expire_time"] - datetime.now().timestamp())
    if (
        vault.timestring_map(
            config.get(
                "min_ttl", lease["min_ttl"] if lease.get("min_ttl") is not None else 300
            )
        )
        >= expires_in
    ):
        lease["expires_in"] = expires_in
        events.append(_enrich_info(config, lease))
    return events


def _enrich_info(config, info):
    info["ckey"] = config["lease"]
    info["meta"] = config.get("meta", info.get("meta"))
    info.pop("id", None)
    info["tag"] = "expire"
    return info
