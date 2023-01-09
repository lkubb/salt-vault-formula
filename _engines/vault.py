"""
Engine for the Vault integration. Ensures sessions
are kept alive and leases are renewed.

.. versionadded:: 3007

Configuration
-------------

interval
    Interval between renewal checks. Defaults to 300 (seconds).
    Can be specified as a time string like ``5m``/``1h`` as well.

leases
    List of regex patterns that match leases that should be
    checked for renewal. Defaults to ``.*``, which will monitor all
    cached leases.

min_lease_validity
    If a lease is valid for less than this amount of time, it will
    be renewed. Defaults to 1200 (20m).
    Can be specified as a time string like ``5m``/``1h`` as well.
"""

import logging
import re
import time

import salt.utils.vault as vault

log = logging.getLogger(__name__)


def start(interval=300, leases=".*", min_lease_validity=1200):
    """
    Start the Vault engine
    """
    interval = int(vault.timestring_map(interval))
    min_lease_validity = int(vault.timestring_map(min_lease_validity))
    engine = VaultEngine(
        interval=interval, leases=leases, min_lease_validity=min_lease_validity
    )
    engine.run()


class VaultEngine:
    running = True

    def __init__(self, interval=300, leases=".*", min_lease_validity=1200):
        self.interval = interval
        if not isinstance(leases, list):
            leases = [leases]
        self.lease_patterns = tuple(re.compile(ptrn) for ptrn in leases)

    def run(self):
        while self.running:
            # Ensure the current token is renewed, if possible.
            # This is done inside the vault util module and only
            # requires a request for an authenticated client.
            # Since requesting the lease store does that
            try:
                lease_store = vault.get_lease_store(__opts__, __context__)
            except Exception as err:  # pylint: disable=broad-except
                log.error(err)
                time.sleep(self.interval)
                continue

            all_leases = lease_store.list()
            if ".*" in self.leases or "*" in self.leases:
                leases = all_leases
            else:
                leases = []
                for ptrn in self.lease_patterns:
                    leases += [lease for lease in all_leases if ptrn.match(lease)]

            # Ensure registered leases matching are renewed.
            for lease in set(leases):
                # Requesting it from the store will renew it. Do not remove it from cache
                # if it does not fulfill the minimum validity though.
                try:
                    ret = lease_store.get(
                        lease, valid_for=self.min_lease_validity, flush=False
                    )
                except Exception as err:  # pylint: disable=broad-except
                    log.error(f"Failed requesting/renewing lease {lease}: {err}")
                    continue

                if ret is None:
                    log.warning(f"Monitored lease {lease} will run out")

            time.sleep(self.interval)
