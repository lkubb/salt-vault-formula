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

import vaultutil as vault
from salt.exceptions import CommandExecutionError

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
        self.all = ".*" in leases or "*" in leases
        self.lease_patterns = (
            tuple(re.compile(ptrn) for ptrn in leases) if not self.all else []
        )
        self.min_lease_validity = min_lease_validity

    def run(self):
        fail_ctr = 0
        while self.running:
            # Ensure the current token is renewed, if possible.
            # This is done inside the vault util module and only
            # requires a request for an authenticated client.
            # Since requesting the lease store does that
            try:
                try:
                    # __context__ is explicitly not passed:
                    # The context cache is designed for short processes like
                    # a `state.apply`. Since this engine is a long-running process,
                    # the context cache might/will get out of sync, but has priority,
                    # possibly overwriting fresher data in other caches.
                    lease_store = vault.get_lease_store(__opts__, {})
                    fail_ctr = 0
                except CommandExecutionError as err:
                    if "No access to master" in str(err):
                        log.warning(
                            "master_uri is not in opts, indicating no connection to master. Attempting reload"
                        )
                        return
                    raise
            except Exception as err:  # pylint: disable=broad-except
                log.error(f"Received error: {err}")
                fail_ctr += 1
                interval = self.interval
                if fail_ctr <= 5:
                    interval = interval / 5
                log.info(
                    f"Last {fail_ctr} attempts failed. Reattempting renewal in {interval} seconds"
                )
                time.sleep(interval)
                continue

            all_leases = lease_store.list()
            if self.all is True:
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
