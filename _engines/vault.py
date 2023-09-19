"""
Engine for the Vault integration. Ensures sessions
are kept alive and leases are renewed.

If Vault authentication credentials are sourced from
the local configuration, can be configured to warn about
expiry, including for AppRole SecretIDs (which would not
be warned about by expiry events).

.. versionadded:: 3007

Configuration
-------------

interval
    Interval between renewal checks. Defaults to 300 (seconds).
    Can be specified as a time string like ``5m``/``1h`` as well.

leases
    List of regex patterns that match leases that should be
    checked for renewal. Defaults to ``.*``, which will monitor all
    cached leases. Set this to a falsy value to disable renewals.

min_lease_validity
    If a lease is valid for less than this amount of time, it will
    be renewed. Defaults to 1200 (20m).
    Can be specified as a time string like ``5m``/``1h`` as well.

local_expire_event_interval
    If Vault authentication credentials are sourced from
    the local node configuration, warn about their future
    expiry, beginning from this interval before the actual event.
    Can be configured using a time string like ``2d``.
    Defaults to 0 (inactive).
"""

import logging
import re
import time

import vaultutil as vault
from salt.exceptions import CommandExecutionError

log = logging.getLogger(__name__)


def start(
    interval=300, leases=".*", min_lease_validity=1200, local_expire_event_interval=0
):
    """
    Start the Vault engine
    """
    interval = int(vault.timestring_map(interval))
    min_lease_validity = int(vault.timestring_map(min_lease_validity))
    engine = VaultEngine(
        interval=interval,
        leases=leases,
        min_lease_validity=min_lease_validity,
        local_expire_event_interval=local_expire_event_interval,
    )
    engine.run()


class VaultEngine:
    running = True

    def __init__(
        self,
        interval=300,
        leases=".*",
        min_lease_validity=1200,
        local_expire_event_interval=0,
    ):
        self.interval = interval
        if leases:
            if not isinstance(leases, list):
                leases = [leases]
            self.all = ".*" in leases or "*" in leases
            self.lease_patterns = (
                tuple(re.compile(ptrn) for ptrn in leases) if not self.all else []
            )
        else:
            self.all = False
            self.lease_patterns = None
        self.min_lease_validity = min_lease_validity
        if local_expire_event_interval:
            if not __opts__.get("vault", {}).get("server") or (
                __opts__.get("__role", "minion") == "minion"
                and __opts__.get("vault", {}).get("config_location") != "local"
            ):
                log.warning(
                    "No local Vault configuration found. Ignoring `local_expire_event_interval`"
                )
                local_expire_event_interval = 0
        self.local_expire_event_interval = vault.timestring_map(
            local_expire_event_interval
        )
        self.local_auth_cache = None

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

            if self.lease_patterns or self.all:
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
                            lease, valid_for=self.min_lease_validity, revoke=False
                        )
                    except Exception as err:  # pylint: disable=broad-except
                        log.error(f"Failed requesting/renewing lease {lease}: {err}")
                        continue

                    if ret is None:
                        log.warning(f"Monitored lease {lease} will run out")

            if self.local_expire_event_interval:
                if self.local_auth_cache is None:
                    client, config = vault.get_authd_client(
                        __opts__, {}, get_config=True
                    )
                    if config["auth"]["method"] == "token":
                        token = client.auth.token
                        self.local_auth_cache = token.expire_time
                    elif config["auth"]["method"] == "approle":
                        # SecretID meta info is not cached otherwise currently
                        api = vault.AppRoleApi(client)
                        res = vault.VaultSecretId(
                            secret_id=str(client.auth.approle.secret_id),
                            **api.read_secret_id(
                                config["auth"]["approle_name"],
                                mount=config["auth"]["approle_mount"],
                                secret_id=str(client.auth.approle.secret_id),
                            ),
                        )
                        self.local_auth_cache = res.expire_time

                expires = int(self.local_auth_cache - time.time())
                if expires < self.local_expire_event_interval:
                    vault._get_event(__opts__)(
                        tag="vault/auth/local/expire", data={"valid_for_less": expires}
                    )

            time.sleep(self.interval)
