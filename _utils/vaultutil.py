"""
:maintainer:    SaltStack
:maturity:      new
:platform:      all

Utilities supporting modules for Hashicorp Vault. Configuration instructions are
documented in the :ref:`execution module docs <vault-setup>`.
"""

import base64
import copy
import datetime
import fnmatch
import logging
import random
import re
import string
import time
from itertools import takewhile

import requests
import salt.cache
import salt.crypt
import salt.exceptions
import salt.modules.publish
import salt.modules.saltutil
import salt.utils.context
import salt.utils.data
import salt.utils.dictupdate
import salt.utils.event
import salt.utils.json
import salt.utils.versions
from requests.adapters import HTTPAdapter
from requests.adapters import Retry
from requests.exceptions import ConnectionError
from salt.exceptions import SaltInvocationError

try:
    from urllib3.util import create_urllib3_context

    URLLIB3V1 = False
except ImportError:
    # urllib <2
    from urllib3.util.ssl_ import create_urllib3_context

    URLLIB3V1 = True

try:
    from salt.defaults import NOT_SET
except ImportError:
    NOT_SET = "__unset__"


log = logging.getLogger(__name__)
logging.getLogger("requests").setLevel(logging.WARNING)


TOKEN_CKEY = "__token"
CLIENT_CKEY = "_vault_authd_client"

HTTP_TOO_MANY_REQUESTS = 429

# Default timeout configuration
DEFAULT_CONNECT_TIMEOUT = 9.2
DEFAULT_READ_TIMEOUT = 30

# Default retry configuration
DEFAULT_MAX_RETRIES = 5
DEFAULT_BACKOFF_FACTOR = 0.1
DEFAULT_BACKOFF_MAX = 10.0
DEFAULT_BACKOFF_JITTER = 0.2
DEFAULT_RETRY_POST = False
DEFAULT_RESPECT_RETRY_AFTER = True
DEFAULT_RETRY_AFTER_MAX = 60
# https://developer.hashicorp.com/vault/api-docs#http-status-codes
# 412: eventually consistent data is still missing (Enterprise)
DEFAULT_RETRY_STATUS = (412, 500, 502, 503, 504)

# Caps for retry configuration
MAX_MAX_RETRIES = 10
MAX_BACKOFF_FACTOR = 3.0
MAX_BACKOFF_MAX = 60.0
MAX_BACKOFF_JITTER = 5.0


def query(
    method,
    endpoint,
    opts,
    context,
    payload=None,
    wrap=False,
    raise_error=True,
    is_unauthd=False,
    **kwargs,
):
    """
    Query the Vault API. Supplemental arguments to ``requestes.request``
    can be passed as kwargs.

    method
        HTTP verb to use.

    endpoint
        API path to call (without leading ``/v1/``).

    opts
        Pass ``__opts__`` from the module.

    context
        Pass ``__context__`` from the module.

    payload
        Dictionary of payload values to send, if any.

    wrap
        Whether to request response wrapping. Should be a time string
        like ``30s`` or False (default).

    raise_error
        Whether to inspect the response code and raise exceptions.
        Defaults to True.

    is_unauthd
        Whether the queried endpoint is an unauthenticated one and hence
        does not deduct a token use. Only relevant for endpoints not found
        in ``sys``. Defaults to False.
    """
    client, config = get_authd_client(opts, context, get_config=True)
    try:
        return client.request(
            method,
            endpoint,
            payload=payload,
            wrap=wrap,
            raise_error=raise_error,
            is_unauthd=is_unauthd,
            **kwargs,
        )
    except VaultPermissionDeniedError:
        if not _check_clear(config, client):
            raise

    # in case policies have changed
    clear_cache(opts, context)
    client = get_authd_client(opts, context)
    return client.request(
        method,
        endpoint,
        payload=payload,
        wrap=wrap,
        raise_error=raise_error,
        is_unauthd=is_unauthd,
        **kwargs,
    )


def query_raw(
    method,
    endpoint,
    opts,
    context,
    payload=None,
    wrap=False,
    retry=True,
    is_unauthd=False,
    **kwargs,
):
    """
    Query the Vault API, returning the raw response object. Supplemental
    arguments to ``requestes.request`` can be passed as kwargs.

    method
        HTTP verb to use.

    endpoint
        API path to call (without leading ``/v1/``).

    opts
        Pass ``__opts__`` from the module.

    context
        Pass ``__context__`` from the module.

    payload
        Dictionary of payload values to send, if any.

    retry
        Retry the query with cleared cache in case the permission
        was denied (to check for revoked cached credentials).
        Defaults to True.

    wrap
        Whether to request response wrapping. Should be a time string
        like ``30s`` or False (default).

    is_unauthd
        Whether the queried endpoint is an unauthenticated one and hence
        does not deduct a token use. Only relevant for endpoints not found
        in ``sys``. Defaults to False.
    """
    client, config = get_authd_client(opts, context, get_config=True)
    res = client.request_raw(
        method, endpoint, payload=payload, wrap=wrap, is_unauthd=is_unauthd, **kwargs
    )

    if not retry:
        return res

    if res.status_code == 403:
        if not _check_clear(config, client):
            return res

        # in case policies have changed
        clear_cache(opts, context)
        client = get_authd_client(opts, context)
        res = client.request_raw(
            method,
            endpoint,
            payload=payload,
            wrap=wrap,
            is_unauthd=is_unauthd,
            **kwargs,
        )
    return res


def is_v2(path, opts=None, context=None):
    """
    Determines if a given secret path is kv version 1 or 2.
    """
    if opts is None or context is None:
        opts = globals().get("__opts__", {}) if opts is None else opts
        context = globals().get("__context__", {}) if context is None else context
        salt.utils.versions.warn_until(
            "Argon",
            "The __utils__ loader functionality will be removed. This will "
            "cause context/opts dunders to be unavailable in utility modules. "
            "Please pass opts and context from importing Salt modules explicitly.",
        )
    kv = get_kv(opts, context)
    return kv.is_v2(path)


def read_kv(path, opts, context, include_metadata=False):
    """
    Read secret at <path>.
    """
    kv, config = get_kv(opts, context, get_config=True)
    try:
        return kv.read(path, include_metadata=include_metadata)
    except VaultPermissionDeniedError:
        if not _check_clear(config, kv.client):
            raise

    # in case policies have changed
    clear_cache(opts, context)
    kv = get_kv(opts, context)
    return kv.read(path, include_metadata=include_metadata)


def read_kv_meta(path, opts, context):
    """
    Read secret metadata and version info at <path>.
    Requires KV v2.
    """
    kv, config = get_kv(opts, context, get_config=True)
    try:
        return kv.read_meta(path)
    except VaultPermissionDeniedError:
        if not _check_clear(config, kv.client):
            raise

    # in case policies have changed
    clear_cache(opts, context)
    kv = get_kv(opts, context)
    return kv.read_meta(path)


def write_kv(path, data, opts, context):
    """
    Write secret <data> to <path>.
    """
    kv, config = get_kv(opts, context, get_config=True)
    try:
        return kv.write(path, data)
    except VaultPermissionDeniedError:
        if not _check_clear(config, kv.client):
            raise

    # in case policies have changed
    clear_cache(opts, context)
    kv = get_kv(opts, context)
    return kv.write(path, data)


def patch_kv(path, data, opts, context):
    """
    Patch secret <data> at <path>.
    """
    kv, config = get_kv(opts, context, get_config=True)
    try:
        return kv.patch(path, data)
    except VaultAuthExpired:
        # patching can consume several token uses when
        # 1) `patch` cap unvailable 2) KV v1 3) KV v2 w/ old Vault versions
        kv = get_kv(opts, context)
        return kv.patch(path, data)
    except VaultPermissionDeniedError:
        if not _check_clear(config, kv.client):
            raise

    # in case policies have changed
    clear_cache(opts, context)
    kv = get_kv(opts, context)
    return kv.patch(path, data)


def delete_kv(path, opts, context, versions=None, all_versions=False):
    """
    Delete secret at <path>. For KV v2, versions can be specified,
    which will be soft-deleted.
    """
    kv, config = get_kv(opts, context, get_config=True)
    try:
        return kv.delete(path, versions=versions, all_versions=all_versions)
    except VaultPermissionDeniedError:
        if not _check_clear(config, kv.client):
            raise

    # in case policies have changed
    clear_cache(opts, context)
    kv = get_kv(opts, context)
    return kv.delete(path, versions=versions, all_versions=all_versions)


def destroy_kv(path, opts, context, versions=None, all_versions=False):
    """
    Destroy secret <versions> at <path>. Requires KV v2.
    """
    kv, config = get_kv(opts, context, get_config=True)
    try:
        return kv.destroy(path, versions, all_versions=all_versions)
    except VaultPermissionDeniedError:
        if not _check_clear(config, kv.client):
            raise

    # in case policies have changed
    clear_cache(opts, context)
    kv = get_kv(opts, context)
    return kv.destroy(path, versions, all_versions=all_versions)


def wipe_kv(path, opts, context):
    """
    Completely remove all version history and data at <path>.
    Requires KV v2.
    """
    kv, config = get_kv(opts, context, get_config=True)
    try:
        return kv.wipe(path)
    except VaultPermissionDeniedError:
        if not _check_clear(config, kv.client):
            raise

    # in case policies have changed
    clear_cache(opts, context)
    kv = get_kv(opts, context)
    return kv.wipe(path)


def list_kv(path, opts, context):
    """
    List secrets at <path>.
    """
    kv, config = get_kv(opts, context, get_config=True)
    try:
        return kv.list(path)
    except VaultPermissionDeniedError:
        if not _check_clear(config, kv.client):
            raise

    # in case policies have changed
    clear_cache(opts, context)
    kv = get_kv(opts, context)
    return kv.list(path)


def _check_clear(config, client):
    """
    Called when encountering a VaultPermissionDeniedError.
    Decides whether caches should be cleared to retry with
    possibly updated token policies.
    """
    if config["cache"]["clear_on_unauthorized"]:
        return True
    try:
        # verify the current token is still valid
        return not client.token_valid(remote=True)
    except VaultAuthExpired:
        return True


def get_kv(opts, context, get_config=False):
    """
    Return an instance of VaultKV, which can be used
    to interact with the ``kv`` backend.
    """
    client, config = get_authd_client(opts, context, get_config=True)
    ttl = None
    connection = True
    if config["cache"]["kv_metadata"] != "connection":
        ttl = config["cache"]["kv_metadata"]
        connection = False
    cbank = _get_cache_bank(opts, connection=connection)
    ckey = "secret_path_metadata"
    metadata_cache = VaultCache(
        context,
        cbank,
        ckey,
        cache_backend=_get_cache_backend(config, opts),
        ttl=ttl,
    )
    kv = VaultKV(client, metadata_cache)
    if get_config:
        return kv, config
    return kv


def get_lease_store(opts, context, get_config=False):
    """
    Return an instance of LeaseStore, which can be used
    to cache leases and handle operations like renewals and revocations.
    """
    client, config = get_authd_client(opts, context, get_config=True)
    session_cbank = _get_cache_bank(opts, session=True)
    expire_events = None
    if config["cache"]["expire_events"]:
        expire_events = _get_event(opts)
    lease_cache = VaultLeaseCache(
        context,
        session_cbank + "/leases",
        cache_backend=_get_cache_backend(config, opts),
        expire_events=expire_events,
    )
    store = LeaseStore(client, lease_cache, expire_events=expire_events)
    if get_config:
        return store, config
    return store


def get_approle_api(opts, context, force_local=False, get_config=False):
    """
    Return an instance of AppRoleApi containing an AuthenticatedVaultClient.
    """
    client, config = get_authd_client(
        opts, context, force_local=force_local, get_config=True
    )
    api = AppRoleApi(client)
    if get_config:
        return api, config
    return api


def get_identity_api(opts, context, force_local=False, get_config=False):
    """
    Return an instance of IdentityApi containing an AuthenticatedVaultClient.
    """
    client, config = get_authd_client(
        opts, context, force_local=force_local, get_config=True
    )
    api = IdentityApi(client)
    if get_config:
        return api, config
    return api


def clear_cache(
    opts, context, ckey=None, connection=True, session=False, force_local=False
):
    """
    Clears the Vault cache.
    Will ensure the current token and associated leases are revoked
    by default.

    It is organized in a hierarchy: ``/vault/connection/session/leases``.
    (*italics* mark data that is only cached when receiving configuration from a master)

    ``connection`` contains KV metadata (by default), *configuration* and *(AppRole) auth credentials*.
    ``session`` contains the currently active token.
    ``leases`` contains leases issued to the currently active token like database credentials.

    A master keeps a separate instance of the above per minion
    in ``minions/<minion_id>``.

    opts
        Pass ``__opts__``.

    context
        Pass ``__context__``.

    ckey
        Only clear this cache key instead of the whole cache bank.

    connection
        Only clear the cached data scoped to a connection. This includes
        configuration, auth credentials, the currently active auth token
        as well as leases and KV metadata (by default). Defaults to true.
        Set this to false to clear all Vault caches.

    session
        Only clear the cached data scoped to a session. This only includes
        leases and the currently active auth token, but not configuration
        or (AppRole) auth credentials. Defaults to false.
        Setting this to true will keep the connection cache, regardless
        of ``connection``.

    force_local
        Required on the master when the runner is issuing credentials during
        pillar compilation. Instructs the cache to use the ``/vault`` cache bank,
        regardless of determined run type. Defaults to false and should not
        be set by anything other than the runner.
    """
    cbank = _get_cache_bank(
        opts, connection=connection, session=session, force_local=force_local
    )
    if (
        not ckey
        or (not (connection or session) and ckey == "connection")
        or (session and ckey == TOKEN_CKEY)
        or ((connection and not session) and ckey == "config")
    ):
        client, config = _build_revocation_client(
            opts, context, force_local=force_local
        )
        # config and client will both be None if the cached data is invalid
        if config:
            try:
                # Don't revoke the only token that is available to us
                if config["auth"]["method"] != "token" or not (
                    force_local
                    or _get_salt_run_type(opts)
                    in (SALT_RUNTYPE_MASTER, SALT_RUNTYPE_MINION_LOCAL)
                ):
                    if config["cache"]["clear_attempt_revocation"]:
                        delta = config["cache"]["clear_attempt_revocation"]
                        if delta is True:
                            delta = 1
                        client.token_revoke(delta)
                    # Don't send expiry events for pillar compilation impersonation
                    if (
                        config["cache"]["expire_events"]
                        and not force_local
                        and _get_salt_run_type(opts)
                        not in (
                            SALT_RUNTYPE_MASTER_IMPERSONATING,
                            SALT_RUNTYPE_MASTER_PEER_RUN,
                        )
                    ):
                        scope = cbank.split("/")[-1]
                        _get_event(opts)(
                            data={"scope": scope}, tag=f"vault/cache/{scope}/clear"
                        )
            except Exception as err:  # pylint: disable=broad-except
                log.error(
                    "Failed to revoke token or send event before clearing cache:\n"
                    f"{type(err).__name__}: {err}"
                )
    if cbank in context:
        if ckey is None:
            context.pop(cbank)
        else:
            context[cbank].pop(ckey, None)
            if connection and not session:
                # Ensure the active client gets recreated after altering the connection cache
                context[cbank].pop(CLIENT_CKEY, None)

    # also remove sub-banks from context to mimic cache behavior
    if ckey is None:
        for bank in list(context):
            if bank.startswith(cbank):
                context.pop(bank)
    cache = salt.cache.factory(opts)
    if cache.contains(cbank, ckey):
        return cache.flush(cbank, ckey)

    # In case the cache driver was overridden for the Vault integration
    local_opts = copy.copy(opts)
    opts["cache"] = "localfs"
    cache = salt.cache.factory(local_opts)
    return cache.flush(cbank, ckey)


def update_config(opts, context, keep_session=False):
    """
    Attempt to update the cached configuration without
    clearing the currently active session.

    opts
        Pass __opts__.

    context
        Pass __context__.

    keep_session
        Only update configuration that can be updated without
        creating a new login session.
        If this is false, still tries to keep the active session,
        but might clear it if the server configuration has changed
        significantly.
        Defaults to False.
    """
    if _get_salt_run_type(opts) in (SALT_RUNTYPE_MASTER, SALT_RUNTYPE_MINION_LOCAL):
        # local configuration is not cached
        return True
    connection_cbank = _get_cache_bank(opts)
    try:
        _get_connection_config(connection_cbank, opts, context, update=True)
        return True
    except VaultConfigExpired:
        pass
    if keep_session:
        return False
    clear_cache(opts, context, connection=True)
    get_authd_client(opts, context)
    return True


def _get_cache_backend(config, opts):
    if config["cache"]["backend"] == "session":
        return None
    if config["cache"]["backend"] in ("localfs", "disk", "file"):
        # cache.Cache does not allow setting the type of cache by param
        local_opts = copy.copy(opts)
        local_opts["cache"] = "localfs"
        return salt.cache.factory(local_opts)
    # this should usually resolve to localfs as well on minions,
    # but can be overridden by setting cache in the minion config
    return salt.cache.factory(opts)


def expand_pattern_lists(pattern, **mappings):
    """
    Expands the pattern for any list-valued mappings, such that for any list of
    length N in the mappings present in the pattern, N copies of the pattern are
    returned, each with an element of the list substituted.

    pattern:
        A pattern to expand, for example ``by-role/{grains[roles]}``

    mappings:
        A dictionary of variables that can be expanded into the pattern.

    Example: Given the pattern `` by-role/{grains[roles]}`` and the below grains

    .. code-block:: yaml

        grains:
            roles:
                - web
                - database

    This function will expand into two patterns,
    ``[by-role/web, by-role/database]``.

    Note that this method does not expand any non-list patterns.
    """
    expanded_patterns = []
    f = string.Formatter()

    # This function uses a string.Formatter to get all the formatting tokens from
    # the pattern, then recursively replaces tokens whose expanded value is a
    # list. For a list with N items, it will create N new pattern strings and
    # then continue with the next token. In practice this is expected to not be
    # very expensive, since patterns will typically involve a handful of lists at
    # most.

    for _, field_name, _, _ in f.parse(pattern):
        if field_name is None:
            continue
        (value, _) = f.get_field(field_name, None, mappings)
        if isinstance(value, (list, dict)):
            token = f"{{{field_name}}}"
            expanded = [pattern.replace(token, str(elem)) for elem in value]
            for expanded_item in expanded:
                result = expand_pattern_lists(expanded_item, **mappings)
                expanded_patterns += result
            return expanded_patterns
    return [pattern]


def timestring_map(val):
    """
    Turn a time string (like ``60m``) into a float with seconds as a unit.
    """
    if val is None:
        return val
    if isinstance(val, (int, float)):
        return float(val)
    try:
        return float(val)
    except ValueError:
        pass
    if not isinstance(val, str):
        raise SaltInvocationError("Expected integer or time string")
    if not re.match(r"^\d+(?:\.\d+)?[smhd]$", val):
        raise SaltInvocationError(f"Invalid time string format: {val}")
    raw, unit = float(val[:-1]), val[-1]
    if unit == "s":
        return raw
    raw *= 60
    if unit == "m":
        return raw
    raw *= 60
    if unit == "h":
        return raw
    raw *= 24
    if unit == "d":
        return raw
    raise RuntimeError("This path should not have been hit")


SALT_RUNTYPE_MASTER = 0
SALT_RUNTYPE_MASTER_IMPERSONATING = 1
SALT_RUNTYPE_MASTER_PEER_RUN = 2
SALT_RUNTYPE_MINION_LOCAL = 3
SALT_RUNTYPE_MINION_REMOTE = 4


def _get_salt_run_type(opts):
    if "vault" in opts and opts.get("__role", "minion") == "master":
        if opts.get("minion_id"):
            return SALT_RUNTYPE_MASTER_IMPERSONATING
        if "grains" in opts and "id" in opts["grains"]:
            return SALT_RUNTYPE_MASTER_PEER_RUN
        return SALT_RUNTYPE_MASTER

    config_location = opts.get("vault", {}).get("config_location")
    if config_location and config_location not in ("local", "master"):
        raise salt.exceptions.InvalidConfigError(
            "Invalid vault configuration: config_location must be either local or master"
        )

    if config_location == "master":
        pass
    elif any(
        (
            opts.get("local", None),
            opts.get("file_client", None) == "local",
            opts.get("master_type", None) == "disable",
            config_location == "local",
        )
    ):
        return SALT_RUNTYPE_MINION_LOCAL
    return SALT_RUNTYPE_MINION_REMOTE


def _get_cache_bank(opts, force_local=False, connection=True, session=False):
    minion_id = None
    # force_local is necessary because pillar compilation would otherwise
    # leak tokens between master and minions
    if not force_local and _get_salt_run_type(opts) in (
        SALT_RUNTYPE_MASTER_IMPERSONATING,
        SALT_RUNTYPE_MASTER_PEER_RUN,
    ):
        minion_id = opts["grains"]["id"]
    prefix = "vault" if minion_id is None else f"minions/{minion_id}/vault"
    if session:
        return prefix + "/connection/session"
    if connection:
        return prefix + "/connection"
    return prefix


def get_authd_client(opts, context, force_local=False, get_config=False):
    """
    Returns an AuthenticatedVaultClient that is valid for at least one query.
    """
    # salt-ssh
    if "__master_opts__" in opts and "vault" not in opts:
        # Let's run the same way as during pillar compilation.
        vopts = {}
        vopts.update(opts)
        vopts.update(opts["__master_opts__"])
        vopts["id"] = vopts["minion_id"] = opts["id"]
        opts = vopts

    def try_build():
        client = config = None
        retry = False
        try:
            client, config = _build_authd_client(opts, context, force_local=force_local)
        except (VaultConfigExpired, VaultPermissionDeniedError, ConnectionError):
            clear_cache(opts, context, connection=True, force_local=force_local)
            retry = True
        except VaultUnwrapException as err:
            # ensure to notify about potential intrusion attempt
            _get_event(opts)(tag="vault/security/unwrapping/error", data=err.event_data)
            raise
        return client, config, retry

    cbank = _get_cache_bank(opts, force_local=force_local)
    retry = False
    client = config = None

    # First, check if an already initialized instance is available
    # and still valid
    if cbank in context and CLIENT_CKEY in context[cbank]:
        log.debug("Fetching client instance and config from context")
        client, config = context[cbank][CLIENT_CKEY]
        if not client.token_valid(remote=False):
            log.debug("Cached client instance was invalid")
            client = config = None
            context[cbank].pop(CLIENT_CKEY)

    # Otherwise, try to build one from possibly cached data
    if client is None or config is None:
        try:
            client, config, retry = try_build()
        except VaultAuthExpired:
            clear_cache(opts, context, session=True, force_local=force_local)
            client, config, retry = try_build()

    # Check if the token needs to be and can be renewed.
    # Since this needs to check the possibly active session and does not care
    # about valid secret IDs etc, we need to inspect the actual token.
    if (
        not retry
        and config["auth"]["token_lifecycle"]["renew_increment"] is not False
        and client.auth.get_token().is_renewable()
        and not client.auth.get_token().is_valid(
            config["auth"]["token_lifecycle"]["minimum_ttl"]
        )
    ):
        log.debug("Renewing token")
        client.token_renew(
            increment=config["auth"]["token_lifecycle"]["renew_increment"]
        )

    # Check if the current token could not be renewed for a sufficient amount of time.
    if not retry and not client.token_valid(
        config["auth"]["token_lifecycle"]["minimum_ttl"] or 0, remote=False
    ):
        clear_cache(opts, context, session=True, force_local=force_local)
        client, config, retry = try_build()

    if retry:
        log.debug("Requesting new authentication credentials")
        try:
            client, config = _build_authd_client(opts, context, force_local=force_local)
        except VaultUnwrapException as err:
            _get_event(opts)(tag="vault/security/unwrapping/error", data=err.event_data)
            raise
        if not client.token_valid(
            config["auth"]["token_lifecycle"]["minimum_ttl"] or 0, remote=False
        ):
            if not config["auth"]["token_lifecycle"]["minimum_ttl"]:
                raise VaultException(
                    "Could not build valid client. This is most likely a bug."
                )
            log.warning(
                "Configuration error: auth:token_lifecycle:minimum_ttl cannot be "
                "honored because fresh tokens are issued with less ttl. Continuing anyways."
            )

    if cbank not in context:
        context[cbank] = {}
    context[cbank][CLIENT_CKEY] = (client, config)

    if get_config:
        return client, config
    return client


def _build_authd_client(opts, context, force_local=False):
    connection_cbank = _get_cache_bank(opts, force_local=force_local)
    config, embedded_token, unauthd_client = _get_connection_config(
        connection_cbank, opts, context, force_local=force_local
    )
    # Tokens are cached in a distinct scope to enable cache per session
    session_cbank = _get_cache_bank(opts, force_local=force_local, session=True)
    cache_ttl = (
        config["cache"]["secret"] if config["cache"]["secret"] != "ttl" else None
    )
    token_cache = VaultAuthCache(
        context,
        session_cbank,
        TOKEN_CKEY,
        VaultToken,
        cache_backend=_get_cache_backend(config, opts),
        ttl=cache_ttl,
        flush_exception=VaultAuthExpired,
    )

    client = None

    if config["auth"]["method"] == "approle":
        secret_id = config["auth"]["secret_id"] or None
        cached_token = token_cache.get(10)
        secret_id_cache = None
        if secret_id:
            secret_id_cache = VaultAuthCache(
                context,
                connection_cbank,
                "secret_id",
                VaultSecretId,
                cache_backend=_get_cache_backend(config, opts),
                ttl=cache_ttl,
            )
            secret_id = secret_id_cache.get()
            # Only fetch secret ID if there is no cached valid token
            if cached_token is None and secret_id is None:
                secret_id = _fetch_secret_id(
                    config,
                    opts,
                    secret_id_cache,
                    unauthd_client,
                    force_local=force_local,
                )
            if secret_id is None:
                # If the auth config is sourced locally, ensure the
                # secret ID is known regardless whether we have a valid token.
                # For remote sources, we would needlessly request one, so don't.
                if (
                    _get_salt_run_type(opts)
                    in (SALT_RUNTYPE_MASTER, SALT_RUNTYPE_MINION_LOCAL)
                    or force_local
                ):
                    secret_id = _fetch_secret_id(
                        config,
                        opts,
                        secret_id_cache,
                        unauthd_client,
                        force_local=force_local,
                    )
                else:
                    secret_id = InvalidVaultSecretId()
        role_id = config["auth"]["role_id"]
        # this happens with wrapped response merging
        if isinstance(role_id, dict):
            role_id = role_id["role_id"]
        approle = VaultAppRole(role_id, secret_id)
        token_auth = VaultTokenAuth(cache=token_cache)
        auth = VaultAppRoleAuth(
            approle,
            unauthd_client,
            mount=config["auth"]["approle_mount"],
            cache=secret_id_cache,
            token_store=token_auth,
        )
        client = AuthenticatedVaultClient(
            auth, session=unauthd_client.session, **config["server"], **config["client"]
        )
    elif config["auth"]["method"] in ("token", "wrapped_token"):
        token = _fetch_token(
            config,
            opts,
            token_cache,
            unauthd_client,
            force_local=force_local,
            embedded_token=embedded_token,
        )
        auth = VaultTokenAuth(token=token, cache=token_cache)
        client = AuthenticatedVaultClient(
            auth, session=unauthd_client.session, **config["server"], **config["client"]
        )

    if client is not None:
        return client, config
    raise salt.exceptions.SaltException("Connection configuration is invalid.")


def _build_revocation_client(opts, context, force_local=False):
    """
    Tries to build an AuthenticatedVaultClient solely from caches.
    This client is used to revoke all leases before forgetting about them.
    """
    connection_cbank = _get_cache_bank(opts, force_local=force_local)
    # Disregard a possibly returned locally configured token since
    # it is cached with metadata if it has been used. Also, we do not want
    # to revoke statically configured tokens anyways.
    config, _, unauthd_client = _get_connection_config(
        connection_cbank, opts, context, force_local=force_local, pre_flush=True
    )
    if config is None:
        return None, None

    # Tokens are cached in a distinct scope to enable cache per session
    session_cbank = _get_cache_bank(opts, force_local=force_local, session=True)
    token_cache = VaultAuthCache(
        context,
        session_cbank,
        TOKEN_CKEY,
        VaultToken,
        cache_backend=_get_cache_backend(config, opts),
    )

    token = token_cache.get(flush=False)

    if token is None:
        return None, None
    auth = VaultTokenAuth(token=token, cache=token_cache)
    client = AuthenticatedVaultClient(
        auth, session=unauthd_client.session, **config["server"], **config["client"]
    )
    return client, config


def _check_upgrade(config, pre_flush=False):
    """
    Check if cached configuration contains all expected keys.
    Relevant when new keys are introduced to not break immediately after
    an update since the cached config is assumed to have been parsed already.
    pre_flush needs to be passed since we don't want to cause an update
    immediately before flushing the cache anyways.
    """
    if "client" not in config:
        if not pre_flush:
            return True
        config["client"] = {}
    return False


def _get_connection_config(
    cbank, opts, context, force_local=False, pre_flush=False, update=False
):
    if (
        _get_salt_run_type(opts) in (SALT_RUNTYPE_MASTER, SALT_RUNTYPE_MINION_LOCAL)
        or force_local
    ):
        # only cache config fetched from remote
        return _use_local_config(opts)

    if pre_flush and update:
        raise VaultException("`pre_flush` and `update` are mutually exclusive")
    log.debug("Using Vault server connection configuration from remote.")
    config_cache = _get_config_cache(opts, context, cbank)
    if pre_flush:
        # ensure any cached data is tried when building a client for revocation
        config_cache.ttl = None
    # In case cached data is available, this takes care of bubbling up
    # an exception indicating all connection-scoped data should be flushed
    # if the config is outdated.
    config = config_cache.get()
    if config is not None:
        # Check if the cached config is compatible with the current version.
        update = update or _check_upgrade(config, pre_flush)
        if not update:
            log.debug("Using cached Vault server connection configuration.")
            return config, None, VaultClient(**config["server"], **config["client"])

    if pre_flush:
        # used when building a client that revokes leases before clearing cache
        return None, None, None

    log.debug("Using new Vault server connection configuration.")
    try:
        issue_params = parse_config(opts.get("vault", {}), validate=False)[
            "issue_params"
        ]
        new_config, unwrap_client = _query_master(
            "get_config",
            opts,
            issue_params=issue_params or None,
            config_only=update,
        )
    except VaultConfigExpired as err:
        # Make sure to still work with old peer_run configuration
        if "Peer runner return was empty" not in err.message or update:
            raise
        log.warning(
            "Got empty response to Vault config request. Falling back to vault.generate_token. "
            "Please update your master peer_run configuration."
        )
        new_config, unwrap_client = _query_master(
            "generate_token",
            opts,
            ttl=issue_params.get("explicit_max_ttl"),
            uses=issue_params.get("num_uses"),
            upgrade_request=True,
        )
    new_config = parse_config(new_config, opts=opts, require_token=not update)
    # do not couple token cache with configuration cache
    embedded_token = new_config["auth"].pop("token", None)
    new_config = {
        "auth": new_config["auth"],
        "cache": new_config["cache"],
        "client": new_config["client"],
        "server": new_config["server"],
    }
    if update and config:
        if new_config["server"] != config["server"]:
            raise VaultConfigExpired()
        if new_config["auth"]["method"] != config["auth"]["method"]:
            raise VaultConfigExpired()
        if new_config["auth"]["method"] == "approle" and (
            new_config["auth"]["role_id"] != config["auth"]["role_id"]
            or new_config["auth"]["secret_id"] is not config["auth"]["secret_id"]
        ):
            raise VaultConfigExpired()
        if new_config["cache"]["backend"] != config["cache"]["backend"]:
            raise VaultConfigExpired()
        config_cache.flush(cbank=False)

    config_cache.store(new_config)
    if unwrap_client is None:
        unwrap_client = VaultClient(**new_config["server"], **new_config["client"])
    return new_config, embedded_token, unwrap_client


def _use_local_config(opts):
    log.debug("Using Vault connection details from local config.")
    config = parse_config(opts.get("vault", {}))
    embedded_token = config["auth"].pop("token", None)
    return (
        {
            "auth": config["auth"],
            "cache": config["cache"],
            "client": config["client"],
            "server": config["server"],
        },
        embedded_token,
        VaultClient(**config["server"], **config["client"]),
    )


def _fetch_secret_id(config, opts, secret_id_cache, unwrap_client, force_local=False):
    def cache_or_fetch(config, opts, secret_id_cache, unwrap_client):
        secret_id = secret_id_cache.get()
        if secret_id is not None:
            return secret_id

        log.debug("Fetching new Vault AppRole secret ID.")
        secret_id, _ = _query_master(
            "generate_secret_id",
            opts,
            unwrap_client=unwrap_client,
            unwrap_expected_creation_path=_get_expected_creation_path(
                "secret_id", config
            ),
            issue_params=parse_config(opts.get("vault", {}), validate=False)[
                "issue_params"
            ]
            or None,
        )
        secret_id = VaultSecretId(**secret_id["data"])
        # Do not cache single-use secret IDs
        if secret_id.num_uses != 1:
            secret_id_cache.store(secret_id)
        return secret_id

    if (
        _get_salt_run_type(opts) in (SALT_RUNTYPE_MASTER, SALT_RUNTYPE_MINION_LOCAL)
        or force_local
    ):
        secret_id = config["auth"]["secret_id"]
        if isinstance(secret_id, dict):
            if secret_id.get("wrap_info"):
                secret_id = unwrap_client.unwrap(
                    secret_id["wrap_info"]["token"],
                    expected_creation_path=_get_expected_creation_path(
                        "secret_id", config
                    ),
                )
                secret_id = secret_id["data"]
            return LocalVaultSecretId(**secret_id)
        if secret_id:
            # assume locally configured secret_ids do not expire
            return LocalVaultSecretId(
                secret_id=config["auth"]["secret_id"],
                secret_id_ttl=0,
                secret_id_num_uses=0,
            )
        # When secret_id is falsey, the approle does not require secret IDs,
        # hence a call to this function is superfluous
        raise salt.exceptions.SaltException("This code path should not be hit at all.")

    log.debug("Using secret_id issued by master.")
    return cache_or_fetch(config, opts, secret_id_cache, unwrap_client)


def _fetch_token(
    config, opts, token_cache, unwrap_client, force_local=False, embedded_token=None
):
    def cache_or_fetch(config, opts, token_cache, unwrap_client, embedded_token):
        token = token_cache.get(10)
        if token is not None:
            log.debug("Using cached token.")
            return token

        if isinstance(embedded_token, dict):
            token = VaultToken(**embedded_token)

        if not isinstance(token, VaultToken) or not token.is_valid(10):
            log.debug("Fetching new Vault token.")
            token, _ = _query_master(
                "generate_new_token",
                opts,
                unwrap_client=unwrap_client,
                unwrap_expected_creation_path=_get_expected_creation_path(
                    "token", config
                ),
                issue_params=parse_config(opts.get("vault", {}), validate=False)[
                    "issue_params"
                ]
                or None,
            )
            token = VaultToken(**token["auth"])

        # do not cache single-use tokens
        if token.num_uses != 1:
            token_cache.store(token)
        return token

    if (
        _get_salt_run_type(opts) in (SALT_RUNTYPE_MASTER, SALT_RUNTYPE_MINION_LOCAL)
        or force_local
    ):
        token = None
        if isinstance(embedded_token, dict):
            if embedded_token.get("wrap_info"):
                embedded_token = unwrap_client.unwrap(
                    embedded_token["wrap_info"]["token"],
                    expected_creation_path=_get_expected_creation_path("token", config),
                )["auth"]
            token = VaultToken(**embedded_token)
        elif config["auth"]["method"] == "wrapped_token":
            embedded_token = unwrap_client.unwrap(
                embedded_token,
                expected_creation_path=_get_expected_creation_path("token", config),
            )["auth"]
            token = VaultToken(**embedded_token)
        elif embedded_token is not None:
            # if the embedded plain token info has been cached before, don't repeat
            # the query unnecessarily
            token = token_cache.get()
            if token is None or embedded_token != str(token):
                # lookup and verify raw token
                token_info = unwrap_client.token_lookup(embedded_token, raw=True)
                if token_info.status_code != 200:
                    raise VaultException(
                        "Configured token cannot be verified. It is most likely expired or invalid."
                    )
                token_meta = token_info.json()["data"]
                token = VaultToken(
                    lease_id=embedded_token,
                    lease_duration=token_meta["ttl"],
                    **token_meta,
                )
                token_cache.store(token)
        if token is not None:
            return token
        raise VaultException("Invalid configuration, missing token.")

    log.debug("Using token generated by master.")
    return cache_or_fetch(config, opts, token_cache, unwrap_client, embedded_token)


def _query_master(
    func,
    opts,
    unwrap_client=None,
    unwrap_expected_creation_path=None,
    **kwargs,
):
    def check_result(
        result,
        unwrap_client=None,
        unwrap_expected_creation_path=None,
    ):
        if not result:
            log.error(
                "Failed to get Vault connection from master! No result returned - "
                "does the peer runner publish configuration include `vault.%s`?",
                func,
            )
            # Expire configuration in case this is the result of an auth method change.
            raise VaultConfigExpired(
                f"Peer runner return was empty. Make sure {func} is listed in the master peer_run config."
            )
        if not isinstance(result, dict):
            log.error(
                "Failed to get Vault connection from master! Response is not a dict: %s",
                result,
            )
            raise salt.exceptions.CommandExecutionError(result)
        if "error" in result:
            log.error(
                "Failed to get Vault connection from master! An error was returned: %s",
                result["error"],
            )
            if result.get("expire_cache"):
                log.warning("Master returned error and requested cache expiration.")
                raise VaultConfigExpired()
            raise salt.exceptions.CommandExecutionError(result)

        config_expired = False
        expected_server = None

        if result.get("expire_cache", False):
            log.info("Master requested Vault config expiration.")
            config_expired = True

        if "server" in result:
            # Ensure locally overridden verify parameter does not
            # always invalidate cache.
            reported_server = parse_config(result["server"], validate=False, opts=opts)[
                "server"
            ]
            result.update({"server": reported_server})

        if unwrap_client is not None:
            expected_server = unwrap_client.get_config()

        if expected_server is not None and result.get("server") != expected_server:
            log.info(
                "Mismatch of cached and reported server data detected. Invalidating cache."
            )
            # make sure to fetch wrapped data anyways for security reasons
            config_expired = True
            unwrap_expected_creation_path = None
            unwrap_client = None

        # This is used to augment some vault responses with data fetched by the master
        # e.g. secret_id_num_uses
        misc_data = result.get("misc_data", {})

        if result.get("wrap_info") or result.get("wrap_info_nested"):
            if unwrap_client is None:
                unwrap_client = VaultClient(**result["server"])

            for key in [""] + result.get("wrap_info_nested", []):
                if key:
                    wrapped = salt.utils.data.traverse_dict(result, key)
                else:
                    wrapped = result
                if not wrapped or "wrap_info" not in wrapped:
                    continue
                wrapped_response = VaultWrappedResponse(**wrapped["wrap_info"])
                try:
                    unwrapped_response = unwrap_client.unwrap(
                        wrapped_response,
                        expected_creation_path=unwrap_expected_creation_path,
                    )
                except VaultUnwrapException as err:
                    err.event_data.update({"func": f"vault.{func}"})
                    raise
                if key:
                    salt.utils.dictupdate.set_dict_key_value(
                        result,
                        key,
                        unwrapped_response.get("auth")
                        or unwrapped_response.get("data"),
                    )
                else:
                    if unwrapped_response.get("auth"):
                        result.update({"auth": unwrapped_response["auth"]})
                    if unwrapped_response.get("data"):
                        result.update({"data": unwrapped_response["data"]})

        if config_expired:
            raise VaultConfigExpired()

        for key, val in misc_data.items():
            tgt = "data" if result.get("data") is not None else "auth"
            if (
                salt.utils.data.traverse_dict_and_list(result, f"{tgt}:{key}", NOT_SET)
                == NOT_SET
            ):
                salt.utils.dictupdate.set_dict_key_value(
                    result,
                    f"{tgt}:{key}",
                    val,
                )

        result.pop("wrap_info", None)
        result.pop("wrap_info_nested", None)
        result.pop("misc_data", None)
        return result, unwrap_client

    minion_id = opts["grains"]["id"]
    pki_dir = opts["pki_dir"]

    # When rendering pillars, the module executes on the master, but the token
    # should be issued for the minion, so that the correct policies are applied
    if opts.get("__role", "minion") == "minion":
        private_key = f"{pki_dir}/minion.pem"
        log.debug(
            "Running on minion, signing request `vault.%s` with key %s",
            func,
            private_key,
        )
        signature = base64.b64encode(salt.crypt.sign_message(private_key, minion_id))
        arg = [
            ("minion_id", minion_id),
            ("signature", signature),
            ("impersonated_by_master", False),
        ] + list(kwargs.items())

        with salt.utils.context.func_globals_inject(
            salt.modules.publish.runner, __opts__=opts
        ):
            result = salt.modules.publish.runner(
                f"vault.{func}", arg=[{"__kwarg__": True, k: v} for k, v in arg]
            )
    else:
        private_key = f"{pki_dir}/master.pem"
        log.debug(
            "Running on master, signing request `vault.%s` for %s with key %s",
            func,
            minion_id,
            private_key,
        )
        signature = base64.b64encode(salt.crypt.sign_message(private_key, minion_id))
        with salt.utils.context.func_globals_inject(
            salt.modules.saltutil.runner, __opts__=opts
        ):
            result = salt.modules.saltutil.runner(
                f"vault.{func}",
                minion_id=minion_id,
                signature=signature,
                impersonated_by_master=True,
                **kwargs,
            )
    return check_result(
        result,
        unwrap_client=unwrap_client,
        unwrap_expected_creation_path=unwrap_expected_creation_path,
    )


def _get_event(opts):
    event = salt.utils.event.get_event(
        opts.get("__role", "minion"), sock_dir=opts["sock_dir"], opts=opts, listen=False
    )

    if opts.get("__role", "minion") == "minion":
        return event.fire_master
    return event.fire_event


def parse_config(config, validate=True, opts=None, require_token=True):
    """
    Returns a vault configuration dictionary that has all
    keys with defaults. Checks if required data is available.
    """
    default_config = {
        "auth": {
            "approle_mount": "approle",
            "approle_name": "salt-master",
            "method": "token",
            "secret_id": None,
            "token_lifecycle": {
                "minimum_ttl": 10,
                "renew_increment": None,
            },
        },
        "cache": {
            "backend": "session",
            "clear_attempt_revocation": 60,
            "clear_on_unauthorized": True,
            "config": 3600,
            "expire_events": False,
            "kv_metadata": "connection",
            "secret": "ttl",
        },
        "client": {
            "connect_timeout": DEFAULT_CONNECT_TIMEOUT,
            "read_timeout": DEFAULT_READ_TIMEOUT,
            "max_retries": DEFAULT_MAX_RETRIES,
            "backoff_factor": DEFAULT_BACKOFF_FACTOR,
            "backoff_max": DEFAULT_BACKOFF_MAX,
            "backoff_jitter": DEFAULT_BACKOFF_JITTER,
            "retry_post": DEFAULT_RETRY_POST,
            "retry_status": list(DEFAULT_RETRY_STATUS),
            "respect_retry_after": DEFAULT_RESPECT_RETRY_AFTER,
            "retry_after_max": DEFAULT_RETRY_AFTER_MAX,
        },
        "issue": {
            "allow_minion_override_params": False,
            "type": "token",
            "approle": {
                "mount": "salt-minions",
                "params": {
                    "bind_secret_id": True,
                    "secret_id_num_uses": 1,
                    "secret_id_ttl": 60,
                    "token_explicit_max_ttl": 60,
                    "token_num_uses": 10,
                },
            },
            "token": {
                "role_name": None,
                "params": {
                    "explicit_max_ttl": None,
                    "num_uses": 1,
                },
            },
            "wrap": "30s",
        },
        "issue_params": {},
        "metadata": {
            "entity": {
                "minion-id": "{minion}",
            },
            "secret": {
                "saltstack-jid": "{jid}",
                "saltstack-minion": "{minion}",
                "saltstack-user": "{user}",
            },
        },
        "policies": {
            "assign": [
                "saltstack/minions",
                "saltstack/{minion}",
            ],
            "cache_time": 60,
            "refresh_pillar": None,
        },
        "server": {
            "namespace": None,
            "verify": None,
        },
    }
    # Policy generation has params, the new config groups them together.
    if isinstance(config.get("policies", {}), list):
        config["policies"] = {"assign": config.pop("policies")}
    merged = salt.utils.dictupdate.merge(
        default_config,
        config,
        strategy="smart",
        merge_lists=False,
    )
    # ttl, uses were used as configuration for issuance and minion overrides as well
    # as token meta information. The new configuration splits those semantics.
    for old_token_conf, new_token_conf in (
        ("ttl", "explicit_max_ttl"),
        ("uses", "num_uses"),
    ):
        if old_token_conf in merged["auth"]:
            merged["issue"]["token"]["params"][new_token_conf] = merged["issue_params"][
                new_token_conf
            ] = merged["auth"].pop(old_token_conf)
    # Those were found in the root namespace, but grouping them together
    # makes semantic and practical sense.
    for old_server_conf in ("namespace", "url", "verify"):
        if old_server_conf in merged:
            merged["server"][old_server_conf] = merged.pop(old_server_conf)
    if "role_name" in merged:
        merged["issue"]["token"]["role_name"] = merged.pop("role_name")
    if "token_backend" in merged["auth"]:
        merged["cache"]["backend"] = merged["auth"].pop("token_backend")
    if "allow_minion_override" in merged["auth"]:
        merged["issue"]["allow_minion_override_params"] = merged["auth"].pop(
            "allow_minion_override"
        )
    if opts is not None and "vault" in opts:
        local_config = opts["vault"]
        # Respect locally configured verify parameter
        if local_config.get("verify", NOT_SET) != NOT_SET:
            merged["server"]["verify"] = local_config["verify"]
        elif local_config.get("server", {}).get("verify", NOT_SET) != NOT_SET:
            merged["server"]["verify"] = local_config["server"]["verify"]
        # same for token_lifecycle
        if local_config.get("auth", {}).get("token_lifecycle"):
            merged["auth"]["token_lifecycle"] = local_config["auth"]["token_lifecycle"]
        # and client config
        if local_config.get("client"):
            merged["client"] = {**merged["client"], **local_config["client"]}

    if not validate:
        return merged

    try:
        if merged["auth"]["method"] == "approle":
            if "role_id" not in merged["auth"]:
                raise AssertionError("auth:role_id is required for approle auth")
        elif merged["auth"]["method"] == "token":
            if require_token and "token" not in merged["auth"]:
                raise AssertionError("auth:token is required for token auth")
        else:
            raise AssertionError(
                f"`{merged['auth']['method']}` is not a valid auth method."
            )

        if "url" not in merged["server"]:
            raise AssertionError("server:url is required")
    except AssertionError as err:
        raise salt.exceptions.InvalidConfigError(
            f"Invalid vault configuration: {err}"
        ) from err
    return merged


def _get_expected_creation_path(secret_type, config=None):
    if secret_type == "token":
        return r"auth/token/create(/[^/]+)?"

    if secret_type == "secret_id":
        if config is not None:
            return r"auth/{}/role/{}/secret\-id".format(
                re.escape(config["auth"]["approle_mount"]),
                re.escape(config["auth"]["approle_name"]),
            )
        return r"auth/[^/]+/role/[^/]+/secret\-id"

    if secret_type == "role_id":
        if config is not None:
            return r"auth/{}/role/{}/role\-id".format(
                re.escape(config["auth"]["approle_mount"]),
                re.escape(config["auth"]["approle_name"]),
            )
        return r"auth/[^/]+/role/[^/]+/role\-id"

    raise VaultInvocationError(
        f"secret_type must be one of token, secret_id, role_id, got `{secret_type}`."
    )


class VaultException(salt.exceptions.SaltException):
    """
    Base class for exceptions raised by this module
    """


class VaultLeaseExpired(VaultException):
    """
    Raised when a cached lease is reported to be expired locally.
    """

    def __init__(self, lease):
        super().__init__()
        self.lease = lease


class VaultAuthExpired(VaultException):
    """
    Raised when cached authentication data is reported to be outdated locally.
    """


class VaultConfigExpired(VaultException):
    """
    Raised when secret authentication data queried from the master reports
    a different server configuration than locally cached or an explicit
    cache TTL set in the configuration has been reached.
    """


class VaultUnwrapException(VaultException):
    """
    Raised when an expected creation path for a wrapping token differs
    from the reported one.
    This has to be taken seriously as it indicates tampering.
    """

    def __init__(self, expected, actual, url, namespace, verify, *args, **kwargs):
        msg = (
            "Wrapped response was not created from expected Vault path: "
            f"`{actual}` is not matched by any of `{expected}`.\n"
            "This indicates tampering with the wrapping token by a third party "
            "and should be taken very seriously! If you changed some authentication-"
            "specific configuration on the master recently, especially minion "
            "approle mount, you should consider if this error was caused by outdated "
            "cached data on this minion instead."
        )
        super().__init__(msg, *args, **kwargs)
        self.event_data = {
            "expected": expected,
            "actual": actual,
            "url": url,
            "namespace": namespace,
            "verify": verify,
        }


# https://www.vaultproject.io/api-docs#http-status-codes
class VaultInvocationError(VaultException):
    """
    HTTP 400 and InvalidArgumentException for this module
    """


class VaultPermissionDeniedError(VaultException):
    """
    HTTP 403
    """


class VaultNotFoundError(VaultException):
    """
    HTTP 404
    In some cases, this is also raised when the client does not have
    the correct permissions for the requested endpoint.
    """


class VaultUnsupportedOperationError(VaultException):
    """
    HTTP 405
    """


class VaultPreconditionFailedError(VaultException):
    """
    HTTP 412
    """


class VaultRateLimitExceededError(VaultException):
    """
    HTTP 429
    """


class VaultServerError(VaultException):
    """
    HTTP 500
    HTTP 502
    """


class VaultUnavailableError(VaultException):
    """
    HTTP 503
    Indicates maintenance or sealed status.
    """


class VaultAPIAdapter(HTTPAdapter):
    """
    An adapter that

        * allows to restrict requests CA chain validation to a single
          root certificate without writing it to disk.
        * sets default values for timeout settings without having to
          specify it in every request.
    """

    def __init__(
        self, *args, verify=None, connect_timeout=None, read_timeout=None, **kwargs
    ):
        ca_cert_data = None
        try:
            if verify.strip().startswith("-----BEGIN CERTIFICATE"):
                ca_cert_data = verify
                verify = None
        except AttributeError:
            pass
        self.ca_cert_data = ca_cert_data
        self.verify = verify
        self.connect_timeout = connect_timeout or DEFAULT_CONNECT_TIMEOUT
        self.read_timeout = read_timeout or DEFAULT_READ_TIMEOUT
        super().__init__(*args, **kwargs)

    def init_poolmanager(
        self,
        connections,
        maxsize,
        block=requests.adapters.DEFAULT_POOLBLOCK,
        **pool_kwargs,
    ):
        if self.ca_cert_data is not None:
            ssl_context = create_urllib3_context()
            ssl_context.load_verify_locations(cadata=self.ca_cert_data)
            pool_kwargs["ssl_context"] = ssl_context
        return super().init_poolmanager(
            connections, maxsize, block=block, **pool_kwargs
        )

    def send(
        self, request, stream=False, timeout=None, verify=True, cert=None, proxies=None
    ):
        """
        Wrap sending the request to ensure ``verify`` and ``timeout`` is set
        as specified on every request. ``timeout`` can be overridden per request.
        """
        if self.verify is not None:
            verify = self.verify
        if timeout is None:
            timeout = (self.connect_timeout, self.read_timeout)
        return super().send(
            request,
            stream=stream,
            timeout=timeout,
            verify=verify,
            cert=cert,
            proxies=proxies,
        )


class VaultRetry(Retry):
    """
    The Vault API responds with HTTP 429 when rate limits have been hit.
    We want to always retry 429, regardless of the HTTP verb and the presence
    of the ``Retry-After`` header, thus we need to subclass the retry configuration class.
    For HTTP error responses, we do not want to retry immediately if the header was not set.

    We override the default exponential power-of-2 algorithm for calculating
    the backoff time with a Fibonacci one because we expect a relatively
    quick turnaround.
    """

    PHI = 1.618
    SQRT5 = 2.236

    def __init__(
        self,
        *args,
        backoff_jitter=0.0,
        backoff_max=Retry.DEFAULT_BACKOFF_MAX,
        retry_after_max=DEFAULT_RETRY_AFTER_MAX,
        **kwargs,
    ):
        """
        For ``urllib3<2``, backport ``backoff_max`` and ``backoff_jitter``.
        Also, allow limiting the value returned by ``Retry-After`` by
        specifying ``retry_after_max``.
        """
        if URLLIB3V1:
            self.backoff_max = backoff_max
            self.backoff_jitter = backoff_jitter
        else:
            kwargs["backoff_max"] = backoff_max
            kwargs["backoff_jitter"] = backoff_jitter
        self.retry_after_max = retry_after_max
        super().__init__(*args, **kwargs)

    def is_retry(self, method, status_code, has_retry_after=False):
        """
        HTTP 429 is always retryable (even for POST/PATCH), otherwise fall back
        to the configuration.
        """
        if status_code == HTTP_TOO_MANY_REQUESTS:
            return True
        return super().is_retry(method, status_code, has_retry_after=has_retry_after)

    def get_backoff_time(self):
        """
        When we're retrying HTTP error responses, ensure we don't execute the
        first retry immediately.
        Also overrides the default 2**n algorithm with one based on the Fibonacci sequence.
        On ``urllib3<2``, this also backports ``backoff_jitter`` and ``backoff_max``.
        """
        # We want to consider only the last consecutive errors sequence (Ignore redirects).
        consecutive_errors = list(
            takewhile(lambda x: x.redirect_location is None, reversed(self.history))
        )
        consecutive_errors_len = len(consecutive_errors)
        if consecutive_errors_len and consecutive_errors[0].status is not None:
            # Ensure we only immediately retry for local (connection/read) errors,
            # not when we got an HTTP response.
            consecutive_errors_len += 1
        if consecutive_errors_len <= 1:
            return 0
        # Approximate the nth Fibonacci number.
        # We want to begin with the 4th one (2).
        backoff_value = round(
            self.backoff_factor
            * round(self.PHI ** (consecutive_errors_len + 1) / self.SQRT5),
            1,
        )
        if self.backoff_jitter != 0.0:
            backoff_value += random.random() * self.backoff_jitter
        return float(max(0, min(self.backoff_max, backoff_value)))

    def get_retry_after(self, response):
        """
        The default implementation sleeps for as long as requested
        by the ``Retry-After`` header. We want to limit that somewhat
        to avoid sleeping until the end of the universe.
        """
        retry_after = response.headers.get("Retry-After")

        if retry_after is None:
            return None

        res = self.parse_retry_after(retry_after)
        if self.retry_after_max is None:
            return res
        return min(res, self.retry_after_max)

    def new(self, **kw):
        """
        Since we backport some params and introduce a new one,
        ensure all requests use the defined parameters, not the default ones.
        """
        ret = super().new(**kw)
        if URLLIB3V1:
            ret.backoff_jitter = self.backoff_jitter
            ret.backoff_max = self.backoff_max
        ret.retry_after_max = self.retry_after_max
        return ret


class VaultClient:
    """
    Unauthenticated client for the Vault API.
    Base class for authenticated client.
    """

    def __init__(
        self,
        url,
        namespace=None,
        verify=None,
        session=None,
        connect_timeout=DEFAULT_CONNECT_TIMEOUT,
        read_timeout=DEFAULT_READ_TIMEOUT,
        max_retries=DEFAULT_MAX_RETRIES,
        backoff_factor=DEFAULT_BACKOFF_FACTOR,
        backoff_max=DEFAULT_BACKOFF_MAX,
        backoff_jitter=DEFAULT_BACKOFF_JITTER,
        retry_post=DEFAULT_RETRY_POST,
        respect_retry_after=DEFAULT_RESPECT_RETRY_AFTER,
        retry_status=DEFAULT_RETRY_STATUS,
        retry_after_max=DEFAULT_RETRY_AFTER_MAX,
    ):
        self.url = url
        self.namespace = namespace
        self.verify = verify

        self.connect_timeout = connect_timeout
        self.read_timeout = read_timeout

        # Cap the retry-backoff values somewhat
        self.max_retries = max(0, min(max_retries, MAX_MAX_RETRIES))
        self.backoff_factor = max(0, min(backoff_factor, MAX_BACKOFF_FACTOR))
        self.backoff_max = max(0, min(backoff_max, MAX_BACKOFF_MAX))
        self.backoff_jitter = max(0, min(backoff_jitter, MAX_BACKOFF_JITTER))
        self.retry_post = bool(retry_post)
        self.respect_retry_after = bool(respect_retry_after)
        self.retry_after_max = (
            max(0, retry_after_max) if retry_after_max is not None else None
        )
        self.retry_status = tuple(retry_status) if retry_status is not None else None

        retry = VaultRetry(
            total=self.max_retries,
            backoff_factor=self.backoff_factor,
            backoff_max=self.backoff_max,
            backoff_jitter=self.backoff_jitter,
            respect_retry_after_header=self.respect_retry_after,
            retry_after_max=self.retry_after_max,
            allowed_methods=None if retry_post else Retry.DEFAULT_ALLOWED_METHODS,
            raise_on_status=False,
            status_forcelist=self.retry_status,
        )

        if session is None:
            session = requests.Session()
            adapter = VaultAPIAdapter(
                max_retries=retry,
                verify=verify,
                connect_timeout=self.connect_timeout,
                read_timeout=self.read_timeout,
            )
            session.mount(url, adapter)
        else:
            # Sessions should only be inherited from other instances
            # of this class. A changed ``verify`` setting causes a fresh
            # client to be instantiated.
            # We want to keep the TCP connection alive, so we'll modify
            # the adapter in place.
            adapter = session.get_adapter(url)
            adapter.max_retries = retry
            adapter.connect_timeout = self.connect_timeout
            adapter.read_timeout = self.read_timeout
        self.session = session

    def delete(self, endpoint, wrap=False, raise_error=True, add_headers=None):
        """
        Wrapper for client.request("DELETE", ...)
        """
        return self.request(
            "DELETE",
            endpoint,
            wrap=wrap,
            raise_error=raise_error,
            add_headers=add_headers,
        )

    def get(self, endpoint, wrap=False, raise_error=True, add_headers=None):
        """
        Wrapper for client.request("GET", ...)
        """
        return self.request(
            "GET", endpoint, wrap=wrap, raise_error=raise_error, add_headers=add_headers
        )

    def list(self, endpoint, wrap=False, raise_error=True, add_headers=None):
        """
        Wrapper for client.request("LIST", ...)
        TODO: configuration to enable GET requests with query parameters for LIST?
        """
        return self.request(
            "LIST",
            endpoint,
            wrap=wrap,
            raise_error=raise_error,
            add_headers=add_headers,
        )

    def post(
        self, endpoint, payload=None, wrap=False, raise_error=True, add_headers=None
    ):
        """
        Wrapper for client.request("POST", ...)
        Vault considers POST and PUT to be synonymous.
        """
        return self.request(
            "POST",
            endpoint,
            payload=payload,
            wrap=wrap,
            raise_error=raise_error,
            add_headers=add_headers,
        )

    def patch(self, endpoint, payload, wrap=False, raise_error=True, add_headers=None):
        """
        Wrapper for client.request("PATCH", ...)
        """
        return self.request(
            "PATCH",
            endpoint,
            payload=payload,
            wrap=wrap,
            raise_error=raise_error,
            add_headers=add_headers,
        )

    def request(
        self,
        method,
        endpoint,
        payload=None,
        wrap=False,
        raise_error=True,
        add_headers=None,
        **kwargs,
    ):
        """
        Issue a request against the Vault API.
        Returns boolean when no data was returned, otherwise the decoded json data
        or a VaultWrappedResponse object if wrapping was requested.
        """
        res = self.request_raw(
            method,
            endpoint,
            payload=payload,
            wrap=wrap,
            add_headers=add_headers,
            **kwargs,
        )
        if res.status_code == 204:
            return True
        data = res.json()
        if not res.ok:
            if raise_error:
                self._raise_status(res)
            return data
        if wrap:
            return VaultWrappedResponse(**data["wrap_info"])
        return data

    def request_raw(
        self, method, endpoint, payload=None, wrap=False, add_headers=None, **kwargs
    ):
        """
        Issue a request against the Vault API. Returns the raw response object.
        """
        url = self._get_url(endpoint)
        headers = self._get_headers(wrap)
        try:
            headers.update(add_headers)
        except TypeError:
            pass
        res = self.session.request(
            method,
            url,
            headers=headers,
            json=payload,
            **kwargs,
        )
        return res

    def unwrap(self, wrapped, expected_creation_path=None):
        """
        Unwraps the data associated with a wrapping token.

        wrapped
            Wrapping token to unwrap

        expected_creation_path
            Regex expression or list of expressions that should fully match the
            wrapping token creation path. At least one match is required.
            Defaults to None, which skips the check.

            .. note::
                This check prevents tampering with wrapping tokens, which are
                valid for one request only. Usually, if an attacker sniffs a wrapping
                token, there will be two unwrapping requests, causing an audit warning.
                If the attacker can issue a new wrapping token and insert it into the
                response instead, this warning would be silenced. Assuming they do not
                possess the permissions to issue a wrapping token from the correct
                endpoint, checking the creation path makes this kind of attack obvious.
        """
        if expected_creation_path:
            wrap_info = self.wrap_info(wrapped)
            if not isinstance(expected_creation_path, list):
                expected_creation_path = [expected_creation_path]
            if not any(
                re.fullmatch(p, wrap_info["creation_path"])
                for p in expected_creation_path
            ):
                raise VaultUnwrapException(
                    actual=wrap_info["creation_path"],
                    expected=expected_creation_path,
                    url=self.url,
                    namespace=self.namespace,
                    verify=self.verify,
                )
        url = self._get_url("sys/wrapping/unwrap")
        headers = self._get_headers()
        payload = {}
        if "X-Vault-Token" not in headers:
            headers["X-Vault-Token"] = str(wrapped)
        else:
            payload["token"] = str(wrapped)
        res = self.session.request("POST", url, headers=headers, json=payload)
        if not res.ok:
            self._raise_status(res)
        return res.json()

    def wrap_info(self, wrapped):
        """
        Lookup wrapping token meta information.
        """
        endpoint = "sys/wrapping/lookup"
        add_headers = {"X-Vault-Token": str(wrapped)}
        return self.post(endpoint, wrap=False, add_headers=add_headers)["data"]

    def token_lookup(self, token=None, accessor=None, raw=False):
        """
        Lookup token meta information.

        token
            The token to look up or to use to look up the accessor.
            Required.

        accessor
            The accessor to use to query the token meta information.

        raw
            Return the raw response object instead of response data.
            Also disables status code checking.
        """
        endpoint = "auth/token/lookup-self"
        method = "GET"
        payload = {}
        if token is None:
            raise VaultInvocationError(
                "Unauthenticated VaultClient needs a token to lookup."
            )
        add_headers = {"X-Vault-Token": token}

        if accessor is not None:
            endpoint = "auth/token/lookup-accessor"
            payload["accessor"] = accessor

        res = self.request_raw(
            method, endpoint, payload=payload, wrap=False, add_headers=add_headers
        )
        if raw:
            return res
        self._raise_status(res)
        return res.json()["data"]

    def token_valid(self, valid_for=0, remote=True):  # pylint: disable=unused-argument
        return False

    def get_config(self):
        """
        Returns Vault server configuration used by this client.
        """
        return {
            "url": self.url,
            "namespace": self.namespace,
            "verify": self.verify,
        }

    def _get_url(self, endpoint):
        endpoint = endpoint.strip("/")
        return f"{self.url}/v1/{endpoint}"

    def _get_headers(self, wrap=False):
        headers = {"Content-Type": "application/json", "X-Vault-Request": "true"}
        if self.namespace is not None:
            headers["X-Vault-Namespace"] = self.namespace
        if wrap:
            headers["X-Vault-Wrap-TTL"] = str(wrap)
        return headers

    def _raise_status(self, res):
        errors = ", ".join(res.json().get("errors", []))
        if res.status_code == 400:
            raise VaultInvocationError(errors)
        if res.status_code == 403:
            raise VaultPermissionDeniedError(errors)
        if res.status_code == 404:
            raise VaultNotFoundError(errors)
        if res.status_code == 405:
            raise VaultUnsupportedOperationError(errors)
        if res.status_code == 412:
            raise VaultPreconditionFailedError(errors)
        if res.status_code == HTTP_TOO_MANY_REQUESTS:
            raise VaultRateLimitExceededError(errors)
        if res.status_code in (500, 502):
            raise VaultServerError(errors)
        if res.status_code == 503:
            raise VaultUnavailableError(errors)
        res.raise_for_status()


# This list is not complete at all, but contains
# the most important paths.
VAULT_UNAUTHD_PATHS = (
    "sys/wrapping/lookup",
    "sys/internal/ui/mounts",
    "sys/internal/ui/namespaces",
    "sys/seal-status",
    "sys/health",
)


class AuthenticatedVaultClient(VaultClient):
    """
    Authenticated client for the Vault API.
    This should be used for most operations.
    """

    auth = None

    def __init__(self, auth, url, **kwargs):
        self.auth = auth
        super().__init__(url, **kwargs)

    def token_valid(self, valid_for=0, remote=True):
        """
        Check whether this client's authentication information is
        still valid.

        remote
            Check with the remote Vault server as well. This consumes
            a token use. Defaults to true.
        """
        if not self.auth.is_valid(valid_for):
            return False
        if not remote:
            return True
        try:
            res = self.token_lookup(raw=True)
            if res.status_code != 200:
                return False
            return True
        except Exception as err:  # pylint: disable=broad-except
            raise salt.exceptions.CommandExecutionError(
                "Error while looking up self token."
            ) from err

    def token_lookup(self, token=None, accessor=None, raw=False):
        """
        Lookup token meta information.

        token
            The token to look up. If neither token nor accessor
            are specified, looks up the current token in use by
            this client.

        accessor
            The accessor of the token to query the meta information for.

        raw
            Return the raw response object instead of response data.
            Also disables status code checking.
        """
        endpoint = "auth/token/lookup"
        method = "POST"
        payload = {}
        if token is None and accessor is None:
            endpoint += "-self"
            method = "GET"
        if token is not None:
            payload["token"] = token
        elif accessor is not None:
            endpoint += "-accessor"
            payload["accessor"] = accessor
        if raw:
            return self.request_raw(method, endpoint, payload=payload, wrap=False)
        return self.request(method, endpoint, payload=payload, wrap=False)["data"]

    def token_renew(self, increment=None, token=None, accessor=None):
        """
        Renew a token.

        increment
            Request the token to be valid for this amount of time from the current
            point of time onwards. Can also be used to reduce the validity period.
            The server might not honor this increment.
            Can be an integer (seconds) or a time string like ``1h``. Optional.

        token
            The token that should be renewed. Optional.
            If token and accessor are unset, renews the token currently in use
            by this client.

        accessor
            The accessor of the token that should be renewed. Optional.
        """
        endpoint = "auth/token/renew"
        payload = {}

        if token is None and accessor is None:
            if not self.auth.is_renewable():
                return False
            endpoint += "-self"

        if increment is not None:
            payload["increment"] = increment
        if token is not None:
            payload["token"] = token
        elif accessor is not None:
            endpoint += "-accessor"
            payload["accessor"] = accessor

        res = self.post(endpoint, payload=payload)

        if token is None and accessor is None:
            self.auth.update_token(res["auth"])
        return res["auth"]

    def token_revoke(self, delta=1, token=None, accessor=None):
        """
        Revoke a token by setting its TTL to 1s.

        delta
            The time in seconds to request revocation after.
            Defaults to 1s.

        token
            The token that should be revoked. Optional.
            If token and accessor are unset, revokes the token currently in use
            by this client.

        accessor
            The accessor of the token that should be revoked. Optional.
        """
        try:
            self.token_renew(increment=delta, token=token, accessor=accessor)
        except (VaultPermissionDeniedError, VaultNotFoundError, VaultAuthExpired):
            # if we're trying to revoke ourselves and this happens,
            # the token was already invalid
            if token or accessor:
                raise
            return False
        return True

    def request_raw(
        self,
        method,
        endpoint,
        payload=None,
        wrap=False,
        add_headers=None,
        is_unauthd=False,
        **kwargs,
    ):  # pylint: disable=arguments-differ
        """
        Issue an authenticated request against the Vault API. Returns the raw response object.
        """
        ret = super().request_raw(
            method,
            endpoint,
            payload=payload,
            wrap=wrap,
            add_headers=add_headers,
            **kwargs,
        )
        # tokens are used regardless of status code
        if not is_unauthd and not endpoint.startswith(VAULT_UNAUTHD_PATHS):
            self.auth.used()
        return ret

    def _get_headers(self, wrap=False):
        headers = super()._get_headers(wrap)
        headers["X-Vault-Token"] = str(self.auth.get_token())
        return headers


def iso_to_timestamp(iso_time):
    """
    Most endpoints respond with RFC3339-formatted strings
    This is a hacky way to use inbuilt tools only for converting
    to a timestamp
    """
    # drop subsecond precision to make it easier on us
    # (length would need to be 3, 6 or 9)
    iso_time = re.sub(r"\.[\d]+", "", iso_time)
    iso_time = re.sub(r"Z$", "+00:00", iso_time)
    try:
        # Python >=v3.7
        return int(datetime.datetime.fromisoformat(iso_time).timestamp())
    except AttributeError:
        # Python < v3.7
        dstr, tstr = iso_time.split("T")
        year = int(dstr[:4])
        month = int(dstr[5:7])
        day = int(dstr[8:10])
        hour = int(tstr[:2])
        minute = int(tstr[3:5])
        second = int(tstr[6:8])
        tz_pos = (tstr.find("-") + 1 or tstr.find("+") + 1) - 1
        tz_hour = int(tstr[tz_pos + 1 : tz_pos + 3])
        tz_minute = int(tstr[tz_pos + 4 : tz_pos + 6])
        if all(x == 0 for x in (tz_hour, tz_minute)):
            tz = datetime.timezone.utc
        else:
            tz_sign = -1 if tstr[tz_pos] == "-" else 1
            td = datetime.timedelta(hours=tz_hour, minutes=tz_minute)
            tz = datetime.timezone(tz_sign * td)
        return int(
            datetime.datetime(year, month, day, hour, minute, second, 0, tz).timestamp()
        )


class DurationMixin:
    """
    Mixin that handles expiration with time
    """

    def __init__(
        self,
        renewable=False,
        duration=0,
        creation_time=None,
        expire_time=None,
        **kwargs,
    ):
        if "lease_duration" in kwargs:
            duration = kwargs.pop("lease_duration")
        self.renewable = renewable
        self.duration = duration
        creation_time = (
            creation_time if creation_time is not None else round(time.time())
        )
        try:
            creation_time = int(creation_time)
        except ValueError:
            creation_time = iso_to_timestamp(creation_time)
        self.creation_time = creation_time

        expire_time = (
            expire_time if expire_time is not None else round(time.time()) + duration
        )
        try:
            expire_time = int(expire_time)
        except ValueError:
            expire_time = iso_to_timestamp(expire_time)
        self.expire_time = expire_time
        super().__init__(**kwargs)

    def is_renewable(self):
        """
        Checks whether the lease is renewable
        """
        return self.renewable

    def is_valid_for(self, valid_for=0, blur=0):
        """
        Checks whether the entity is valid

        valid_for
            Check whether the entity will still be valid in the future.
            This can be an integer, which will be interpreted as seconds, or a
            time string using the same format as Vault does:
            Suffix ``s`` for seconds, ``m`` for minutes, ``h`` for hours, ``d`` for days.
            Defaults to 0.

        blur
            Allow undercutting ``valid_for`` for this amount of seconds.
            Defaults to 0.
        """
        if not self.duration:
            return True
        delta = self.expire_time - time.time() - timestring_map(valid_for)
        if delta >= 0:
            return True
        return abs(delta) <= blur

    @property
    def ttl_left(self):
        return max(self.expire_time - round(time.time()), 0)


class UseCountMixin:
    """
    Mixin that handles expiration with number of uses
    """

    def __init__(self, num_uses=0, use_count=0, **kwargs):
        self.num_uses = num_uses
        self.use_count = use_count
        super().__init__(**kwargs)

    def used(self):
        """
        Increment the use counter by one.
        """
        self.use_count += 1

    def has_uses_left(self, uses=1):
        """
        Check whether this entity has uses left.
        """
        return self.num_uses == 0 or self.num_uses - (self.use_count + uses) >= 0


class DropInitKwargsMixin:
    """
    Mixin that breaks the chain of passing unhandled kwargs up the MRO.
    """

    def __init__(self, *args, **kwargs):  # pylint: disable=unused-argument
        super().__init__(*args)


class AccessorMixin:
    """
    Mixin that manages accessor information relevant for tokens/secret IDs
    """

    def __init__(self, accessor=None, wrapping_accessor=None, **kwargs):
        # ensure the accessor always points to the actual entity
        if "wrapped_accessor" in kwargs:
            wrapping_accessor = accessor
            accessor = kwargs.pop("wrapped_accessor")
        self.accessor = accessor
        self.wrapping_accessor = wrapping_accessor
        super().__init__(**kwargs)

    def accessor_payload(self):
        if self.accessor is not None:
            return {"accessor": self.accessor}
        raise VaultInvocationError("No accessor information available")


class BaseLease(DurationMixin, DropInitKwargsMixin):
    """
    Base class for leases that expire with time.
    """

    def __init__(self, lease_id, **kwargs):
        self.id = self.lease_id = lease_id
        super().__init__(**kwargs)

    def __str__(self):
        return self.id

    def __repr__(self):
        return repr(self.to_dict())

    def __eq__(self, other):
        try:
            data = other.__dict__
        except AttributeError:
            data = other
        return data == self.__dict__

    def with_renewed(self, **kwargs):
        """
        Partially update the contained data after lease renewal
        """
        attrs = copy.copy(self.__dict__)
        # ensure expire_time is reset properly
        attrs.pop("expire_time")
        attrs.update(kwargs)
        return type(self)(**attrs)

    def to_dict(self):
        """
        Return a dict of all contained attributes
        """
        return copy.deepcopy(self.__dict__)


class VaultLease(BaseLease):
    """
    Data object representing a Vault lease.
    """

    def __init__(
        self,
        lease_id,
        data,
        min_ttl=None,
        renew_increment=None,
        revoke_delay=None,
        meta=None,
        **kwargs,
    ):
        # save lease-associated data
        self.data = data
        # save metadata used by the engine and beacon modules
        self.min_ttl = min_ttl
        self.renew_increment = renew_increment
        self.revoke_delay = revoke_delay
        self.meta = meta
        super().__init__(lease_id, **kwargs)

    def is_valid_for(self, valid_for=None, blur=0):
        """
        Checks whether the lease is valid

        valid_for
            Check whether the entity will still be valid in the future.
            This can be an integer, which will be interpreted as seconds, or a
            time string using the same format as Vault does:
            Suffix ``s`` for seconds, ``m`` for minutes, ``h`` for hours, ``d`` for days.
            Defaults to what was set on the lease when creating it or 0.

        blur
            Allow undercutting ``valid_for`` for this amount of seconds.
            Defaults to 0.
        """
        return super().is_valid_for(
            valid_for=valid_for if valid_for is not None else (self.min_ttl or 0),
            blur=blur,
        )


class VaultToken(UseCountMixin, AccessorMixin, BaseLease):
    """
    Data object representing an authentication token
    """

    def __init__(self, **kwargs):
        if "client_token" in kwargs:
            # Ensure response data from Vault is accepted as well
            kwargs["lease_id"] = kwargs.pop("client_token")
        super().__init__(**kwargs)

    def is_valid(self, valid_for=0, uses=1):
        """
        Checks whether the token is valid for an amount of time and number of uses

        valid_for
            Check whether the token will still be valid in the future.
            This can be an integer, which will be interpreted as seconds, or a
            time string using the same format as Vault does:
            Suffix ``s`` for seconds, ``m`` for minutes, ``h`` for hours, ``d`` for days.
            Defaults to 0.

        uses
            Check whether the token has at least this number of uses left. Defaults to 1.
        """
        return self.is_valid_for(valid_for) and self.has_uses_left(uses)

    def is_renewable(self):
        """
        Check whether the token is renewable, which requires it
        to be currently valid for at least two uses and renewable
        """
        # Renewing a token deducts a use, hence it does not make sense to
        # renew a token on the last use
        return self.renewable and self.is_valid(uses=2)

    def payload(self):
        """
        Return the payload to use for POST requests using this token
        """
        return {"token": str(self)}

    def serialize_for_minion(self):
        """
        Serialize all necessary data to recreate this object
        into a dict that can be sent to a minion.
        """
        return {
            "client_token": self.id,
            "renewable": self.renewable,
            "lease_duration": self.duration,
            "num_uses": self.num_uses,
            "creation_time": self.creation_time,
            "expire_time": self.expire_time,
        }


class VaultSecretId(UseCountMixin, AccessorMixin, BaseLease):
    """
    Data object representing an AppRole secret ID.
    """

    def __init__(self, **kwargs):
        if "secret_id" in kwargs:
            # Ensure response data from Vault is accepted as well
            kwargs["lease_id"] = kwargs.pop("secret_id")
            kwargs["lease_duration"] = kwargs.pop("secret_id_ttl")
            kwargs["num_uses"] = kwargs.pop("secret_id_num_uses", 0)
            kwargs["accessor"] = kwargs.pop("secret_id_accessor", None)
        if "expiration_time" in kwargs:
            kwargs["expire_time"] = kwargs.pop("expiration_time")
        super().__init__(**kwargs)

    def is_valid(self, valid_for=0, uses=1):
        """
        Checks whether the secret ID is valid for an amount of time and number of uses

        valid_for
            Check whether the secret ID will still be valid in the future.
            This can be an integer, which will be interpreted as seconds, or a
            time string using the same format as Vault does:
            Suffix ``s`` for seconds, ``m`` for minutes, ``h`` for hours, ``d`` for days.
            Defaults to 0.

        uses
            Check whether the secret ID has at least this number of uses left. Defaults to 1.
        """
        return self.is_valid_for(valid_for) and self.has_uses_left(uses)

    def payload(self):
        """
        Return the payload to use for POST requests using this secret ID
        """
        return {"secret_id": str(self)}

    def serialize_for_minion(self):
        """
        Serialize all necessary data to recreate this object
        into a dict that can be sent to a minion.
        """
        return {
            "secret_id": self.id,
            "secret_id_ttl": self.duration,
            "secret_id_num_uses": self.num_uses,
            "creation_time": self.creation_time,
            "expire_time": self.expire_time,
        }


class VaultWrappedResponse(AccessorMixin, BaseLease):
    """
    Data object representing a wrapped response
    """

    def __init__(
        self,
        creation_path,
        **kwargs,
    ):
        if "token" in kwargs:
            # Ensure response data from Vault is accepted as well
            kwargs["lease_id"] = kwargs.pop("token")
            kwargs["lease_duration"] = kwargs.pop("ttl")
        if "renewable" not in kwargs:
            # Not renewable might be incorrect, wrapped tokens are,
            # but we cannot know what was wrapped here.
            kwargs["renewable"] = False
        super().__init__(**kwargs)
        self.creation_path = creation_path

    def serialize_for_minion(self):
        """
        Serialize all necessary data to recreate this object
        into a dict that can be sent to a minion.
        """
        return {
            "wrap_info": {
                "token": self.id,
                "ttl": self.duration,
                "creation_time": self.creation_time,
                "creation_path": self.creation_path,
            },
        }


class CommonCache:
    """
    Base class that unifies context and other cache backends.
    """

    def __init__(
        self, context, cbank, cache_backend=None, ttl=None, flush_exception=None
    ):
        self.context = context
        self.cbank = cbank
        self.cache = cache_backend
        self.ttl = ttl
        self.flush_exception = flush_exception

    def _ckey_exists(self, ckey, flush=True):
        if self.cbank in self.context and ckey in self.context[self.cbank]:
            return True
        if self.cache is not None:
            if not self.cache.contains(self.cbank, ckey):
                return False
            if self.ttl is not None:
                updated = self.cache.updated(self.cbank, ckey)
                if int(time.time()) - updated >= self.ttl:
                    if flush:
                        log.debug(
                            f"Cached data in {self.cbank}/{ckey} outdated, flushing."
                        )
                        self.flush()
                    return False
            return True
        return False

    def _get_ckey(self, ckey, flush=True):
        if not self._ckey_exists(ckey, flush=flush):
            return None
        if self.cbank in self.context and ckey in self.context[self.cbank]:
            return self.context[self.cbank][ckey]
        if self.cache is not None:
            return (
                self.cache.fetch(self.cbank, ckey) or None
            )  # account for race conditions
        raise RuntimeError("This code path should not have been hit.")

    def _store_ckey(self, ckey, value):
        if self.cache is not None:
            self.cache.store(self.cbank, ckey, value)
        if self.cbank not in self.context:
            self.context[self.cbank] = {}
        self.context[self.cbank][ckey] = value

    def _flush(self, ckey=None):
        if not ckey and self.flush_exception is not None:
            # Flushing caches in Vault often requires an orchestrated effort
            # to ensure leases/sessions are terminated instead of left open.
            raise self.flush_exception()
        if self.cache is not None:
            self.cache.flush(self.cbank, ckey)
        if self.cbank in self.context:
            if ckey is None:
                self.context.pop(self.cbank)
            else:
                self.context[self.cbank].pop(ckey, None)
        # also remove sub-banks from context to mimic cache behavior
        if ckey is None:
            for bank in list(self.context):
                if bank.startswith(self.cbank):
                    self.context.pop(bank)

    def _list(self):
        ckeys = []
        if self.cbank in self.context:
            ckeys += list(self.context[self.cbank])
        if self.cache is not None:
            ckeys += self.cache.list(self.cbank)
        return set(ckeys)


class VaultCache(CommonCache):
    """
    Encapsulates session and other cache backends for a single domain
    like secret path metadata. Uses a single cache key.
    """

    def __init__(
        self, context, cbank, ckey, cache_backend=None, ttl=None, flush_exception=None
    ):
        super().__init__(
            context,
            cbank,
            cache_backend=cache_backend,
            ttl=ttl,
            flush_exception=flush_exception,
        )
        self.ckey = ckey

    def exists(self, flush=True):
        """
        Check whether data for this domain exists
        """
        return self._ckey_exists(self.ckey, flush=flush)

    def get(self, flush=True):
        """
        Return the cached data for this domain or None
        """
        return self._get_ckey(self.ckey, flush=flush)

    def flush(self, cbank=False):
        """
        Flush the cache for this domain
        """
        return self._flush(self.ckey if not cbank else None)

    def store(self, value):
        """
        Store data for this domain
        """
        return self._store_ckey(self.ckey, value)


class VaultConfigCache(VaultCache):
    """
    Handles caching of received configuration
    """

    def __init__(
        self,
        context,
        cbank,
        ckey,
        opts,
        cache_backend_factory=_get_cache_backend,
        init_config=None,
        flush_exception=None,
    ):  # pylint: disable=super-init-not-called
        self.context = context
        self.cbank = cbank
        self.ckey = ckey
        self.opts = opts
        self.config = None
        self.cache = None
        self.ttl = None
        self.cache_backend_factory = cache_backend_factory
        self.flush_exception = flush_exception
        if init_config is not None:
            self._load(init_config)

    def exists(self, flush=True):
        """
        Check if a configuration has been loaded and cached
        """
        if self.config is None:
            return False
        return super().exists(flush=flush)

    def get(self, flush=True):
        """
        Return the current cached configuration
        """
        if self.config is None:
            return None
        return super().get(flush=flush)

    def flush(self, cbank=True):
        """
        Flush all connection-scoped data
        """
        if self.config is None:
            log.warning(
                "Tried to flush uninitialized configuration cache. Skipping flush."
            )
            return
        # flush the whole connection-scoped cache by default
        super().flush(cbank=cbank)
        self.config = None
        self.cache = None
        self.ttl = None

    def _load(self, config):
        if self.config is not None:
            if (
                self.config["cache"]["backend"] != "session"
                and self.config["cache"]["backend"] != config["cache"]["backend"]
            ):
                self.flush()
        self.config = config
        self.cache = self.cache_backend_factory(self.config, self.opts)
        self.ttl = self.config["cache"]["config"]

    def store(self, value):
        """
        Reload cache configuration, then store the new Vault configuration,
        overwriting the existing one.
        """
        self._load(value)
        super().store(value)


class LeaseCacheMixin:
    """
    Mixin for auth and lease cache that checks validity
    and acts with hydrated objects
    """

    def __init__(self, *args, **kwargs):
        self.lease_cls = kwargs.pop("lease_cls", VaultLease)
        self.expire_events = kwargs.pop("expire_events", None)
        super().__init__(*args, **kwargs)

    def _check_validity(self, lease_data, valid_for=0):
        lease = self.lease_cls(**lease_data)
        try:
            # is_valid on auth classes accounts for duration and uses
            if lease.is_valid(valid_for):
                log.debug("Using cached lease.")
                return lease
        except AttributeError:
            if lease.is_valid_for(valid_for):
                log.debug("Using cached lease.")
                return lease
        if self.expire_events is not None:
            raise VaultLeaseExpired(lease)
        return None


class VaultLeaseCache(LeaseCacheMixin, CommonCache):
    """
    Handles caching of Vault leases. Supports multiple cache keys.
    Checks whether cached leases are still valid before returning.
    Does not enforce for per-lease ``min_ttl``.
    """

    def get(self, ckey, valid_for=0, flush=True):
        """
        Returns valid cached lease data or None.
        Flushes cache if invalid by default.
        """
        data = self._get_ckey(ckey, flush=flush)
        if data is None:
            return data
        try:
            ret = self._check_validity(data, valid_for=valid_for)
        except VaultLeaseExpired as err:
            if self.expire_events is not None:
                self.expire_events(
                    tag=f"vault/lease/{ckey}/expire",
                    data={
                        "valid_for_less": valid_for
                        if valid_for is not None
                        else err.lease.min_ttl or 0,
                        "ttl_left": err.lease.ttl_left,
                        "meta": err.lease.meta,
                    },
                )
            ret = None
        if ret is None and flush:
            log.debug("Cached lease not valid anymore. Flushing cache.")
            self._flush(ckey)
        return ret

    def store(self, ckey, value):
        """
        Store a lease in cache
        """
        try:
            value = value.to_dict()
        except AttributeError:
            pass
        return self._store_ckey(ckey, value)

    def exists(self, ckey, flush=True):
        """
        Check whether a named lease exists in cache. Does not filter invalid ones,
        so fetching a reported one might still return None.
        """
        return self._ckey_exists(ckey, flush=flush)

    def flush(self, ckey=None):
        """
        Flush the lease cache or a single lease from the lease cache
        """
        return self._flush(ckey)

    def list(self):
        """
        List all cached leases. Does not filter invalid ones,
        so fetching a reported one might still return None.
        """
        return self._list()


class VaultAuthCache(LeaseCacheMixin, CommonCache):
    """
    Implements authentication secret-specific caches. Checks whether
    the cached secrets are still valid before returning.
    """

    def __init__(
        self,
        context,
        cbank,
        ckey,
        auth_cls,
        cache_backend=None,
        ttl=None,
        flush_exception=None,
    ):
        super().__init__(
            context,
            cbank,
            lease_cls=auth_cls,
            cache_backend=cache_backend,
            ttl=ttl,
            flush_exception=flush_exception,
        )
        self.ckey = ckey
        self.flush_exception = flush_exception

    def exists(self, flush=True):
        """
        Check whether data for this domain exists
        """
        return self._ckey_exists(self.ckey, flush=flush)

    def get(self, valid_for=0, flush=True):
        """
        Returns valid cached auth data or None.
        Flushes cache if invalid by default.
        """
        data = self._get_ckey(self.ckey, flush=flush)
        if data is None:
            return data
        ret = self._check_validity(data, valid_for=valid_for)
        if ret is None and flush:
            log.debug("Cached auth data not valid anymore. Flushing cache.")
            self.flush()
        return ret

    def store(self, value):
        """
        Store an auth credential in cache. Will overwrite possibly existing one.
        """
        try:
            value = value.to_dict()
        except AttributeError:
            pass
        return self._store_ckey(self.ckey, value)

    def flush(self, cbank=None):
        """
        Flush the cached auth credentials. If this is a token cache,
        flushing it will delete the whole session-scoped cache bank.
        """
        if self.lease_cls is VaultToken:
            # flush the whole cbank (session-scope) if this is a token cache
            ckey = None
        else:
            ckey = None if cbank else self.ckey
        return self._flush(ckey)


def _get_config_cache(opts, context, cbank, ckey="config"):
    """
    Factory for VaultConfigCache to get around some
    chicken-and-egg problems
    """
    config = None
    if cbank in context and ckey in context[cbank]:
        config = context[cbank][ckey]
    else:
        cache = salt.cache.factory(opts)
        if cache.contains(cbank, ckey):
            # expiration check is done inside the class
            config = cache.fetch(cbank, ckey)
        elif opts.get("cache", "localfs") != "localfs":
            local_opts = copy.copy(opts)
            local_opts["cache"] = "localfs"
            cache = salt.cache.factory(local_opts)
            if cache.contains(cbank, ckey):
                # expiration check is done inside the class
                config = cache.fetch(cbank, ckey)

    return VaultConfigCache(
        context,
        cbank,
        ckey,
        opts,
        init_config=config,
        flush_exception=VaultConfigExpired,
    )


class VaultTokenAuth:
    """
    Container for authentication tokens
    """

    def __init__(self, cache=None, token=None):
        self.cache = cache
        if token is None and cache is not None:
            token = cache.get()
        if token is None:
            token = InvalidVaultToken()
        if isinstance(token, dict):
            token = VaultToken(**token)
        self.token = token

    def is_renewable(self):
        """
        Check whether the contained token is renewable, which requires it
        to be currently valid for at least two uses and renewable
        """
        return self.token.is_renewable()

    def is_valid(self, valid_for=0):
        """
        Check whether the contained token is valid
        """
        return self.token.is_valid(valid_for)

    def get_token(self):
        """
        Get the contained token if it is valid, otherwise
        raises VaultAuthExpired
        """
        if self.token.is_valid():
            return self.token
        raise VaultAuthExpired()

    def used(self):
        """
        Increment the use counter for the contained token
        """
        self.token.used()
        if self.token.num_uses != 0:
            self._write_cache()

    def update_token(self, auth):
        """
        Partially update the contained token (e.g. after renewal)
        """
        self.token = self.token.with_renewed(**auth)
        self._write_cache()

    def replace_token(self, token):
        """
        Completely replace the contained token with a new one
        """
        self.token = token
        self._write_cache()

    def _write_cache(self):
        if self.cache is not None:
            # Write the token indiscriminately since flushing
            # raises VaultAuthExpired.
            # This will be handled as part of the next request.
            self.cache.store(self.token)


class VaultAppRoleAuth:
    """
    Issues tokens from AppRole credentials.
    """

    def __init__(self, approle, client, mount="approle", cache=None, token_store=None):
        self.approle = approle
        self.client = client
        self.mount = mount
        self.cache = cache
        if token_store is None:
            token_store = VaultTokenAuth()
        self.token = token_store

    def is_renewable(self):
        """
        Check whether the currently used token is renewable.
        Secret IDs are not renewable anyways.
        """
        return self.token.is_renewable()

    def is_valid(self, valid_for=0):
        """
        Check whether the contained authentication data can be used
        to issue a valid token
        """
        return self.token.is_valid(valid_for) or self.approle.is_valid(valid_for)

    def get_token(self):
        """
        Return the token issued by the last login, if it is still valid, otherwise
        login with the contained AppRole, if it is valid. Otherwise,
        raises VaultAuthExpired
        """
        if self.token.is_valid():
            return self.token.get_token()
        if self.approle.is_valid():
            return self._login()
        raise VaultAuthExpired()

    def used(self):
        """
        Increment the use counter for the currently used token
        """
        self.token.used()

    def update_token(self, auth):
        """
        Partially update the contained token (e.g. after renewal)
        """
        self.token.update_token(auth)

    def _login(self):
        log.debug("Vault token expired. Recreating one by authenticating with AppRole.")
        endpoint = f"auth/{self.mount}/login"
        payload = self.approle.payload()
        res = self.client.post(endpoint, payload=payload)
        self.approle.used()
        self._replace_token(res["auth"])
        self._write_cache()
        return self.token.get_token()

    def _write_cache(self):
        if self.cache is not None and self.approle.secret_id is not None:
            if isinstance(self.approle.secret_id, LocalVaultSecretId):
                pass
            elif self.approle.secret_id.num_uses == 0:
                pass
            elif self.approle.secret_id.is_valid():
                self.cache.store(self.approle.secret_id)
            else:
                self.cache.flush()

    def _replace_token(self, auth):
        self.token.replace_token(VaultToken(**auth))


class LocalVaultSecretId(VaultSecretId):
    """
    Represents a secret ID from local configuration and should not be cached.
    """

    def is_valid(self, valid_for=0, uses=1):
        """
        Local secret IDs are always assumed to be valid until proven otherwise
        """
        return True


class VaultAppRole:
    """
    Container that represents an AppRole
    """

    def __init__(self, role_id, secret_id=None):
        self.role_id = role_id
        self.secret_id = secret_id

    def replace_secret_id(self, secret_id):
        """
        Replace the contained secret ID with a new one
        """
        self.secret_id = secret_id

    def is_valid(self, valid_for=0, uses=1):
        """
        Checks whether the contained data can be used to authenticate
        to Vault. Secret IDs might not be required by the server when
        bind_secret_id is set to false.

        valid_for
            Allows to check whether the AppRole will still be valid in the future.
            This can be an integer, which will be interpreted as seconds, or a
            time string using the same format as Vault does:
            Suffix ``s`` for seconds, ``m`` for minutes, ``h`` for hours, ``d`` for days.
            Defaults to 0.

        uses
            Check whether the AppRole has at least this number of uses left. Defaults to 1.
        """
        if self.secret_id is None:
            return True
        return self.secret_id.is_valid(valid_for=valid_for, uses=uses)

    def used(self):
        """
        Increment the secret ID use counter by one, if this AppRole uses one.
        """
        if self.secret_id is not None:
            self.secret_id.used()

    def payload(self):
        """
        Return the payload to use for POST requests using this AppRole
        """
        payload = {}
        if self.secret_id is not None:
            payload = self.secret_id.payload()
        payload["role_id"] = self.role_id
        return payload


class InvalidVaultToken(VaultToken):
    def __init__(self, *args, **kwargs):  # pylint: disable=super-init-not-called
        self.renewable = False
        self.use_count = 0
        self.num_uses = 0

    def is_valid(self, valid_for=0, uses=1):
        return False


class InvalidVaultSecretId(VaultSecretId):
    def __init__(self, *args, **kwargs):  # pylint: disable=super-init-not-called
        pass

    def is_valid(self, valid_for=0, uses=1):
        return False


class VaultKV:
    """
    Interface to Vault secret paths
    """

    def __init__(self, client, metadata_cache):
        self.client = client
        self.metadata_cache = metadata_cache

    def read(self, path, include_metadata=False):
        """
        Read secret data at path.

        include_metadata
            For kv-v2, include metadata in the return value:
            ``{"data": {} ,"metadata": {}}``.
        """
        v2_info = self.is_v2(path)
        if v2_info["v2"]:
            path = v2_info["data"]
        res = self.client.get(path)
        ret = res["data"]
        if v2_info["v2"] and not include_metadata:
            return ret["data"]
        return ret

    def read_meta(self, path):
        """
        Read secret metadata for all versions at path. This is different from
        the metadata returned by read, which pertains only to the most recent
        version. Requires Kv v2.
        """
        v2_info = self.is_v2(path)
        if not v2_info["v2"]:
            raise VaultInvocationError("The backend is not KV v2")
        return self.client.get(v2_info["metadata"])["data"]

    def write(self, path, data):
        """
        Write secret data to path.
        """
        v2_info = self.is_v2(path)
        if v2_info["v2"]:
            path = v2_info["data"]
            data = {"data": data}
        return self.client.post(path, payload=data)

    def patch(self, path, data):
        """
        Patch existing data.
        Tries to use a PATCH request, otherwise falls back to updating in memory
        and writing back the whole secret, thus might consume more than one token use.

        Since this uses JSON Merge Patch format, values set to ``null`` (``None``)
        will be dropped. For details, see
        https://datatracker.ietf.org/doc/html/draft-ietf-appsawg-json-merge-patch-07
        """

        def apply_json_merge_patch(data, patch):
            if not patch:
                return data
            if not isinstance(data, dict) or not isinstance(patch, dict):
                raise ValueError("Data and patch must be dictionaries.")

            for key, value in patch.items():
                if value is None:
                    data.pop(key, None)
                elif isinstance(value, dict):
                    data[key] = apply_json_merge_patch(data.get(key, {}), value)
                else:
                    data[key] = value
            return data

        def patch_in_memory(path, data):
            current = self.read(path)
            updated = apply_json_merge_patch(current, data)
            return self.write(path, updated)

        v2_info = self.is_v2(path)
        if not v2_info["v2"]:
            return patch_in_memory(path, data)

        path = v2_info["data"]
        payload = {"data": data}
        add_headers = {"Content-Type": "application/merge-patch+json"}
        try:
            return self.client.patch(path, payload=payload, add_headers=add_headers)
        except VaultPermissionDeniedError:
            log.warning("Failed patching secret, is the `patch` capability set?")
        except VaultUnsupportedOperationError:
            pass
        return patch_in_memory(path, data)

    def delete(self, path, versions=None, all_versions=False):
        """
        Delete secret path data. For kv-v1, this is permanent.
        For KV v2, this only soft-deletes the data.

        versions
            For KV v2, specifies versions to soft-delete. Needs to be castable
            to a list of integers.

        all_versions
            For KV v2, delete all known versions. Defaults to false.
        """
        method = "DELETE"
        payload = None
        v2_info = self.is_v2(path)
        if all_versions and v2_info["v2"]:
            versions = []
            try:
                curr = self.read_meta(path)
            except VaultNotFoundError:
                # The delete API behaves the same
                return True
            else:
                for version, meta in curr["versions"].items():
                    if not meta["destroyed"] and not meta["deletion_time"]:
                        versions.append(version)
                if not versions:
                    # No version left to delete
                    return True
        versions = self._parse_versions(versions)

        if v2_info["v2"]:
            if versions is not None:
                method = "POST"
                path = v2_info["delete_versions"]
                payload = {"versions": versions}
            else:
                # data and delete operations only differ by HTTP verb
                path = v2_info["data"]
        elif versions is not None:
            raise VaultInvocationError("Versioning support requires kv-v2.")

        return self.client.request(method, path, payload=payload)

    def destroy(self, path, versions=None, all_versions=False):
        """
        Permanently remove version data. Requires KV v2.

        versions
            Specifies versions to destroy. Needs to be castable
            to a list of integers. If unspecified, destroys the most
            recent version.

        all_versions
            Destroy all versions of the secret. Defaults to false.
        """
        v2_info = self.is_v2(path)
        if not v2_info["v2"]:
            raise VaultInvocationError("Destroy operation requires kv-v2.")
        if all_versions or not versions:
            versions = []
            try:
                curr = self.read_meta(path)["versions"]
            except VaultNotFoundError:
                # The destroy API behaves the same
                return True
            else:
                if all_versions:
                    for version, meta in curr.items():
                        if not meta["destroyed"]:
                            versions.append(version)
                else:
                    most_recent = str(max(int(x) for x in curr))
                    if not curr[most_recent]["destroyed"]:
                        versions = [most_recent]
                if not versions:
                    # No version left to destroy
                    return True

        versions = self._parse_versions(versions)
        path = v2_info["destroy"]
        payload = {"versions": versions}
        return self.client.post(path, payload=payload)

    def _parse_versions(self, versions):
        if versions is None:
            return versions
        if not isinstance(versions, list):
            versions = [versions]
        try:
            versions = [int(x) for x in versions]
        except ValueError as err:
            raise VaultInvocationError(
                "Versions have to be specified as integers."
            ) from err
        return versions

    def wipe(self, path):
        """
        Delete path metadata and version data, including all version history.
        Requires KV v2.
        """
        v2_info = self.is_v2(path)
        if not v2_info["v2"]:
            raise VaultInvocationError("Wipe operation requires KV v2.")
        path = v2_info["metadata"]
        return self.client.delete(path)

    def list(self, path):
        """
        List keys at path.
        """
        v2_info = self.is_v2(path)
        if v2_info["v2"]:
            path = v2_info["metadata"]

        return self.client.list(path)["data"]["keys"]

    def is_v2(self, path):
        """
        Determines if a given secret path is kv version 1 or 2.
        """
        ret = {
            "v2": False,
            "data": path,
            "metadata": path,
            "delete": path,
            "type": None,
        }
        path_metadata = self._get_secret_path_metadata(path)
        if not path_metadata:
            # metadata lookup failed. Simply return not v2
            return ret
        ret["type"] = path_metadata.get("type", "kv")
        if (
            ret["type"] == "kv"
            and path_metadata["options"] is not None
            and path_metadata.get("options", {}).get("version", "1") == "2"
        ):
            ret["v2"] = True
            ret["data"] = self._v2_the_path(path, path_metadata.get("path", path))
            ret["metadata"] = self._v2_the_path(
                path, path_metadata.get("path", path), "metadata"
            )
            ret["delete"] = ret["data"]
            ret["delete_versions"] = self._v2_the_path(
                path, path_metadata.get("path", path), "delete"
            )
            ret["destroy"] = self._v2_the_path(
                path, path_metadata.get("path", path), "destroy"
            )
        return ret

    def _v2_the_path(self, path, pfilter, ptype="data"):
        """
        Given a path, a filter, and a path type, properly inject
        'data' or 'metadata' into the path.
        """
        possible_types = ("data", "metadata", "delete", "destroy")
        if ptype not in possible_types:
            raise AssertionError()
        msg = f"Path {path} already contains {ptype} in the right place - saltstack duct tape?"

        path = path.rstrip("/").lstrip("/")
        pfilter = pfilter.rstrip("/").lstrip("/")

        together = pfilter + "/" + ptype

        otype = possible_types[0] if possible_types[0] != ptype else possible_types[1]
        other = pfilter + "/" + otype
        if path.startswith(other):
            path = path.replace(other, together, 1)
            msg = f'Path is a "{otype}" type but "{ptype}" type requested - Flipping: {path}'
        elif not path.startswith(together):
            old_path = path
            path = path.replace(pfilter, together, 1)
            msg = f"Converting path to v2 {old_path} => {path}"
        log.debug(msg)
        return path

    def _get_secret_path_metadata(self, path):
        """
        Given a path, query vault to determine mount point, type, and version.
        """
        cache_content = self.metadata_cache.get() or {}

        ret = None
        if path.startswith(tuple(cache_content.keys())):
            log.debug("Found cached metadata for %s", path)
            ret = next(v for k, v in cache_content.items() if path.startswith(k))
        else:
            log.debug("Fetching metadata for %s", path)
            try:
                endpoint = f"sys/internal/ui/mounts/{path}"
                res = self.client.get(endpoint)
                if "data" in res:
                    log.debug("Got metadata for %s", path)
                    cache_content[path] = ret = res["data"]
                    self.metadata_cache.store(cache_content)
                else:
                    raise VaultException("Unexpected response to metadata query.")
            except Exception as err:  # pylint: disable=broad-except
                log.error(
                    "Failed to get secret metadata %s: %s", type(err).__name__, err
                )
        return ret


class LeaseStore:
    """
    Caches leases and handles lease operations
    """

    def __init__(self, client, cache, expire_events=None):
        self.client = client
        self.cache = cache
        self.expire_events = expire_events
        # to update cached leases after renewal/revocation, we need a mapping id => ckey
        self.lease_id_ckey_cache = {}

    def get(
        self,
        ckey,
        valid_for=None,
        renew=True,
        renew_increment=None,
        renew_blur=2,
        revoke=None,
        check_server=False,
    ):
        """
        Return cached lease or None.

        ckey
            Cache key the lease has been saved in.

        valid_for
            Ensure the returned lease is valid for at least this amount of time.
            This can be an integer, which will be interpreted as seconds, or a
            time string using the same format as Vault does:
            Suffix ``s`` for seconds, ``m`` for minutes, ``h`` for hours, ``d`` for days.
            Defaults to the minimum TTL that was set on the lease when creating it or 0.

            .. note::

                This does not take into account token validity, which active leases
                are bound to as well.

        renew
            If the lease is still valid, but not valid for ``valid_for``, attempt to
            renew it. Defaults to true.

        renew_increment
            When renewing, request the lease to be valid for this amount of time from
            the current point of time onwards.
            If unset, will renew the lease by its default validity period and, if
            the renewed lease does not pass ``valid_for``, will try to renew it
            by ``valid_for``.

        renew_blur
            When checking validity after renewal, allow this amount of seconds in leeway
            to account for latency. Especially important when renew_increment is unset
            and the default validity period is less than ``valid_for``.
            Defaults to 2.

        revoke
            If the lease is not valid for ``valid_for`` and renewals
            are disabled or impossible, attempt to have Vault revoke the lease
            after this amount of time and flush the cache. Defaults to the
            revocation delay that was set on the lease when creating it or 60s.

        check_server
            Check on the Vault server whether the lease is still active and was not
            revoked early. Defaults to false.
        """
        if renew_increment is not None and timestring_map(valid_for) > timestring_map(
            renew_increment
        ):
            raise VaultInvocationError(
                "When renew_increment is set, it must be at least valid_for to make sense"
            )

        def check_revoke(lease, min_valid, validity_override=None):
            if self.expire_events is not None:
                event_data = {
                    "valid_for_less": round(min_valid),
                    "ttl": validity_override
                    if validity_override is not None
                    else lease.ttl_left,
                    "meta": lease.meta,
                }
                self.expire_events(tag=f"vault/lease/{ckey}/expire", data=event_data)
            if revoke is None or revoke:
                self.revoke(lease, delta=revoke)
            return None

        # Since we can renew leases, do not check for future validity in cache
        lease = self.cache.get(ckey, flush=bool(revoke))
        if lease is None:
            return lease
        self.lease_id_ckey_cache[str(lease)] = ckey
        # Leases can have an associated min_ttl, which should be taken into
        # account here. It is not done on the lease class to not break internal
        # expectations.
        effective_min_validity = max(
            timestring_map(valid_for) or 0, timestring_map(lease.min_ttl) or 0
        )
        if renew_increment is not None and effective_min_validity > timestring_map(
            renew_increment
        ):
            log.warning(
                f"renew_increment is set to '{renew_increment}', which is lower than "
                f"the minimum TTL of '{lease.min_ttl}' on lease '{ckey}'. "
                f"Dropping requested renew_increment for lease '{ckey}'."
            )
            renew_increment = None
        if lease.is_valid_for(effective_min_validity):
            if check_server:
                try:
                    # TODO: Save the updated info?
                    self.lookup(lease)
                except VaultNotFoundError:
                    return check_revoke(lease, effective_min_validity, 0)
            return lease

        if not renew:
            return check_revoke(lease, effective_min_validity)
        try:
            lease = self.renew(lease, increment=renew_increment, raise_all_errors=False)
        except VaultNotFoundError:
            # The cached lease was already revoked
            return check_revoke(lease, effective_min_validity, 0)
        if not lease.is_valid_for(effective_min_validity, blur=renew_blur):
            if renew_increment is not None:
                # valid_for cannot possibly be respected
                return check_revoke(lease, effective_min_validity)
            # Maybe valid_for is greater than the default validity period, so check if
            # the lease can be renewed by valid_for
            try:
                lease = self.renew(
                    lease, increment=effective_min_validity, raise_all_errors=False
                )
            except VaultNotFoundError:
                # The cached lease was already revoked
                return check_revoke(lease, effective_min_validity, 0)
            if not lease.is_valid_for(effective_min_validity, blur=renew_blur):
                return check_revoke(lease, effective_min_validity)
        return lease

    def list(self):
        """
        List all known cache keys of cached leases.
        """
        return self.cache.list()

    def _list_cached_leases(self, match="*", flush=False):
        """
        Helper for functions that operate on the cached leases.
        """
        leases = []
        for ckey in self.list():
            if not fnmatch.fnmatch(ckey, match):
                continue
            lease = self.cache.get(ckey, flush=flush)
            if lease is None:
                continue
            self.lease_id_ckey_cache[str(lease)] = ckey
            leases.append((ckey, lease))
        return leases

    def list_info(self, match="*"):
        """
        List cached leases.

        match
            Only list cached leases whose ckey matches this glob pattern.
            Defaults to ``*``.
        """
        ret = {}
        for ckey, lease in self._list_cached_leases(match=match, flush=False):
            info = lease.to_dict()
            # do not leak auth data
            info.pop("data", None)
            ret[ckey] = info
        return ret

    def lookup(self, lease):
        """
        Lookup lease meta information.

        lease
            A lease ID or VaultLease object to look up.
        """
        endpoint = "sys/leases/lookup"
        payload = {"lease_id": str(lease)}
        try:
            return self.client.post(endpoint, payload=payload)
        except VaultInvocationError as err:
            if "invalid lease" not in str(err):
                raise
            raise VaultNotFoundError(str(err)) from err

    def renew(self, lease, increment=None, raise_all_errors=True, _store=True):
        """
        Renew a lease.

        lease
            A lease ID or VaultLease object to renew.

        increment
            Request the lease to be valid for this amount of time from the current
            point of time onwards. Can also be used to reduce the validity period.
            The server might not honor this increment.
            Can be an integer (seconds) or a time string like ``1h``. Optional.

        raise_all_errors
            When ``lease`` is a VaultLease and the renewal does not succeed,
            do not catch exceptions. If this is false, the lease will be returned
            unmodified if the exception does not indicate it is invalid (NotFound).
            Defaults to true.
        """
        endpoint = "sys/leases/renew"
        payload = {"lease_id": str(lease)}
        if not isinstance(lease, VaultLease) and lease in self.lease_id_ckey_cache:
            lease = self.cache.get(self.lease_id_ckey_cache[lease], flush=False)
            if lease is None:
                raise VaultNotFoundError("Lease is already expired")
        if increment is not None:
            payload["increment"] = int(timestring_map(increment))
        if isinstance(lease, VaultLease) and lease.renew_increment is not None:
            payload["increment"] = max(
                int(timestring_map(lease.renew_increment)), payload.get("increment", 0)
            )
        try:
            ret = self.client.post(endpoint, payload=payload)
        except VaultException as err:
            if raise_all_errors or not isinstance(lease, VaultLease):
                raise
            if isinstance(err, VaultInvocationError):
                if "lease not found" not in str(err):
                    raise
                raise VaultNotFoundError(str(err)) from err
            return lease

        if _store and isinstance(lease, VaultLease):
            # Do not overwrite data of renewed leases!
            ret.pop("data", None)
            new_lease = lease.with_renewed(**ret)
            if str(new_lease) in self.lease_id_ckey_cache:
                self.store(self.lease_id_ckey_cache[str(new_lease)], new_lease)
            return new_lease
        return ret

    def renew_cached(self, match="*", increment=None):
        """
        Renew cached leases.

        match
            Only renew cached leases whose ckey matches this glob pattern.
            Defaults to ``*``.

        increment
            Request the leases to be valid for this amount of time from the current
            point of time onwards. Can also be used to reduce the validity period.
            The server might not honor this increment.
            Can be an integer (seconds) or a time string like ``1h``. Optional.
            If unset, defaults to the renewal increment that was set when creating
            the lease.
        """
        failed = []
        for ckey, lease in self._list_cached_leases(match=match, flush=True):
            try:
                self.renew(lease, increment=increment)
            except (VaultPermissionDeniedError, VaultNotFoundError) as err:
                log.warning(f"Failed renewing cached lease: {type(err).__name__}")
                log.debug(f"Lease ID was: {lease}")
                failed.append(ckey)
        if failed:
            raise VaultException(f"Failed renewing some leases: {list(failed)}")
        return True

    def revoke(self, lease, delta=None):
        """
        Revoke a lease. Will also remove the cached lease,
        if it has been requested from this LeaseStore before.

        lease
            A lease ID or VaultLease object to revoke.

        delta
            Time after which the lease should be requested
            to be revoked by Vault.
            Defaults to the revocation delay that was set when creating
            the lease or 60s.
        """
        if delta is None:
            if isinstance(lease, VaultLease) and lease.revoke_delay is not None:
                delta = lease.revoke_delay
            else:
                delta = 60
        try:
            # 0 would attempt a complete renewal
            self.renew(lease, increment=delta or 1, _store=False)
        except VaultInvocationError as err:
            if "lease not found" not in str(err):
                raise

        if str(lease) in self.lease_id_ckey_cache:
            self.cache.flush(self.lease_id_ckey_cache.pop(str(lease)))
        return True

    def revoke_cached(
        self,
        match="*",
        delta=None,
        flush_on_failure=True,
    ):
        """
        Revoke cached leases.

        match
            Only revoke cached leases whose ckey matches this glob pattern.
            Defaults to ``*``.

        delta
            Time after which the leases should be revoked by Vault.
            Defaults to the revocation delay that was set when creating
            the lease(s) or 60s.

        flush_on_failure
            If a revocation fails, remove the lease from cache anyways.
            Defaults to true.
        """
        failed = []
        for ckey, lease in self._list_cached_leases(match=match, flush=True):
            try:
                self.revoke(lease, delta=delta)
            except VaultPermissionDeniedError:
                failed.append(ckey)
                if flush_on_failure:
                    # Forget the lease and let Vault's automatic revocation handle it
                    self.cache.flush(self.lease_id_ckey_cache.pop(str(lease)))
        if failed:
            raise VaultException(f"Failed revoking some leases: {list(failed)}")
        return True

    def store(self, ckey, lease):
        """
        Cache a lease.

        ckey
            The cache key the lease should be saved in.

        lease
            A lease ID or VaultLease object to store.
        """
        self.cache.store(ckey, lease)
        self.lease_id_ckey_cache[str(lease)] = ckey
        return True


class AppRoleApi:
    def __init__(self, client):
        self.client = client

    def list_approles(self, mount="approle"):
        endpoint = f"auth/{mount}/role"
        return self.client.list(endpoint)["data"]["keys"]

    def read_approle(self, name, mount="approle"):
        endpoint = f"auth/{mount}/role/{name}"
        return self.client.get(endpoint)["data"]

    def write_approle(
        self,
        name,
        bind_secret_id=None,
        secret_id_bound_cidrs=None,
        secret_id_num_uses=None,
        secret_id_ttl=None,
        local_secret_ids=None,
        token_ttl=None,
        token_max_ttl=None,
        token_policies=None,
        token_bound_cidrs=None,
        token_explicit_max_ttl=None,
        token_no_default_policy=None,
        token_num_uses=None,
        token_period=None,
        token_type=None,
        mount="approle",
    ):
        endpoint = f"auth/{mount}/role/{name}"
        payload = self._filter_none(
            {
                "bind_secret_id": bind_secret_id,
                "secret_id_bound_cidrs": secret_id_bound_cidrs,
                "secret_id_num_uses": secret_id_num_uses,
                "secret_id_ttl": secret_id_ttl,
                "local_secret_ids": local_secret_ids,
                "token_ttl": token_ttl,
                "token_max_ttl": token_max_ttl,
                "token_policies": token_policies,
                "token_bound_cidrs": token_bound_cidrs,
                "token_explicit_max_ttl": token_explicit_max_ttl,
                "token_no_default_policy": token_no_default_policy,
                "token_num_uses": token_num_uses,
                "token_period": token_period,
                "token_type": token_type,
            }
        )
        return self.client.post(endpoint, payload=payload)

    def delete_approle(self, name, mount="approle"):
        endpoint = f"auth/{mount}/role/{name}"
        return self.client.delete(endpoint)

    def read_role_id(self, name, wrap=False, mount="approle"):
        endpoint = f"auth/{mount}/role/{name}/role-id"
        role_id = self.client.get(endpoint, wrap=wrap)
        if wrap:
            return role_id
        return role_id["data"]["role_id"]

    def generate_secret_id(
        self,
        name,
        metadata=None,
        cidr_list=None,
        token_bound_cidrs=None,
        num_uses=None,
        ttl=None,
        wrap=False,
        mount="approle",
        meta_info=False,
    ):
        endpoint = f"auth/{mount}/role/{name}/secret-id"
        if metadata is not None:
            metadata = salt.utils.json.dumps(metadata)
        payload = self._filter_none(
            {
                "metadata": metadata,
                "cidr_list": cidr_list,
                "token_bound_cidrs": token_bound_cidrs,
                "num_uses": num_uses,
                "ttl": ttl,
            }
        )
        response = self.client.post(endpoint, payload=payload, wrap=wrap)
        if wrap:
            secret_id = response
        else:
            secret_id = VaultSecretId(**response["data"])
        if not meta_info:
            return secret_id
        # Sadly, secret_id_num_uses is not part of the information returned
        meta_info = self.client.post(
            endpoint + "-accessor/lookup",
            payload={"secret_id_accessor": secret_id.accessor},
        )["data"]
        return secret_id, meta_info

    def read_secret_id(self, name, secret_id=None, accessor=None, mount="approle"):
        if not secret_id and not accessor:
            raise VaultInvocationError(
                "Need either secret_id or accessor to read secret ID."
            )
        if secret_id:
            endpoint = f"auth/{mount}/role/{name}/secret-id/lookup"
            payload = {"secret_id": str(secret_id)}
        else:
            endpoint = f"auth/{mount}/role/{name}/secret-id-accessor/lookup"
            payload = {"secret_id_accessor": accessor}
        ret = self.client.post(endpoint, payload=payload)
        if isinstance(ret, dict):
            return ret["data"]
        raise VaultNotFoundError()

    def destroy_secret_id(self, name, secret_id=None, accessor=None, mount="approle"):
        if not secret_id and not accessor:
            raise VaultInvocationError(
                "Need either secret_id or accessor to destroy secret ID."
            )
        if secret_id:
            endpoint = f"auth/{mount}/role/{name}/secret-id/destroy"
            payload = {"secret_id": str(secret_id)}
        else:
            endpoint = f"auth/{mount}/role/{name}/secret-id-accessor/destroy"
            payload = {"secret_id_accessor": accessor}
        return self.client.post(endpoint, payload=payload)

    def _filter_none(self, data):
        return {k: v for k, v in data.items() if v is not None}


class IdentityApi:
    def __init__(self, client):
        self.client = client

    def list_entities(self):
        endpoint = "identity/entity/name"
        return self.client.list(endpoint)["data"]["keys"]

    def read_entity(self, name):
        endpoint = f"identity/entity/name/{name}"
        return self.client.get(endpoint)["data"]

    def read_entity_by_alias(self, alias, mount):
        endpoint = "identity/lookup/entity"
        payload = {
            "alias_name": alias,
            "alias_mount_accessor": self._lookup_mount_accessor(mount),
        }
        entity = self.client.post(endpoint, payload=payload)
        if isinstance(entity, dict):
            return entity["data"]
        raise VaultNotFoundError()

    def write_entity(self, name, metadata=None):
        endpoint = f"identity/entity/name/{name}"
        payload = {
            "metadata": metadata,
        }
        return self.client.post(endpoint, payload=payload)

    def delete_entity(self, name):
        endpoint = f"identity/entity/name/{name}"
        return self.client.delete(endpoint)

    def write_entity_alias(self, name, alias_name, mount, custom_metadata=None):
        entity = self.read_entity(name)
        mount_accessor = self._lookup_mount_accessor(mount)
        payload = {
            "canonical_id": entity["id"],
            "mount_accessor": mount_accessor,
            "name": alias_name,
        }
        if custom_metadata is not None:
            payload["custom_metadata"] = custom_metadata

        for alias in entity["aliases"]:
            # Ensure an existing alias is updated
            if alias["mount_accessor"] == mount_accessor:
                payload["id"] = alias["id"]
                break
        return self.client.post("identity/entity-alias", payload=payload)

    def _lookup_mount_accessor(self, mount):
        endpoint = f"sys/auth/{mount}"
        return self.client.get(endpoint)["data"]["accessor"]


####################################################################################
# The following functions were available in previous versions and are deprecated
# TODO: remove deprecated functions after v3008 (Argon)
####################################################################################


def get_vault_connection():
    """
    Get the connection details for calling Vault, from local configuration if
    it exists, or from the master otherwise
    """
    salt.utils.versions.warn_until(
        "Argon",
        "salt.utils.vault.get_vault_connection is deprecated, "
        "please use salt.utils.vault.get_authd_client.",
    )

    opts = globals().get("__opts__", {})
    context = globals().get("__context__", {})

    try:
        vault = get_authd_client(opts, context)
    except salt.exceptions.InvalidConfigError as err:
        # This exception class was raised previously
        raise salt.exceptions.CommandExecutionError(err) from err

    token = vault.auth.get_token()
    server_config = vault.get_config()

    ret = {
        "url": server_config["url"],
        "namespace": server_config["namespace"],
        "token": str(token),
        "verify": server_config["verify"],
        "issued": token.creation_time,
    }

    if _get_salt_run_type(opts) in (
        SALT_RUNTYPE_MASTER_IMPERSONATING,
        SALT_RUNTYPE_MASTER_PEER_RUN,
        SALT_RUNTYPE_MINION_REMOTE,
    ):
        ret["lease_duration"] = token.explicit_max_ttl
        ret["uses"] = token.num_uses
    else:
        ret["ttl"] = token.explicit_max_ttl

    return ret


def del_cache():
    """
    Delete cache file
    """
    salt.utils.versions.warn_until(
        "Argon",
        "salt.utils.vault.del_cache is deprecated, please use salt.utils.vault.clear_cache.",
    )
    clear_cache(
        globals().get("__opts__", {}),
        globals().get("__context__", {}),
        connection=False,
    )


def write_cache(connection):  # pylint: disable=unused-argument
    """
    Write the vault token to cache
    """
    salt.utils.versions.warn_until(
        "Argon",
        "salt.utils.vault.write_cache is deprecated without replacement.",
    )
    # always return false since cache is managed internally
    return False


def get_cache():
    """
    Return connection information from vault cache file
    """
    salt.utils.versions.warn_until(
        "Argon",
        "salt.utils.vault.get_cache is deprecated, please use salt.utils.vault.get_authd_client.",
    )
    return get_vault_connection()


def make_request(
    method,
    resource,
    token=None,
    vault_url=None,
    namespace=None,
    get_token_url=False,
    retry=False,
    **args,
):
    """
    Make a request to Vault
    """
    salt.utils.versions.warn_until(
        "Argon",
        "salt.utils.vault.make_request is deprecated, please use "
        "salt.utils.vault.query or salt.utils.vault.query_raw."
        "To override token/url/namespace, please make use of the "
        "provided classes directly.",
    )

    def _get_client(token, vault_url, namespace, args):
        vault = get_authd_client(opts, context)
        if token is not None:
            vault.session = None
            vault.auth.cache = None
            vault.auth.token = VaultToken(
                client_token=token, renewable=False, lease_duration=60, num_uses=1
            )
        if vault_url is not None:
            vault.session = None
            vault.url = vault_url
        if namespace is not None:
            vault.namespace = namespace
        if "verify" in args:
            vault.verify = args.pop("verify")

        return vault

    opts = globals().get("__opts__", {})
    context = globals().get("__context__", {})
    endpoint = resource.lstrip("/").lstrip("v1/")
    payload = args.pop("json", None)

    if "data" in args:
        payload = salt.utils.json.loads(args.pop("data"))

    vault = _get_client(token, vault_url, namespace, args)
    res = vault.request_raw(method, endpoint, payload=payload, wrap=False, **args)
    if res.status_code == 403 and not retry:
        # retry was used to indicate to only try once more
        clear_cache(opts, context)
        vault = _get_client(token, vault_url, namespace, args)
        res = vault.request_raw(method, endpoint, payload=payload, wrap=False, **args)

    if get_token_url:
        return res, str(vault.auth.token), vault.get_config()["url"]
    return res
