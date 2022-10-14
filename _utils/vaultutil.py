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
import logging
import re
import string
import time

import requests
import salt.cache
import salt.crypt
import salt.exceptions
import salt.utils.data
import salt.utils.dictupdate
import salt.utils.json
import salt.utils.versions

log = logging.getLogger(__name__)
logging.getLogger("requests").setLevel(logging.WARNING)


# Make __salt__ available globally to avoid loading minion_mods multiple times
__salt__ = {}


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
    vault = get_authd_client(opts, context)
    try:
        return vault.request(
            method,
            endpoint,
            payload=payload,
            wrap=wrap,
            raise_error=raise_error,
            is_unauthd=is_unauthd,
            **kwargs,
        )
    except VaultPermissionDeniedError:
        # in case cached authentication data was revoked
        clear_cache(opts, context)
        vault = get_authd_client(opts, context)
        return vault.request(
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
    vault = get_authd_client(opts, context)
    res = vault.request_raw(
        method, endpoint, payload=payload, wrap=wrap, is_unauthd=is_unauthd, **kwargs
    )

    if not retry:
        return res

    if 403 == res.status_code:
        # in case cached authentication data was revoked
        clear_cache(opts, context)
        vault = get_authd_client(opts, context)
        res = vault.request_raw(
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
    # TODO: consider if at least context is really necessary to require
    if opts is None or context is None:
        opts = globals().get("__opts__", {}) if opts is None else opts
        context = globals().get("__context__", {}) if context is None else context
        salt.utils.versions.warn_until(
            "Argon",
            "The __utils__ loader functionality will be removed. This will "
            "cause context/opts dunders to be unavailable in utility modules. "
            "Please pass opts and context from importing Salt modules explicitly.",
        )
    kv = _get_kv(opts, context)
    return kv.is_v2(path)


def read_kv(path, opts, context, include_metadata=False):
    """
    Read secret at <path>.
    """
    kv = _get_kv(opts, context)
    try:
        return kv.read(path, include_metadata=include_metadata)
    except VaultPermissionDeniedError:
        # in case cached authentication data was revoked
        clear_cache(opts, context)
        kv = _get_kv(opts, context)
        return kv.read(path, include_metadata=include_metadata)


def write_kv(path, data, opts, context):
    """
    Write secret <data> to <path>.
    """
    kv = _get_kv(opts, context)
    try:
        return kv.write(path, data)
    except VaultPermissionDeniedError:
        clear_cache(opts, context)
        kv = _get_kv(opts, context)
        return kv.write(path, data)


def patch_kv(path, data, opts, context):
    """
    Patch secret <data> at <path>.
    """
    kv = _get_kv(opts, context)
    try:
        return kv.patch(path, data)
    except VaultPermissionDeniedError:
        clear_cache(opts, context)
        kv = _get_kv(opts, context)
        return kv.patch(path, data)


def delete_kv(path, opts, context, versions=None):
    """
    Delete secret at <path>. For KV v2, versions can be specified,
    which will be soft-deleted.
    """
    kv = _get_kv(opts, context)
    try:
        return kv.delete(path, versions=versions)
    except VaultPermissionDeniedError:
        clear_cache(opts, context)
        kv = _get_kv(opts, context)
        return kv.delete(path, versions=versions)


def destroy_kv(path, versions, opts, context):
    """
    Destroy secret <versions> at <path>. Requires KV v2.
    """
    kv = _get_kv(opts, context)
    try:
        return kv.destroy(path, versions)
    except VaultPermissionDeniedError:
        clear_cache(opts, context)
        kv = _get_kv(opts, context)
        return kv.destroy(path, versions)


def list_kv(path, opts, context):
    """
    List secrets at <path>. Returns ``{"keys": []}`` by default
    for backwards-compatibility reasons, unless <keys_only> is True.
    """
    kv = _get_kv(opts, context)
    try:
        return kv.list(path)
    except VaultPermissionDeniedError:
        clear_cache(opts, context)
        kv = _get_kv(opts, context)
        return kv.list(path)


def _get_kv(opts, context):
    client, config = get_authd_client(opts, context, get_config=True)
    ttl = None
    connection = True
    if config["cache"]["kv_metadata"] != "connection":
        ttl = config["cache"]["kv_metadata"]
        connection = False
    cbank = _get_cache_bank(opts, connection=connection)
    ckey = "secret_path_metadata"
    metadata_cache = VaultCache(config, opts, context, cbank, ckey, ttl=ttl)
    return VaultKV(client, metadata_cache)


def clear_cache(opts, context, ckey=None, connection=True):
    """
    Clears connection cache.
    """
    cbank = _get_cache_bank(opts, connection=connection)
    if cbank in context:
        if ckey is None:
            context.pop(cbank)
        elif ckey in context[cbank]:
            context[cbank].pop(ckey)
    cache = salt.cache.factory(opts)
    if cache.contains(cbank, ckey):
        return cache.flush(cbank, ckey)
    local_opts = copy.copy(opts)
    opts["cache"] = "localfs"
    cache = salt.cache.factory(local_opts)
    return cache.flush(cbank, ckey)


def _get_cache_backend(config, opts):
    if "session" == config["cache"]["backend"]:
        return None
    if config["cache"]["backend"] in ["localfs", "disk", "file"]:
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

    for (_, field_name, _, _) in f.parse(pattern):
        if field_name is None:
            continue
        (value, _) = f.get_field(field_name, None, mappings)
        if isinstance(value, list):
            token = f"{{{field_name}}}"
            expanded = [pattern.replace(token, str(elem)) for elem in value]
            for expanded_item in expanded:
                result = expand_pattern_lists(expanded_item, **mappings)
                expanded_patterns += result
            return expanded_patterns
    return [pattern]


SALT_RUNTYPE_MASTER = 0
SALT_RUNTYPE_MASTER_IMPERSONATING = 1
SALT_RUNTYPE_MINION_LOCAL = 2
SALT_RUNTYPE_MINION_REMOTE = 3


def _get_salt_run_type(opts):
    if "vault" in opts and opts.get("__role", "minion") == "master":
        if "grains" in opts and "id" in opts["grains"]:
            return SALT_RUNTYPE_MASTER_IMPERSONATING
        return SALT_RUNTYPE_MASTER
    if any(
        (
            opts.get("local", None),
            opts.get("file_client", None) == "local",
            opts.get("master_type", None) == "disable",
        )
    ):
        return SALT_RUNTYPE_MINION_LOCAL
    return SALT_RUNTYPE_MINION_REMOTE


def _get_cache_bank(opts, force_local=False, connection=True):
    minion_id = None
    # force_local is necessary because pillar compilation would otherwise
    # leak tokens between master and minions
    if (
        not force_local
        and _get_salt_run_type(opts) == SALT_RUNTYPE_MASTER_IMPERSONATING
    ):
        minion_id = opts["grains"]["id"]
    prefix = "vault" if minion_id is None else f"minions/{minion_id}/vault"
    if connection:
        return prefix + "/connection"
    return prefix


def get_authd_client(opts, context, force_local=False, get_config=False):
    """
    Returns an AuthenticatedVaultClient that is valid for at least one query.
    """
    retry = False
    try:
        client, config = _build_authd_client(opts, context, force_local=force_local)
    except (VaultAuthExpired, VaultConfigExpired, VaultPermissionDeniedError):
        retry = True

    # do not check the vault server for token validity because that consumes a use
    if retry or not client.token_valid(remote=False):
        clear_cache(opts, context)
        client, config = _build_authd_client(opts, context, force_local=force_local)
        if not client.token_valid(remote=False):
            raise VaultException(
                "Could not build valid client. This is most likely a bug."
            )

    if get_config:
        return client, config
    return client


def _build_authd_client(opts, context, force_local=False):
    cbank = _get_cache_bank(opts, force_local=force_local)
    config, embedded_token = _get_connection_config(
        cbank, opts, context, force_local=force_local
    )
    token_cache = VaultAuthCache(config, opts, context, cbank, "token", VaultToken)

    client = None

    if config["auth"]["method"] == "approle":
        secret_id = config["auth"]["secret_id"] or None
        cached_token = token_cache.get(10)
        secret_id_cache = None
        if secret_id:
            secret_id_cache = VaultAuthCache(
                config, opts, context, cbank, "secret_id", VaultAppRoleSecretId
            )
            secret_id = secret_id_cache.get()
            # only fetch secret-id if there is no cached valid token
            if cached_token is None and secret_id is None:
                secret_id = _fetch_secret_id(
                    config, opts, secret_id_cache, force_local=force_local
                )
            if secret_id is None:
                secret_id = InvalidVaultAppRoleSecretId()
        role_id = config["auth"]["role_id"]
        # this happens with wrapped response merging
        if isinstance(role_id, dict):
            role_id = role_id["role_id"]
        approle = VaultAppRole(role_id, secret_id)
        token_auth = VaultTokenAuth(cache=token_cache)
        unauthd_client = VaultClient(**config["server"])
        auth = VaultAppRoleAuth(
            approle,
            unauthd_client,
            mount=config["auth"]["approle_mount"],
            cache=secret_id_cache,
            token_store=token_auth,
        )
        client = AuthenticatedVaultClient(auth, **config["server"])
    elif config["auth"]["method"] in ["token", "wrapped_token"]:
        token = _fetch_token(
            config,
            opts,
            token_cache,
            force_local=force_local,
            embedded_token=embedded_token,
        )
        auth = VaultTokenAuth(token=token, cache=token_cache)
        client = AuthenticatedVaultClient(auth, **config["server"])

    if client is not None:
        return client, config
    raise salt.exceptions.SaltException("Connection configuration is invalid.")


def _get_connection_config(cbank, opts, context, force_local=False):
    if (
        _get_salt_run_type(opts) in [SALT_RUNTYPE_MASTER, SALT_RUNTYPE_MINION_LOCAL]
        or force_local
    ):
        # only cache config fetched from remote
        return _use_local_config(opts)

    log.debug("Using Vault server connection configuration from remote.")
    config_cache = _get_config_cache(opts, context, cbank, "config")

    # In case cached data is available, this takes care of resetting
    # all connection-scoped data if the config is outdated.
    config = config_cache.get()
    if config is not None:
        log.debug("Using cached Vault server connection configuration.")
        return config, None

    log.debug("Using new Vault server connection configuration.")
    try:
        issue_params = parse_config(opts.get("vault", {}), validate=False)[
            "issue_params"
        ]
        config = _query_master(
            "get_config",
            opts,
            issue_params=issue_params or None,
        )
    except VaultConfigExpired as err:
        # Make sure to still work with old peer_run configuration
        if "Peer runner return was empty" not in err.message:
            raise err
        log.warning(
            "Got empty response to Vault config request. Falling back to vault.generate_token. "
            "Please update your master peer_run configuration."
        )
        config = _query_master(
            "generate_token",
            opts,
            ttl=issue_params.get("ttl"),
            uses=issue_params.get("uses"),
            upgrade_request=True,
        )
    config = parse_config(config, opts=opts)
    # do not couple token cache with configuration cache
    embedded_token = config["auth"].pop("token", None)
    config = {
        "auth": config["auth"],
        "cache": config["cache"],
        "server": config["server"],
    }
    config_cache.store(config)
    return config, embedded_token


def _use_local_config(opts):
    log.debug("Using Vault connection details from local config.")
    config = parse_config(opts.get("vault", {}))
    embedded_token = config["auth"].pop("token", None)
    return {
        "auth": config["auth"],
        "cache": config["cache"],
        "server": config["server"],
    }, embedded_token


def _fetch_secret_id(config, opts, secret_id_cache, force_local=False):
    def cache_or_fetch(config, opts, secret_id_cache):
        secret_id = secret_id_cache.get()
        if secret_id is not None:
            return secret_id

        log.debug("Fetching new Vault AppRole secret-id.")
        secret_id = _query_master(
            "generate_secret_id",
            opts,
            expected_server=config["server"],
            unwrap_expected_creation_path=_get_expected_creation_path(
                "secret_id", config
            ),
            issue_params=parse_config(opts.get("vault", {}), validate=False)[
                "issue_params"
            ]
            or None,
        )
        secret_id = VaultAppRoleSecretId(**secret_id["data"])
        # do not cache single-use secret-ids
        if secret_id.secret_id_num_uses != 1:
            secret_id_cache.store(secret_id)
        return secret_id

    if (
        _get_salt_run_type(opts) in [SALT_RUNTYPE_MASTER, SALT_RUNTYPE_MINION_LOCAL]
        or force_local
    ):
        secret_id = config["auth"]["secret_id"]
        if isinstance(secret_id, dict):
            if secret_id.get("wrap_info"):
                unauthd_client = VaultClient(**config["server"])
                secret_id = unauthd_client.unwrap(
                    secret_id["wrap_info"]["token"],
                    expected_creation_path=_get_expected_creation_path(
                        "secret_id", config
                    ),
                )
                secret_id = secret_id["data"]
            return LocalVaultAppRoleSecretId(**secret_id)
        if secret_id:
            # assume locally configured secret_ids do not expire
            return LocalVaultAppRoleSecretId(
                config["auth"]["secret_id"],
                secret_id_ttl=config["cache"]["config"],
                secret_id_num_uses=None,
            )
        # when secret_id is falsey, the approle does not require secret ids,
        # hence a call to this function is superfluous
        raise salt.exceptions.SaltException("This code path should not be hit at all.")

    log.debug("Using secret_id issued by master.")
    return cache_or_fetch(config, opts, secret_id_cache)


def _fetch_token(config, opts, token_cache, force_local=False, embedded_token=None):
    def cache_or_fetch(config, opts, token_cache, embedded_token):
        token = token_cache.get(10)
        if token is not None:
            log.debug("Using cached token.")
            return token

        if isinstance(embedded_token, dict):
            token = VaultToken(**embedded_token)

        if not isinstance(token, VaultToken) or not token.is_valid(10):
            log.debug("Fetching new Vault token.")
            token = _query_master(
                "generate_new_token",
                opts,
                expected_server=config["server"],
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

    runtype = _get_salt_run_type(opts)

    if runtype in [SALT_RUNTYPE_MASTER, SALT_RUNTYPE_MINION_LOCAL] or force_local:
        if isinstance(embedded_token, dict):
            if embedded_token.get("wrap_info"):
                unauthd_client = VaultClient(**config["server"])
                embedded_token = unauthd_client.unwrap(
                    embedded_token["wrap_info"]["token"],
                    expected_creation_path=_get_expected_creation_path("token", config),
                )["auth"]
            token = VaultToken(**embedded_token)
        elif config["auth"]["method"] == "wrapped_token":
            unauthd_client = VaultClient(**config["server"])
            embedded_token = unauthd_client.unwrap(
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
                client = VaultClient(**config["server"])
                token_info = client.token_lookup(embedded_token, raw=True)
                if token_info.status_code != 200:
                    raise VaultException(
                        "Configured token cannot be verified. It is most likely expired or invalid."
                    )
                token_meta = token_info.json()["data"]
                token = VaultToken(
                    embedded_token, lease_duration=token_meta["ttl"], **token_meta
                )
                token_cache.store(token)
        if token is not None:
            return token
        raise VaultException("Invalid configuration, missing token.")

    log.debug("Using token generated by master.")
    return cache_or_fetch(config, opts, token_cache, embedded_token)


def _query_master(
    func,
    opts,
    expected_server=None,
    unwrap_client=None,
    unwrap_expected_creation_path=None,
    **kwargs,
):
    def check_result(
        result,
        expected_server=None,
        unwrap_client=None,
        unwrap_expected_creation_path=None,
    ):
        if not result:
            nonlocal func
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

        if result.get("expire_cache", False):
            log.info("Master requested Vault config expiration.")
            config_expired = True

        if "server" in result:
            # make sure locally overridden verify parameter does not
            # always invalidate cache
            nonlocal opts
            reported_server = parse_config(result["server"], validate=False, opts=opts)[
                "server"
            ]
            result.update({"server": reported_server})

        if expected_server is not None and result.get("server") != expected_server:
            log.info(
                "Mismatch of cached and reported server data detected. Invalidating cache."
            )
            # make sure to fetch wrapped data anyways for security reasons
            config_expired = True
            unwrap_expected_creation_path = None

        # this is used to augment some vault responses with data fetched by the master
        # e.g. secret_id_num_uses
        misc_data = result.get("misc_data", {})

        if result.get("wrap_info") or result.get("wrap_info_nested"):
            if unwrap_client is not None and unwrap_client.get_config() != result.get(
                "server"
            ):
                unwrap_client = None
                # make sure to fetch wrapped data anyways for security reasons
                config_expired = True

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
                unwrapped_response = unwrap_client.unwrap(
                    wrapped_response,
                    expected_creation_path=unwrap_expected_creation_path,
                )
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
                salt.utils.data.traverse_dict_and_list(
                    result, f"{tgt}:{key}", "__unset__"
                )
                == "__unset__"
            ):
                salt.utils.dictupdate.set_dict_key_value(
                    result,
                    f"{tgt}:{key}",
                    val,
                )

        result.pop("wrap_info", None)
        result.pop("wrap_info_nested", None)
        result.pop("misc_data", None)
        return result

    global __salt__  # pylint: disable=global-statement
    if not __salt__:
        __salt__ = salt.loader.minion_mods(opts)

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

        result = __salt__["publish.runner"](
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
        result = __salt__["saltutil.runner"](
            f"vault.{func}",
            minion_id=minion_id,
            signature=signature,
            impersonated_by_master=True,
            **kwargs,
        )
    return check_result(
        result,
        expected_server=expected_server,
        unwrap_client=unwrap_client,
        unwrap_expected_creation_path=unwrap_expected_creation_path,
    )


def parse_config(config, validate=True, opts=None):
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
        },
        "cache": {
            "backend": "session",
            "config": 3600,
            "kv_metadata": "connection",
            "secret": "ttl",
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
                    "ttl": 60,
                    "uses": 10,
                },
            },
            "token": {
                "role_name": None,
                "params": {
                    "ttl": None,
                    "uses": 1,
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
    try:
        # Policy generation has params, the new config groups them together.
        if isinstance(config.get("policies", {}), list):
            config["policies"] = {"assign": config["policies"]}
        merged = salt.utils.dictupdate.merge(
            default_config,
            config,
            strategy="smart",
            merge_lists=False,
        )
        # ttl, uses were used as configuration for issuance and minion overrides as well
        # as token meta information. The new configuration splits those semantics.
        for old_token_conf in ["ttl", "uses"]:
            if old_token_conf in merged["auth"]:
                merged["issue"]["token"]["params"][old_token_conf] = merged[
                    "issue_params"
                ][old_token_conf] = merged["auth"][old_token_conf]
        # Those were found in the root namespace, but grouping them together
        # makes semantic and practical sense.
        for old_server_conf in ["namespace", "url", "verify"]:
            if old_server_conf in merged:
                merged["server"][old_server_conf] = merged[old_server_conf]
        if "role_name" in merged:
            merged["issue"]["token"]["role_name"] = merged["role_name"]
        if "token_backend" in merged["auth"]:
            merged["cache"]["backend"] = merged["auth"]["token_backend"]
        if "allow_minion_override" in merged["auth"]:
            merged["issue"]["allow_minion_override_params"] = merged["auth"][
                "allow_minion_override"
            ]
        if opts is not None and "vault" in opts:
            local_config = opts["vault"]
            # make sure to respect locally configured verify parameter
            if local_config.get("verify", "__unset__") != "__unset__":
                merged["server"]["verify"] = local_config["verify"]
            elif (
                local_config.get("server", {}).get("verify", "__unset__") != "__unset__"
            ):
                merged["server"]["verify"] = local_config["server"]["verify"]

        if not validate:
            return merged

        if merged["auth"]["method"] == "approle":
            if "role_id" not in merged["auth"]:
                raise AssertionError("auth:role_id is required for approle auth")
        elif merged["auth"]["method"] == "token":
            if "token" not in merged["auth"]:
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
    if "token" == secret_type:
        return r"auth/token/create(/[^/]+)?"

    if "secret_id" == secret_type:
        if config is not None:
            return r"auth/{}/role/{}/secret\-id".format(
                re.escape(config["auth"]["approle_mount"]),
                re.escape(config["auth"]["approle_name"]),
            )
        return r"auth/[^/]+/role/[^/]+/secret\-id"

    if "role_id" == secret_type:
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


class VaultAuthExpired(VaultException):
    """
    Raised when authentication data is reported to be outdated locally.
    """


class VaultConfigExpired(VaultException):
    """
    Raised when secret authentication data queried from the master reports
    a different server configuration than locally cached.
    """


class VaultUnwrapException(VaultException):
    """
    Raised when an expected creation path for a wrapping token differs
    from the reported one.
    This has to be taken seriously as it indicates tampering.
    """


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


class VaultClient:
    """
    Unauthenticated client for the Vault API.
    Base class for authenticated client.
    """

    def __init__(self, url, namespace=None, verify=None):
        self.url = url
        self.namespace = namespace
        self.verify = verify

    def delete(self, endpoint, wrap=False, raise_error=True, add_headers=None):
        """
        Wrapper for client.request("POST", ...)
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
        Issue a request against the Vault API. Returns boolean when no data was returned,
        otherwise the decoded json data.
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
        if isinstance(add_headers, dict):
            headers.update(add_headers)
        res = requests.request(
            method, url, headers=headers, json=payload, verify=self.verify, **kwargs
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
                    "Wrapped response was not created from expected Vault path: "
                    f"`{wrap_info['creation_path']}` is not matched by any of `{expected_creation_path}`.\n"
                    "This indicates tampering with the wrapping token by a third party "
                    "and should be taken very seriously! If you changed some authentication-"
                    "specific configuration on the master recently, especially minion "
                    "approle mount, you should consider if this error was caused by outdated "
                    "cached data on this minion instead."
                )
        url = self._get_url("sys/wrapping/unwrap")
        headers = self._get_headers()
        payload = {}
        if "X-Vault-Token" not in headers:
            headers["X-Vault-Token"] = str(wrapped)
        else:
            payload["token"] = str(wrapped)
        res = requests.request("POST", url, headers=headers, json=payload)
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

    def token_valid(self, remote=True):  # pylint: disable=unused-argument
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
        if res.status_code in [500, 502]:
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

    def __init__(self, auth, url, **kwargs):
        self.auth = auth
        super().__init__(url, **kwargs)

    def token_valid(self, remote=True):
        """
        Check whether this client's authentication information is
        still valid.

        remote
            Check with the remote Vault server as well. This consumes
            a token use. Defaults to true.
        """
        if not self.auth.is_valid():
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
            The time the token should be requested to be renewed for, starting
            from the current point in time. The server might not honor this increment.
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


class VaultCache:
    """
    Encapsulates session and other cache backends for a single domain
    like secret path metadata.
    """

    def __init__(self, config, opts, context, cbank, ckey, ttl=None, cache=None):
        self.config = config
        self.opts = opts
        self.context = context
        self.cbank = cbank
        self.ckey = ckey
        self.ttl = ttl
        self.cache = cache if cache is not None else _get_cache_backend(config, opts)

    def exists(self):
        """
        Check whether data for this domain exists
        """
        if self.cbank in self.context and self.ckey in self.context[self.cbank]:
            return True
        if self.cache is not None:
            if not self.cache.contains(self.cbank, self.ckey):
                return False
            if self.ttl is not None:
                updated = self.cache.updated(self.cbank, self.ckey)
                if int(time.time()) - updated >= self.ttl:
                    log.debug("Cached data outdated, flushing.")
                    self.flush()
                    return False
            return True
        return False

    def get(self):
        """
        Return the cached data for this domain or None
        """
        if not self.exists():
            return None
        if self.cbank in self.context and self.ckey in self.context[self.cbank]:
            return self.context[self.cbank][self.ckey]
        if self.cache is not None:
            return self.cache.fetch(self.cbank, self.ckey)
        raise RuntimeError("This code path should not have been hit.")

    def flush(self):
        """
        Flush the cache for this domain
        """
        if self.cache is not None:
            self.cache.flush(self.cbank, self.ckey)
        if self.cbank in self.context:
            self.context[self.cbank].pop(self.ckey, None)

    def store(self, value):
        """
        Store data for this domain
        """
        if self.cache is not None:
            self.cache.store(self.cbank, self.ckey, value)
        if self.cbank not in self.context:
            self.context[self.cbank] = {}
        self.context[self.cbank][self.ckey] = value


def _get_config_cache(opts, context, cbank, ckey):
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

    return VaultConfigCache(opts, context, cbank, ckey, init_config=config)


class VaultConfigCache(VaultCache):
    def __init__(
        self, opts, context, cbank, ckey, init_config=None
    ):  # pylint: disable=super-init-not-called
        self.opts = opts
        self.context = context
        self.cbank = cbank
        self.ckey = ckey
        self.config = None
        self.cache = None
        self.ttl = None
        if init_config is not None:
            self._load(init_config)

    def exists(self):
        if self.config is None:
            return False
        return super().exists()

    def get(self):
        if self.config is None:
            return None
        return super().get()

    def flush(self):
        """
        Flush all connection-scoped data
        """
        if self.config is None:
            log.warning(
                "Tried to flush uninitialized configuration cache. Skipping flush."
            )
            return
        # flush the whole connection-scoped cache
        if self.cache is not None:
            self.cache.flush(self.cbank)
        if self.cbank in self.context:
            self.context.pop(self.cbank, None)
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
        self.cache = _get_cache_backend(self.config, self.opts)
        self.ttl = self.config["cache"]["config"]

    def store(self, value):
        self._load(value)
        super().store(value)


class VaultAuthCache(VaultCache):
    """
    Implements authentication secret-specific caches. Checks whether
    the cached secrets are still valid before returning.
    """

    def __init__(self, config, opts, context, cbank, ckey, auth_cls, ttl=None):
        if ttl is None:
            if config["cache"]["secret"] != "ttl":
                ttl = config["cache"]["secret"]
        super().__init__(config, opts, context, cbank, ckey, ttl=ttl)
        self.auth_cls = auth_cls

    def get(self, seconds_future=0):  # pylint: disable=arguments-differ
        """
        Returns valid cached authentication data or None
        """
        if not self.exists():
            return None
        data = super().get()
        auth = self.auth_cls(**data)
        if auth.is_valid(seconds_future):
            log.debug("Using cached secret.")
            return auth
        log.debug("Cached secret not valid anymore.")
        self.flush()
        return None

    def store(self, value):
        """
        Store auth data
        """
        if isinstance(value, VaultLease):
            value = value.to_dict()
        return super().store(value)


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
        Check whether the contained token is renewable,
        which requires it to be valid and renewable
        """
        return self.is_valid() and self.token.renewable

    def is_valid(self, seconds_future=0):
        """
        Check whether the contained token is valid
        """
        return self.token.is_valid(seconds_future)

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
        self.token = self.token.with_(**auth)
        self._write_cache()

    def replace_token(self, token):
        """
        Completely replace the contained token with a new one
        """
        self.token = token
        self._write_cache()

    def _write_cache(self):
        if self.cache is not None:
            if self.token.is_valid():
                self.cache.store(self.token)
            else:
                self.cache.flush()


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
        Secret IDs are not renewable.
        """
        return self.token.is_renewable()

    def is_valid(self, seconds_future=0):
        """
        Check whether the contained authentication data can be used
        to issue a valid token
        """
        return self.token.is_valid(seconds_future) or self.approle.is_valid(
            seconds_future
        )

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
            if isinstance(self.approle.secret_id, LocalVaultAppRoleSecretId):
                pass
            elif self.approle.secret_id.secret_id_num_uses == 0:
                pass
            elif self.approle.is_valid():
                self.cache.store(self.approle.secret_id)
            else:
                self.cache.flush()

    def _replace_token(self, auth):
        self.token.replace_token(VaultToken(**auth))


class VaultLease:
    """
    Base class for Vault leases that expire with time.
    """

    def __init__(
        self,
        lease_id,
        renewable,
        lease_duration,
        creation_time=None,
        **kwargs,  # pylint: disable=unused-argument
    ):
        self.id = lease_id
        self.renewable = renewable
        self.lease_duration = lease_duration
        if creation_time is not None:
            try:
                creation_time = int(creation_time)
            except ValueError:
                creation_time = _fromisoformat(creation_time)
        self.creation_time = (
            creation_time if creation_time is not None else int(round(time.time()))
        )

    def is_valid(self, seconds_future=0):
        """
        Checks whether the lease is currently valid

        seconds_future
            Allows to check whether the lease will still be valid
            x seconds from now on. Defaults to 0.
        """
        if not self.lease_duration:
            return True
        return self.creation_time + self.lease_duration > time.time() + seconds_future

    def with_(self, **kwargs):
        """
        Partially update the contained data
        """
        attrs = copy.copy(self.__dict__)
        attrs.update(kwargs)
        return type(self)(**attrs)

    def __str__(self):
        return self.id

    def __repr__(self):
        return repr(self.to_dict())

    def __eq__(self, other):
        try:
            data = other.__dict__
        except AttributeError:
            data = other
        return self.__dict__ == data

    def to_dict(self):
        """
        Return a dict of all contained attributes
        """
        return self.__dict__


def _fromisoformat(creation_time):
    """
    Most endpoints respond with RFC3339-formatted strings
    This is a hacky way to use inbuilt tools only
    """
    # drop subsecond precision to make it easier on us
    # (length would need to be 3, 6 or 9)
    creation_time = re.sub(r"\.[\d]+", "", creation_time)
    creation_time = re.sub(r"Z$", "+00:00", creation_time)
    try:
        # Python >=v3.7
        return int(datetime.datetime.fromisoformat(creation_time).timestamp())
    except AttributeError:
        # Python < v3.7
        dstr, tstr = creation_time.split("T")
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
            tz_sign = -1 if "-" == tstr[tz_pos] else 1
            td = datetime.timedelta(hours=tz_hour, minutes=tz_minute)
            tz = datetime.timezone(tz_sign * td)
        return int(
            datetime.datetime(year, month, day, hour, minute, second, 0, tz).timestamp()
        )


class VaultWrappedResponse(VaultLease):
    """
    Data object representing a wrapped response
    """

    def __init__(
        self,
        token,
        ttl,
        creation_time,
        creation_path,
        accessor=None,
        wrapped_accessor=None,
        **kwargs,
    ):
        self.accessor = accessor
        self.wrapped_accessor = wrapped_accessor
        self.creation_path = creation_path
        super().__init__(
            token,
            renewable=False,
            lease_duration=ttl,
            creation_time=creation_time,
            **kwargs,
        )
        self.token = self.id
        self.ttl = self.lease_duration

    def serialize_for_minion(self):
        return {
            "wrap_info": {
                "token": self.id,
                "ttl": self.ttl,
                "creation_time": self.creation_time,
                "creation_path": self.creation_path,
            },
        }


class VaultAppRoleSecretId(VaultLease):
    """
    Data object representing an AppRole secret-id.
    """

    def __init__(
        self,
        secret_id,
        secret_id_ttl,
        secret_id_num_uses=None,
        creation_time=None,
        use_count=0,
        **kwargs,
    ):
        self.num_uses = self.secret_id_num_uses = secret_id_num_uses
        self.use_count = use_count
        super().__init__(
            secret_id,
            renewable=False,
            lease_duration=secret_id_ttl,
            creation_time=creation_time,
        )
        self.secret_id_ttl = self.lease_duration
        self.secret_id = self.id

    def payload(self):
        """
        Return the payload to use for POST requests using this secret-id
        """
        return {"secret_id": str(self)}

    def is_valid(self, seconds_future=0):
        """
        Check whether this secret-id is still valid. Takes into account
        the maximum number of uses, if they are known, and lease duration.

        seconds_future
            Allows to check whether the lease will still be valid
            x seconds from now on. Defaults to 0.
        """
        return super().is_valid(seconds_future) and (
            self.num_uses is None
            or self.num_uses == 0
            or self.num_uses - self.use_count > 0
        )

    def used(self):
        """
        Increment the use counter of this secret-id by one.
        """
        self.use_count += 1

    def serialize_for_minion(self):
        """
        Serialize all necessary data to recreate this object
        into a dict that can be sent to a minion.
        """
        data = {
            "secret_id": self.secret_id,
            "secret_id_ttl": self.secret_id_ttl,
            "creation_time": self.creation_time,
        }
        if self.secret_id_num_uses is not None:
            data["secret_id_num_uses"] = self.secret_id_num_uses
        return data


class LocalVaultAppRoleSecretId(VaultAppRoleSecretId):
    """
    Represents a secret ID from local configuration and should not be cached.
    """


class VaultToken(VaultLease):
    """
    Data object representing an authentication token
    """

    def __init__(
        self,
        client_token,
        renewable,
        lease_duration,
        num_uses,
        accessor=None,
        entity_id=None,
        creation_time=None,
        use_count=0,
        **kwargs,
    ):
        self.accessor = accessor
        self.num_uses = num_uses
        self.entity_id = entity_id
        self.use_count = use_count
        super().__init__(
            client_token,
            renewable=renewable,
            lease_duration=lease_duration,
            creation_time=creation_time,
        )
        # instantiation is currently suboptimal
        # this is needed to make new copies with updated params
        self.client_token = self.id

    def is_valid(self, seconds_future=0):
        """
        Check whether this token is still valid. Takes into account
        the maximum number of uses, and lease duration.

        seconds_future
            Allows to check whether the lease will still be valid
            x seconds from now on. Defaults to 0.
        """
        return super().is_valid(seconds_future) and (
            self.num_uses == 0 or self.num_uses - self.use_count > 0
        )

    def used(self):
        """
        Increment the use counter of this token by one.
        """
        self.use_count += 1

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
            "client_token": self.client_token,
            "renewable": self.renewable,
            "lease_duration": self.lease_duration,
            "num_uses": self.num_uses,
            "creation_time": self.creation_time,
        }


class VaultAppRole:
    """
    Container that represents an AppRole
    """

    def __init__(self, role_id, secret_id=None):
        self.role_id = role_id
        self.secret_id = secret_id

    def replace_secret_id(self, secret_id):
        """
        Replace the contained secret-id with a new one
        """
        self.secret_id = secret_id

    def is_valid(self, seconds_future=0):
        """
        Checks whether the contained data can be used to authenticate
        to Vault. secret-ids might not be required by the server when
        bind_secret_id is set to false.
        """
        if self.secret_id is None:
            return True
        return self.secret_id.is_valid(seconds_future)

    def used(self):
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

    def is_valid(self, seconds_future=0):
        return False


class InvalidVaultAppRoleSecretId(VaultAppRoleSecretId):
    def __init__(self, *args, **kwargs):  # pylint: disable=super-init-not-called
        pass

    def is_valid(self, seconds_future=0):
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
        Patch existing data. Requires kv-v2.
        This uses JSON Merge Patch format, see
        https://datatracker.ietf.org/doc/html/draft-ietf-appsawg-json-merge-patch-07
        """
        v2_info = self.is_v2(path)
        if not v2_info["v2"]:
            raise VaultInvocationError("Patch operation requires kv-v2.")
        path = v2_info["data"]
        data = {"data": data}
        add_headers = {"Content-Type": "application/merge-patch+json"}
        return self.client.patch(path, payload=data, add_headers=add_headers)

    def delete(self, path, versions=None):
        """
        Delete secret path data. For kv-v1, this is permanent.
        For kv-v2, this only soft-deletes the data.

        versions
            For kv-v2, specifies versions to soft-delete. Needs to be castable
            to a list of integers.
        """
        method = "DELETE"
        payload = None
        versions = self._parse_versions(versions)
        v2_info = self.is_v2(path)

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

    def destroy(self, path, versions):
        """
        Permanently remove version data. Requires kv-v2.

        versions
            Specifies versions to destroy. Needs to be castable
            to a list of integers.
        """
        versions = self._parse_versions(versions)
        v2_info = self.is_v2(path)
        if not v2_info["v2"]:
            raise VaultInvocationError("Destroy operation requires kv-v2.")
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

    def nuke(self, path):
        """
        Delete path metadata and version data, including all version history.
        Requires kv-v2.
        """
        v2_info = self.is_v2(path)
        if not v2_info["v2"]:
            raise VaultInvocationError("Nuke operation requires kv-v2.")
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
            and path_metadata.get("options", {}).get("version", "1") in ["2"]
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
        possible_types = ["data", "metadata", "delete", "destroy"]
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

    vault = get_authd_client(opts, context)
    token = vault.auth.get_token()

    server_config = vault.get_config()

    ret = {
        "url": server_config["url"],
        "namespace": server_config["namespace"],
        "token": str(token),
        "verify": server_config["verify"],
        "issued": token.creation_time,
    }

    if _get_salt_run_type(opts) in [
        SALT_RUNTYPE_MASTER_IMPERSONATING,
        SALT_RUNTYPE_MINION_REMOTE,
    ]:
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
        "salt.utils.vault.query or salt.utils.vault.query_raw.",
        "To override token/url/namespace, please make use of the",
        "provided classes directly.",
    )

    def _get_client(token, vault_url, namespace, args):
        vault = get_authd_client(opts, context)
        if token is not None:
            vault.auth.cache = None
            vault.auth.token = VaultToken(
                client_token=token, renewable=False, lease_duration=60, num_uses=1
            )
        if vault_url is not None:
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
    if 403 == res.status_code and not retry:
        # retry was used to indicate to only try once more
        clear_cache(opts, context)
        vault = _get_client(token, vault_url, namespace, args)
        res = vault.request_raw(method, endpoint, payload=payload, wrap=False, **args)

    if get_token_url:
        return res, str(vault.auth.token), vault.get_config()["url"]
    return res
