import fnmatch
import logging

import vaultutil as vault
from salt.exceptions import CommandExecutionError

try:
    from salt.defaults import NOT_SET
except ImportError:
    NOT_SET = "__unset__"

__func_alias__ = {"list_": "list"}

log = logging.getLogger(__name__)


def list_(mount="approle"):
    """
    List existing AppRoles.

    CLI Example:

    .. code-block:: bash

        salt '*' vault_approle.list_

    Required policy:

    .. code-block:: vaultpolicy

        path "auth/<mount>/role" {
            capabilities = ["list"]
        }

    mount
        The name of the mount point the AppRole auth backend is mounted at.
        Defaults to ``approle``.
    """
    try:
        return vault.get_approle_api(__opts__, __context__).list_approles(mount=mount)
    except vault.VaultException as err:
        raise CommandExecutionError(f"{type(err).__name__}: {err}") from err


def read(name, mount="approle"):
    """
    Read an AppRole configuration.

    CLI Example:

    .. code-block:: bash

        salt '*' vault_approle.read salt_master

    Required policy:

    .. code-block:: vaultpolicy

        path "auth/<mount>/role/<name>" {
            capabilities = ["read"]
        }

    name
        The name of the AppRole.

    mount
        The name of the mount point the AppRole auth backend is mounted at.
        Defaults to ``approle``.
    """
    try:
        return vault.get_approle_api(__opts__, __context__).read_approle(
            name, mount=mount
        )
    except vault.VaultException as err:
        raise CommandExecutionError(f"{type(err).__name__}: {err}") from err


def write(
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
    """
    Write an AppRole configuration.

    CLI Example:

    .. code-block:: bash

        salt '*' vault_approle.write salt_master

    Required policy:

    .. code-block:: vaultpolicy

        path "auth/<mount>/role/<name>" {
            capabilities = ["create", "update"]
        }

    name
        The name of the AppRole.

    secret_id_bound_cidrs
        List of CIDR blocks that specifies blocks of IP addresses which can
        perform the login operation

    secret_id_num_uses
        Number of times any particular SecretID can be used to fetch a token from
        this AppRole, after which the SecretID by default will expire. A value of
        zero will allow unlimited uses. However, this option may be overridden by
        the request's 'num_uses' field when generating a SecretID.

    secret_id_ttl
        Duration in either an integer number of seconds (3600) or an integer
        time unit (60m) after which by default any SecretID expires.
        A value of zero will allow the SecretID to not expire. However, this option
        may be overridden by the request's 'ttl' field when generating a SecretID.

    local_secret_ids
        If set, the secret IDs generated using this role will be cluster local.
        This can only be set during role creation and once set, it can't be reset later.

    token_ttl
        The incremental lifetime for generated tokens. This value will be
        referenced at renewal time.

    token_max_ttl
        The maximum lifetime for generated tokens. This value will be
        referenced at renewal time.

    token_policies
        List of token policies to encode onto generated tokens. Depending on the
        auth method, this list may be supplemented by user/group/other values.

    token_bound_cidrs
        List of CIDR blocks that specifies blocks of IP addresses which can
        authenticate successfully, and ties the resulting token to these blocks as well.

    token_explicit_max_ttl
        If set, will encode an explicit max TTL onto the token.
        This is a hard cap, even if token_ttl and token_max_ttl would otherwise
        allow a renewal.

    token_no_default_policy
        If set, the default policy will not be set on generated tokens;
        otherwise it will be added to the policies set in ``token_policies``.

    token_num_uses
        The maximum number of times a generated token may be used (within its lifetime);
        0 means unlimited. If you require the token to have the ability to create
        child tokens, you will need to set this value to 0.

    token_period
        The maximum allowed period value when a periodic token is requested from this role.

    token_type
        The type of token that should be generated. Can be ``service``, ``batch``,
        or ``default`` to use the mount's tuned default.
        For token store roles, there are two additional possibilities:
        ``default-service`` and ``default-batch``, which specify the type
        to return unless the client requests a different type at generation time.

    mount
        The name of the mount point the AppRole auth backend is mounted at.
        Defaults to ``approle``.
    """
    try:
        return vault.get_approle_api(__opts__, __context__).write_approle(
            name,
            bind_secret_id=bind_secret_id,
            secret_id_bound_cidrs=secret_id_bound_cidrs,
            secret_id_num_uses=secret_id_num_uses,
            secret_id_ttl=secret_id_ttl,
            local_secret_ids=local_secret_ids,
            token_ttl=token_ttl,
            token_max_ttl=token_max_ttl,
            token_policies=token_policies,
            token_bound_cidrs=token_bound_cidrs,
            token_explicit_max_ttl=token_explicit_max_ttl,
            token_no_default_policy=token_no_default_policy,
            token_num_uses=token_num_uses,
            token_period=token_period,
            token_type=token_type,
            mount=mount,
        )
    except vault.VaultException as err:
        raise CommandExecutionError(f"{type(err).__name__}: {err}") from err


def delete(name, mount="approle"):
    """
    Delete an AppRole.

    CLI Example:

    .. code-block:: bash

        salt '*' vault_approle.delete salt_master_bak

    Required policy:

    .. code-block:: vaultpolicy

        path "auth/<mount>/role/<name>" {
            capabilities = ["delete"]
        }

    name
        The name of the AppRole.

    mount
        The name of the mount point the AppRole auth backend is mounted at.
        Defaults to ``approle``.
    """
    try:
        return vault.get_approle_api(__opts__, __context__).delete_approle(
            name, mount=mount
        )
    except vault.VaultException as err:
        raise CommandExecutionError(f"{type(err).__name__}: {err}") from err


def get_role_id(name, mount="approle", wrap=False):
    """
    Get an AppRole's role ID.

    CLI Example:

    .. code-block:: bash

        salt '*' vault.get_role_id salt_master

    Required policy:

    .. code-block:: vaultpolicy

        path "auth/<mount>/role/<name>/role-id" {
            capabilities = ["read"]
        }

    name
        The name of the AppRole.

    mount
        The name of the mount point the AppRole auth backend is mounted at.
        Defaults to ``approle``.

    wrap
        Instead of returning the role ID, return a response
        wrapping token that is valid for this amount of time.
        Defaults to false.
    """
    try:
        ret = vault.get_approle_api(__opts__, __context__).read_role_id(
            name, mount=mount, wrap=wrap
        )
    except vault.VaultException as err:
        raise CommandExecutionError(f"{type(err).__name__}: {err}") from err
    if wrap:
        return ret.to_dict()
    return ret


def get_secret_id(
    name,
    metadata=None,
    cidr_list=None,
    token_bound_cidrs=None,
    num_uses=None,
    ttl=None,
    cache=True,
    min_ttl=10,
    wrap=False,
    min_wrap_ttl=10,
    mount="approle",
    all_data=False,
):
    """
    Generate a secret ID for an AppRole.

    CLI Example:

    .. code-block:: bash

        salt '*' vault.get_secret_id salt_master_bak

    Required policy:

    .. code-block:: vaultpolicy

        path "auth/<mount>/role/<name>/secret-id" {
            capabilities = ["create", "update"]
        }

    name
        The name of the AppRole.

    metadata
        A string-valued dictionary of metadata tied to this particular secret ID.

    cidr_list
        List of CIDR blocks enforcing secret IDs to be used from specific set of
        IP addresses.
        If ``secret_id_bound_cidrs`` is set on the role, then this list of CIDR
        blocks should be a subset of the CIDR blocks listed on the role.

    token_bound_cidrs
        A list of CIDR blocks which can use the auth tokens generated by this SecretID.
        Overrides any role-set value, but must be a subset thereof.

    num_uses
        Number of times this SecretID can be used, after which the SecretID expires.
        A value of zero will allow unlimited uses. Overrides ``secret_id_num_uses``
        role option when supplied. May not be higher than role's ``secret_id_num_uses``.

    ttl
        Duration in seconds (``3600``) or an integer time unit (``60m``) after which
        this SecretID expires.
        Overrides ``secret_id_ttl`` role option when supplied.
        May not be longer than role's ``secret_id_ttl``.

    cache
        Whether to cache issued secret IDs/wrapped responses. Defaults to true.
        Set this to a string to be able to issue distinct secret IDs for
        the same role.

    min_ttl
        When using cached data, ensure the secret ID is at least valid for this
        amount of time. Defaults to 10 (seconds).

    wrap
        Instead of returning the secret ID, return a response
        wrapping URL that is valid for this amount of time.
        Defaults to false.

    min_wrap_ttl
        When using cached data, ensure the wrapping token is at least valid for this
        amount of time. Defaults to 10 (seconds).

    mount
        The name of the mount point the AppRole auth backend is mounted at.
        Defaults to ``approle``.

    all_data
        Return a dictionary of information, including [wrapping_]accessor, duration, expire_time etc.
        If this is false, only returns the secret ID/wrapping token as a string.
        Defaults to false.
    """
    if cache:
        ckey = f"secid.{mount}.{name}." + ("default" if cache is True else cache)
        secid_store = _get_store()
        secret_id = secid_store.get(ckey, valid_for=min_ttl)
        if secret_id is None:
            pass
        elif bool(wrap) is not isinstance(secret_id, vault.VaultWrappedResponse):
            log.debug(
                "Switched between wrapped response and plain secret ID, destroying previous"
            )
            secid_store.destroy_cached(match=ckey)
        else:
            if isinstance(secret_id, vault.VaultSecretId) or (
                isinstance(secret_id, vault.VaultWrappedResponse)
                and secret_id.is_valid_for(min_wrap_ttl)
            ):
                if all_data:
                    return secret_id.to_dict()
                return str(secret_id)
            secid_store.destroy_cached(match=ckey)

    try:
        secret_id = vault.get_approle_api(__opts__, __context__).generate_secret_id(
            name,
            metadata=metadata,
            cidr_list=cidr_list,
            token_bound_cidrs=token_bound_cidrs,
            num_uses=num_uses,
            ttl=ttl,
            wrap=wrap,
            mount=mount,
        )
    except vault.VaultException as err:
        raise CommandExecutionError(f"{type(err).__name__}: {err}") from err
    if cache:
        secid_store.store(ckey, secret_id)
    if all_data:
        return secret_id.to_dict()
    return str(secret_id)


def lookup_secret_id(name, secret_id=None, accessor=None, mount="approle"):
    """
    Lookup Secret ID meta information.

    Required policy:

    .. code-block:: vaultpolicy

        path "auth/<mount>/role/<name>/secret-id/lookup" {
            capabilities = ["create", "update"]
        }

        path "auth/<mount>/role/<name>/secret-id-accessor/lookup" {
            capabilities = ["create", "update"]
        }

    secid
        A secret ID or VaultSecretId object to look up.
        Specify either this or ``accessor``.

    accessor
        A secret ID accessor for the secret ID to look up.
        Specify either this or ``secid``.
    """
    try:
        return vault.get_approle_api(__opts__, __context__).read_secret_id(
            name, secret_id=secret_id, accessor=accessor, mount=mount
        )
    except vault.VaultException as err:
        raise CommandExecutionError(f"{type(err).__name__}: {err}") from err


def destroy_secret_id(name, secret_id=None, accessor=None, mount="approle"):
    """
    Destroy a Secret ID.

    Required policy:

    .. code-block:: vaultpolicy

        path "auth/<mount>/role/<name>/secret-id/destroy" {
            capabilities = ["create", "update"]
        }

        path "auth/<mount>/role/<name>/secret-id-accessor/destroy" {
            capabilities = ["create", "update"]
        }

    secid
        A secret ID or VaultSecretId object to look up.
        Specify either this or ``accessor``.

    accessor
        A secret ID accessor for the secret ID to look up.
        Specify either this or ``secid``.
    """
    try:
        return vault.get_approle_api(__opts__, __context__).destroy_secret_id(
            name, secret_id=secret_id, accessor=accessor, mount=mount
        )
    except vault.VaultException as err:
        raise CommandExecutionError(f"{type(err).__name__}: {err}") from err


def clear_cached(name=None, cache=None, mount=None, flush_on_failure=True):
    """
    Flush cached secret IDs. Will attempt revocation.

    CLI Example:

    .. code-block:: bash

        salt '*' vault.clear_cached

    Recommended policy:

    .. code-block:: vaultpolicy

        path "auth/<mount>/role/<name>/secret-id-accessor/destroy" {
            capabilities = ["create", "update"]
        }

    name
        Only clear secret IDs for this role name.

    cache
        Only clear secret IDs with this cache name.

    mount
        Only clear secret IDs from this backend mount.

    flush_on_failure
        If a revocation fails, remove the lease from cache anyways.
        Defaults to true.
    """
    ptrn = ["secid"]
    ptrn.append("*" if mount is None else mount)
    ptrn.append("*" if name is None else name)
    ptrn.append("*" if cache is None else "default" if cache is True else cache)
    return _get_store().destroy_cached(
        match=".".join(ptrn), flush_on_failure=flush_on_failure
    )


def _get_store():
    """
    Return an instance of AuthStore.
    """
    try:
        api, config = vault.get_approle_api(__opts__, __context__, get_config=True)
    except vault.VaultException as err:
        raise CommandExecutionError(f"{type(err).__name__}: {err}") from err
    vault_cbank = vault._get_cache_bank(__opts__)
    cache = vault.VaultLeaseCache(
        __context__,
        vault_cbank + "/secid",
        cache_backend=vault._get_cache_backend(config, __opts__),
        lease_cls=_secretid_or_wrapped,
    )
    return SecretIdStore(api, cache)


def _secretid_or_wrapped(**kwargs):
    if kwargs.get("creation_path"):
        return vault.VaultWrappedResponse(**kwargs)
    return vault.VaultSecretId(**kwargs)


class SecretIdStore:
    """
    Caches secret IDs and handles revocation
    """

    def __init__(self, api, cache):
        self.api = api
        self.cache = cache

    def get(
        self,
        ckey,
        valid_for=0,
        destroy=True,
    ):
        """
        Return a valid cached secret ID/wrapped response or None.

        ckey
            Cache key the secret ID has been saved in.

        valid_for
            Ensure the returned secret ID or wrapping token is valid for at least
            this amount of time.
            This can be an integer, which will be interpreted as seconds, or a
            time string using the same format as Vault does:
            Suffix ``s`` for seconds, ``m`` for minutes, ``h`` for hours, ``d`` for days.
            Defaults to 0.

        destroy
            If the secret ID is invalid or not valid for ``valid_for``,
            attempt to destroy it if possible and flush the cache.
            Defaults to true.
        """
        # Since we need to destroy secret IDs, do not check for future validity in cache
        secid = self.cache.get(ckey, flush=destroy)
        if secid is None:
            return secid
        meta = self._lookup(secid, ckey, destroy)
        if meta is None:
            return None
        if meta.is_valid_for(valid_for):
            return secid if str(meta) == "unknown" else meta
        if destroy:
            self.destroy_cached(ckey)
        return None

    def list(self):
        """
        List all cached leases.
        """
        return self.cache.list()

    def _lookup(self, secid, ckey, flush):
        """
        Lookup secret ID meta information.

        secid
            A secret ID or VaultWrappedResponse associated with an issued
            secret ID to lookup.

        ckey
            Cache key where the object was stored (to update information, if changed)
        """
        try:
            _, mount, name, _ = ckey.split(".")
            meta = self.api.read_secret_id(name, accessor=secid.accessor, mount=mount)
        except vault.VaultNotFoundError:
            if flush:
                self.cache.flush(ckey)
            return None
        if isinstance(secid, vault.VaultWrappedResponse):
            # todo: introduce WrappedSecretId and cache that
            secid_meta = vault.VaultSecretId(secret_id="unknown", **meta)
            return secid_meta
        secid_updated = secid.with_renewed(**meta)
        if secid_updated != secid:
            self.cache.store(ckey, secid)
        return secid_updated

    def destroy(self, name, secid, mount="approle"):
        """
        Destroy a secret ID.

        secid
            A secret ID or VaultWrappedResponse associated with an issued
            secret ID to revoke.
        """
        try:
            self.api.destroy_secret_id(name, accessor=secid.accessor, mount=mount)
        except vault.VaultNotFoundError:
            pass
        return True

    def destroy_cached(
        self,
        match="*",
        flush_on_failure=True,
    ):
        """
        Revoke cached leases.

        match
            Only revoke cached leases whose ckey matches this glob pattern.
            Defaults to ``*``.

        flush_on_failure
            If a revocation fails, remove the lease from cache anyways.
            Defaults to true.
        """
        failed = []
        for ckey in self.list():
            if not fnmatch.fnmatch(ckey, match):
                continue
            secid = self.cache.get(ckey, flush=True)
            if secid is None:
                continue
            _, mount, name, _ = ckey.split(".")
            try:
                self.destroy(name, secid, mount=mount)
            except vault.VaultPermissionDeniedError:
                failed.append(ckey)
                if flush_on_failure:
                    # Forget the lease and let Vault's automatic revocation handle it
                    self.cache.flush(ckey)
        if failed:
            raise vault.VaultException(
                f"Failed deleting some secret IDs: {list(failed)}"
            )
        return True

    def store(self, ckey, secid):
        """
        Cache a secret ID.

        ckey
            The cache key the lease should be saved in.

        secid
            A secret ID or wrapped secret ID to store.
        """
        self.cache.store(ckey, secid)
        return True
