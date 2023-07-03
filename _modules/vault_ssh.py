"""
Interface with the Vault SSH secret engine.
"""

import logging
from pathlib import Path

import vaultutil as vault
import salt.utils.json
from salt.exceptions import CommandExecutionError, SaltInvocationError


__virtualname__ = "vault_ssh"
log = logging.getLogger(__name__)


def __virtual__():
    return __virtualname__


def read_role(name, mount="ssh"):
    """
    Reads an existing SSH role.

    CLI Example:

    .. code-block:: bash

        salt '*' vault_ssh.read_role sre

    Required policy:

    .. code-block:: vaultpolicy

        path "<mount>/roles/<name>" {
            capabilities = ["read"]
        }

    name
        The name of the SSH role.

    mount
        The name of the mount point the SSH secret backend is mounted at.
        Defaults to ``ssh``.
    """
    try:
        return vault.query("GET", f"{mount}/roles/{name}", __opts__, __context__)[
            "data"
        ]
    except vault.VaultException as err:
        raise CommandExecutionError(f"{type(err).__name__}: {err}") from err


def write_role(
    name,
    key_type,
    default_user="",
    default_user_template=False,
    cidr_list=None,
    exclude_cidr_list=None,
    port=None,
    allowed_users=None,
    allowed_users_template=None,
    allowed_domains=None,
    allowed_domains_template=None,
    ttl=None,
    max_ttl=None,
    allowed_critical_options=None,
    allowed_extensions=None,
    default_critical_options=None,
    default_extensions=None,
    allow_user_certificates=False,
    allow_host_certificates=False,
    allow_bare_domains=False,
    allow_subdomains=False,
    allow_user_key_ids=False,
    key_id_format=None,
    allowed_user_key_length=None,
    algorithm_signer=None,
    not_before_duration=None,
    mount="ssh",
):
    """
    Creates/updates an SSH role.

    CLI Example:

    .. code-block:: bash

        salt '*' vault_ssh.write_role sre

    Required policy:

    .. code-block:: vaultpolicy

        path "<mount>/roles/<name>" {
            capabilities = ["read"]
        }

    name
        The name of the SSH role.

    key_type
        The type of credentials generated by this role. ``otp`` or ``ca``.

    default_user
        The default username for which a credential will be generated.
        When ``default_user_template`` is true, this can contain an identity
        template with any prefix or suffix, like ``ssh-{{identity.entity.id}}-user``.
        For the CA type, if you wish this to be a valid principal, it must also
        be in ``allowed_users``.

    default_user_template
        Allow ``default_users`` to be specified using identity template values.
        A non-templated user is also permitted. Defaults to false.

    cidr_list
        List of CIDR blocks to which the role is applicable. Required, unless
        the role is registered as a zero-address role.
        Not applicable to ``ca`` key types.

    exclude_cidr_list
        List of CIDR blocks not accepted by the role.
        Not applicable to ``ca`` key types.

    port
        Specifies the port number for SSH connection, which will be returned to
        OTP clients as an informative value. Defaults to ``22``.

    allowed_users
        List of usernames the client can request under this role.
        If this is ``*`` (default for ``otp``, but **not** ``ca``), **any usernames are allowed**.
        If ``allowed_users_template`` is true, this list can contain an
        identity template with any prefix or suffix. The ``default_user``
        will always be allowed.

    allowed_users_template
        Allow ``allowed_users`` to be specified using identity template values.
        Non-templated users are also permitted. Defaults to false.

    allowed_domains
        List of domains for which a client can request a host certificate.
        ``*`` allows any domain. See also ``allow_bare_domains`` and ``allow_subdomains``.

    allowed_domains_template
        Allow ``allowed_domains_template`` to be specified using identity template values.
        Non-templated domains are also permitted. Defaults to false.

    ttl
        Specifies the Time To Live value provided as a string duration with
        time suffix. Hour is the largest suffix. If unset, uses the system
        default value or the value of ``max_ttl``, whichever is shorter

    max_ttl
        Specifies the maximum Time To Live provided as a string duration with
        time suffix. Hour is the largest suffix. If unset, defaults to the
        system maximum lease TTL.

    allowed_critical_options
        List of critical options that certificates can carry when signed.
        If unset (default), allows any option.

    allowed_extensions
        List of extensions that certificates can carry when signed.
        If unset (default), will always take the extensions
        from ``default_extensions`` only. If set to ``*``, will allow
        any extension to be set.
        For the list of extensions, take a look at the sshd manual's
        AUTHORIZED_KEYS FILE FORMAT section. You should add a ``permit-``
        before the name of extension to allow it.

    default_critical_options
        Map of critical options to their values certificates should carry
        if none are provided when signing.

    default_extensions
        Map of extensions to their values certificates should carry
        if none are provided when signing or allowed_extensions is unset.

    allow_user_certificates
        Allow certificates to be signed for ``user`` use. Defaults to false.

    allow_host_certificates
        Allow certificates to be signed for ``host`` use. Defaults to false.


    allow_bare_domains
        Allow host certificates to be signed for the base domains listed in
        ``allowed_domains``. This is a separate option as in some cases this
        can be considered a security threat. Defaults to false.

    allow_subdomains
        Allow host certificates to be signed for subdomains of the base domains
        listed in ``allowed_domains``. Defaults to false.

    allow_user_key_ids
        Allow users to override the key ID for a certificate. When false (default),
        the key ID will always be the token display name.
        The key ID is logged by the SSH server and can be useful for auditing.

    key_id_format
        Specifies a custom format for the key ID of a signed certificate.
        See `key_id_format <https://developer.hashicorp.com/vault/api-docs/secret/ssh#key_id_format>`_
        for available template values.

    allowed_user_key_length
        Map of ssh key types to allowed sizes when signing with the CA type.
        Values can be a list of multiple sizes.
        Keys can both be OpenSSH-style key identifiers and short names
        (``rsa``, ``ecdsa``, ``dsa``, or ``ed25519``). If an algorithm has
        a fixed key size, values are ignored.

    algorithm_signer
        **RSA** algorithm to sign keys with. Valid: ``ssh-rsa``, ``rsa-sha2-256``,
        ``rsa-sha2-512``, or ``default`` (which is the default). Ignored
        when not signing with an RSA key.

    not_before_duration
        Specifies the duration by which to backdate the ``ValidAfter`` property.
        Defaults to ``30s``.

    mount
        The name of the mount point the SSH secret backend is mounted at.
        Defaults to ``ssh``.
    """
    endpoint = f"{mount}/roles/{name}"
    payload = {
        "key_type": key_type,
        "default_user": default_user,
        "default_user_template": default_user_template,
        "allowed_users_template": allowed_users_template,
    }

    if ttl is not None:
        payload["ttl"] = ttl
    if max_ttl is not None:
        payload["max_ttl"] = max_ttl
    if allowed_users is not None:
        if isinstance(allowed_users, list):
            allowed_users = ",".join(allowed_users)
        payload["allowed_users"] = allowed_users

    otp_params = {
        "cidr_list": cidr_list,
        "exclude_cidr_list": exclude_cidr_list,
        "port": port,
    }

    ca_params = {
        "allowed_user_key_length": allowed_user_key_length,
        "allowed_domains": allowed_domains,
        "allowed_domains_template": allowed_domains_template,
        "allowed_critical_options": allowed_critical_options,
        "allowed_extensions": allowed_extensions,
        "default_critical_options": default_critical_options,
        "default_extensions": default_extensions,
        "allow_user_certificates": allow_user_certificates,
        "allow_host_certificates": allow_host_certificates,
        "allow_bare_domains": allow_bare_domains,
        "allow_subdomains": allow_subdomains,
        "allow_user_key_ids": allow_user_key_ids,
        "key_id_format": key_id_format,
        "not_before_duration": not_before_duration,
    }

    if key_type == "otp":
        if any(ca_params.values()):
            raise SaltInvocationError(
                f"The following parameters are invalid for `otp` key types: {', '.join(k for k, v in ca_params.items() if v)}"
            )
        type_params = otp_params
    elif key_type == "ca":
        if any(otp_params.values()):
            raise SaltInvocationError(
                f"The following parameters are invalid for `ca` key types: {', '.join(k for k, v in otp_params.items() if v)}"
            )
        if not (allow_user_certificates or allow_host_certificates):
            raise SaltInvocationError(
                "Either allow_user_certificates or allow_host_certificates must be true"
            )
        type_params = ca_params
    else:
        raise SaltInvocationError(f"Invalid key_type: {key_type}. Allowed: otp, ca")

    for param, val in type_params.items():
        if isinstance(val, dict):
            payload[param] = {
                k: salt.utils.json.dumps(v)
                if isinstance(v, dict) or isinstance(v, list)
                else v
                for k, v in val.items()
            }
        elif isinstance(val, list):
            payload[param] = val if not isinstance(val, list) else ",".join(val)
        elif val is not None:
            payload[param] = val
    try:
        return vault.query("POST", endpoint, __opts__, __context__, payload=payload)
    except vault.VaultException as err:
        raise CommandExecutionError(f"{type(err).__name__}: {err}") from err


def delete_role(name, mount="ssh"):
    """
    Deletes an existing SSH role.

    CLI Example:

    .. code-block:: bash

        salt '*' vault_ssh.delete_role sre

    Required policy:

    .. code-block:: vaultpolicy

        path "<mount>/roles/<name>" {
            capabilities = ["delete"]
        }

    name
        The name of the SSH role.

    mount
        The name of the mount point the SSH secret backend is mounted at.
        Defaults to ``ssh``.
    """
    try:
        return vault.query("DELETE", f"{mount}/roles/{name}", __opts__, __context__)
    except vault.VaultException as err:
        raise CommandExecutionError(f"{type(err).__name__}: {err}") from err


def list_roles(mount="ssh"):
    """
    Lists existing SSH roles.

    CLI Example:

    .. code-block:: bash

        salt '*' vault_ssh.list_roles

    Required policy:

    .. code-block:: vaultpolicy

        path "<mount>/roles" {
            capabilities = ["list"]
        }

    mount
        The name of the mount point the SSH secret backend is mounted at.
        Defaults to ``ssh``.
    """
    try:
        res = vault.query("LIST", f"{mount}/roles", __opts__, __context__)["data"]
    except vault.VaultNotFoundError:
        return {}
    except vault.VaultException as err:
        raise CommandExecutionError(f"{type(err).__name__}: {err}") from err

    keys = res["key_info"]
    for key in res["keys"]:
        if key not in keys:
            keys[key] = {}
    return keys


def list_roles_ip(address, mount="ssh"):
    """
    Lists existing SSH roles associated with a given IP address.

    CLI Example:

    .. code-block:: bash

        salt '*' vault_ssh.list_roles_ip 10.1.0.1

    Required policy:

    .. code-block:: vaultpolicy

        path "<mount>/lookup" {
            capabilities = ["create", "update"]
        }

    address
        The IP address to list roles for.

    mount
        The name of the mount point the SSH secret backend is mounted at.
        Defaults to ``ssh``.
    """
    endpoint = f"{mount}/config/zeroaddress"
    payload = {"ip": address}
    try:
        return vault.query("POST", endpoint, __opts__, __context__, payload=payload)[
            "data"
        ]["roles"]
    except vault.VaultInvocationError as err:
        if "Missing roles" not in str(err):
            raise
        return []
    except vault.VaultException as err:
        raise CommandExecutionError(f"{type(err).__name__}: {err}") from err


def list_roles_zeroaddr(mount="ssh"):
    """
    Return the list of configured zero-address roles. These are roles
    that are allowed to request credentials for any IP address.

    CLI Example:

    .. code-block:: bash

        salt '*' vault_ssh.list_roles_zeroaddr 10.1.0.1

    Required policy:

    .. code-block:: vaultpolicy

        path "<mount>/config/zeroaddress" {
            capabilities = ["read"]
        }

    mount
        The name of the mount point the SSH secret backend is mounted at.
        Defaults to ``ssh``.
    """
    try:
        return vault.query("GET", f"{mount}/config/zeroaddress", __opts__, __context__)[
            "data"
        ]["roles"]
    except vault.VaultNotFoundError:
        return []
    except vault.VaultException as err:
        raise CommandExecutionError(f"{type(err).__name__}: {err}") from err


def write_zeroaddr_roles(roles, mount="ssh"):
    """
    Write the list of configured zero-address roles. These are roles
    that are allowed to request credentials for any IP address.

    CLI Example:

    .. code-block:: bash

        salt '*' vault_ssh.write_roles_zeroaddr '[super, admin]'

    Required policy:

    .. code-block:: vaultpolicy

        path "<mount>/config/zeroaddress" {
            capabilities = ["create", "update"]
        }

    roles
        The list of role names that should be marked as zero address roles.

    mount
        The name of the mount point the SSH secret backend is mounted at.
        Defaults to ``ssh``.
    """
    endpoint = f"{mount}/config/zeroaddress"
    payload = {"roles": roles}
    try:
        return vault.query("POST", endpoint, __opts__, __context__, payload=payload)
    except vault.VaultException as err:
        raise CommandExecutionError(f"{type(err).__name__}: {err}") from err


def delete_zeroaddr_roles(mount="ssh"):
    """
    Delete the list of configured zero-address roles. These are roles
    that are allowed to request credentials for any IP address.

    CLI Example:

    .. code-block:: bash

        salt '*' vault_ssh.delete_roles_zeroaddr

    Required policy:

    .. code-block:: vaultpolicy

        path "<mount>/config/zeroaddress" {
            capabilities = ["delete"]
        }

    mount
        The name of the mount point the SSH secret backend is mounted at.
        Defaults to ``ssh``.
    """
    try:
        return vault.query(
            "DELETE", f"{mount}/config/zeroaddress", __opts__, __context__
        )
    except vault.VaultException as err:
        raise CommandExecutionError(f"{type(err).__name__}: {err}") from err


def get_creds(name, address, username="", mount="ssh"):
    """
    Generate credentials for a specific IP (and username) using an existing role.
    Returns a mapping with ``ip``, ``key``, ``key_type``, ``port`` and ``username``.

    CLI Example:

    .. code-block:: bash

        salt '*' vault_ssh.get_creds sre 10.1.0.1
        salt '*' vault_ssh.get_creds sre 10.1.0.1 bob

    Required policy:

    .. code-block:: vaultpolicy

        path "<mount>/creds/<role_name>" {
            capabilities = ["create", "update"]
        }

    name
        The name of the role.

    address
        The IP address of the host to generate credentials for.

    username
        The username on the remote host to generate credentials for.
        If empty, the default username of the role will be used.

    mount
        The name of the mount point the SSH secret backend is mounted at.
        Defaults to ``ssh``.
    """
    endpoint = f"{mount}/creds/{name}"
    payload = {"ip": address, "username": username}
    # TODO: cache lease!
    try:
        return vault.query("POST", endpoint, __opts__, __context__, payload=payload)[
            "data"
        ]
    except vault.VaultException as err:
        raise CommandExecutionError(f"{type(err).__name__}: {err}") from err


def create_ca(
    private_key=None,
    public_key=None,
    key_type="ssh-rsa",
    key_bits=0,
    force=False,
    mount="ssh",
):
    """
    Create a CA to be used for certificate authentication.

    CLI Example:

    .. code-block:: bash

        salt '*' vault_ssh.create_ca

    Required policy:

    .. code-block:: vaultpolicy

        path "<mount>/config/ca" {
            capabilities = ["create", "update"]
        }

    private_key
        The private key part of the SSH CA key pair. Can be a file
        local to the minion or a PEM-encoded string.
        If this or ``public_key`` is unspecified, will generate a pair
        on the Vault server.

    public_key
        The public key part of the SSH CA key pair. Can be a file
        local to the minion or a PEM-encoded string.
        If this or ``public_key`` is unspecified, will generate a pair
        on the Vault server.

    key_type
        The desired key type for the generated SSH CA key when generating
        on the Vault server. Valid: ``ssh-rsa`` (default), ``sha2-nistp256``,
        ``ecdsa-sha2-nistp384``, ``ecdsa-sha2-nistp521``, or ``ssh-ed25519``.
        Can also specify an algorithm: ``rsa``, ``ec``, or ``ed25519``.

    key_bits
        The desired key bits for the generated SSH CA key when generating
        on the Vault server. Only used for variable length keys (e.g. ``ssh-rsa``)
        or when ``ec`` was specified as ``key_type``, in which case this
        selects the NIST P-curve: ``256``, ``384``, ``521``.
        0 (default) will select 4096 bits for RSA or NIST P-256 for EC.

    mount
        The name of the mount point the SSH secret backend is mounted at.
        Defaults to ``ssh``.
    """
    endpoint = f"{mount}/config/ca"

    if private_key and public_key:
        payload = {
            "generate_signing_key": False,
            "private_key": _get_file_or_data(private_key),
            "public_key": _get_file_or_data(public_key),
        }
    else:
        payload = {
            "generate_signing_key": True,
            "key_type": key_type,
            "key_bits": key_bits,
        }

    try:
        return vault.query("POST", endpoint, __opts__, __context__, payload=payload)[
            "data"
        ]["public_key"]
    except vault.VaultException as err:
        raise CommandExecutionError(f"{type(err).__name__}: {err}") from err


def destroy_ca(mount="ssh"):
    """
    Destroy an existing CA on the mount.

    CLI Example:

    .. code-block:: bash

        salt '*' vault_ssh.destroy_ca

    Required policy:

    .. code-block:: vaultpolicy

        path "<mount>/config/ca" {
            capabilities = ["delete"]
        }

    mount
        The name of the mount point the SSH secret backend is mounted at.
        Defaults to ``ssh``.
    """
    try:
        return vault.query("DELETE", f"{mount}/config/ca", __opts__, __context__)
    except vault.VaultException as err:
        raise CommandExecutionError(f"{type(err).__name__}: {err}") from err


def read_ca(mount="ssh"):
    """
    Read the public key for an existing CA on the mount.
    This defaults to reading from the authenticated endpoint, but falls
    back to the unauthenticated one.

    CLI Example:

    .. code-block:: bash

        salt '*' vault_ssh.read_ca

    Required policy: None for the unauthenticated endpoint or

    .. code-block:: vaultpolicy

        path "<mount>/config/ca" {
            capabilities = ["read"]
        }

    mount
        The name of the mount point the SSH secret backend is mounted at.
        Defaults to ``ssh``.
    """
    try:
        return vault.query("GET", f"{mount}/config/ca", __opts__, __context__)["data"][
            "public_key"
        ]
    except vault.VaultPermissionDeniedError:
        log.info(
            "Permission denied for the authenticated endpoint, trying unauthenticated one"
        )
    except vault.VaultException as err:
        raise CommandExecutionError(f"{type(err).__name__}: {err}") from err
    try:
        res = vault.query_raw(
            "GET", f"{mount}/public_key", __opts__, __context__, is_unauthd=True
        )
    except vault.VaultException as err:
        raise CommandExecutionError(f"{type(err).__name__}: {err}") from err
    if res.status_code == 200:
        return res.text
    res.raise_for_status()


def sign_key(
    name,
    public_key,
    ttl=None,
    valid_principals=None,
    cert_type="user",
    key_id=None,
    critical_options=None,
    extensions=None,
    mount="ssh",
):
    """
    Sign an SSH public key under an existing role on the mount.
    Returns a mapping with ``serial_number`` and ``signed_key``.

    CLI Example:

    .. code-block:: bash

        salt '*' vault_ssh.sign_key sre $HOME/.ssh/id_me.pub

    Required policy:

    .. code-block:: vaultpolicy

        path "<mount>/sign/<role_name>" {
            capabilities = ["create", "update"]
        }

    name
        The name of the SSH role.

    public_key
        The SSH public key that should be signed. Can be a file local to
        the minion or a PEM-encoded string.

    ttl
        Request a specific time to live for the certificate, limited by the
        role's TTL. If unspecified, will default to the role's TTL or system
        values.

    valid_principals
        List of usernames/hostnames the certificate should be signed for.

    cert_type
        The type of certificate to issue, either ``user`` or ``host``. Defaults
        to ``user``.

    key_id
        The key ID the created certificate should have. If unspecified, the display
        name of the creating token will be used.

    critical_options
        A map of critical options the certificate should carry.

    extensions
        A map of extensions the certificate should carry.

    mount
        The name of the mount point the SSH secret backend is mounted at.
        Defaults to ``ssh``.
    """
    endpoint = f"{mount}/sign/{name}"
    payload = {"public_key": _get_file_or_data(public_key), "cert_type": cert_type}

    if ttl is not None:
        payload["ttl"] = ttl
    if key_id is not None:
        payload["key_id"] = key_id

    if valid_principals is not None:
        if isinstance(valid_principals, list):
            valid_principals = ",".join(valid_principals)
        payload["valid_principals"] = valid_principals

    for param, val in [
        ("critical_options", critical_options),
        ("extensions", extensions),
    ]:
        if val is not None:
            payload[param] = {
                k: salt.utils.json.dumps(v)
                if isinstance(v, dict) or isinstance(v, list)
                else v
                for k, v in val.items()
            }

    try:
        return vault.query("POST", endpoint, __opts__, __context__, payload=payload)[
            "data"
        ]
    except vault.VaultException as err:
        raise CommandExecutionError(f"{type(err).__name__}: {err}") from err


def generate_key_cert(
    name,
    key_type="ssh-rsa",
    key_bits=0,
    ttl=None,
    valid_principals=None,
    cert_type="user",
    key_id=None,
    critical_options=None,
    extensions=None,
    mount="ssh",
):
    """
    Generate an SSH private key and accompanying signed certificate.
    Returns a mapping with keys ``private_key``, ``private_key_type``,
    ``serial_number``, ``signed_key``.

    CLI Example:

    .. code-block:: bash

        salt '*' vault_ssh.generate_key_cert sre

    Required policy:

    .. code-block:: vaultpolicy

        path "<mount>/sign/<role_name>" {
            capabilities = ["create", "update"]
        }

    name
        The name of the SSH role.

    key_type
        The desired key type for the generated SSH CA key.
        Valid: ``ssh-rsa`` (default), ``sha2-nistp256``,
        ``ecdsa-sha2-nistp384``, ``ecdsa-sha2-nistp521``, or ``ssh-ed25519``.
        Can also specify an algorithm: ``rsa``, ``ec``, or ``ed25519``.

    key_bits
        The desired key bits for the generated SSH CA key.
        Only used for variable length keys (e.g. ``ssh-rsa``)
        or when ``ec`` was specified as ``key_type``, in which case this
        selects the NIST P-curve: ``256``, ``384``, ``521``.
        0 (default) will select 4096 bits for RSA or NIST P-256 for EC.

    ttl
        Request a specific time to live for the certificate, limited by the
        role's TTL. If unspecified, will default to the role's TTL or system
        values.

    valid_principals
        List of usernames/hostnames the certificate should be signed for.

    cert_type
        The type of certificate to issue, either ``user`` or ``host``. Defaults
        to ``user``.

    key_id
        The key ID the created certificate should have. If unspecified, the display
        name of the creating token will be used.

    critical_options
        A map of critical options the certificate should carry.

    extensions
        A map of extensions the certificate should carry.

    mount
        The name of the mount point the SSH secret backend is mounted at.
        Defaults to ``ssh``.
    """
    endpoint = f"{mount}/issue/{name}"
    payload = {"key_type": key_type, "cert_type": cert_type, "key_bits": key_bits}

    if ttl is not None:
        payload["ttl"] = ttl
    if key_id is not None:
        payload["key_id"] = key_id

    if valid_principals is not None:
        if isinstance(valid_principals, list):
            valid_principals = ",".join(valid_principals)
        payload["valid_principals"] = valid_principals

    for param, val in [
        ("critical_options", critical_options),
        ("extensions", extensions),
    ]:
        if val is not None:
            payload[param] = {
                k: salt.utils.json.dumps(v)
                if isinstance(v, dict) or isinstance(v, list)
                else v
                for k, v in val.items()
            }

    try:
        return vault.query("POST", endpoint, __opts__, __context__, payload=payload)[
            "data"
        ]
    except vault.VaultException as err:
        raise CommandExecutionError(f"{type(err).__name__}: {err}") from err


def create_certificate(
    ca_server=None,
    signing_policy=None,
    path=None,
    overwrite=False,
    raw=False,
    **kwargs,
):
    """
    Create an OpenSSH certificate and return an encoded version of it.
    This is a compatibility layer between ``ssh_pki.certificate_managed``
    and this module, hence the parameter names do not match their expected
    value sometimes.

    CLI Example:

    .. code-block:: bash

        salt '*' vault_ssh.create_certificate signing_private_key='/etc/pki/ssh/myca.key'

    ca_server
        The name of the mount point the SSH secret backend is mounted at.

    signing_policy
        The name of the SSH role to use for issuance. Required.

    cert_type
        The certificate type to generate. Either ``user`` or ``host``.
        Required if not specified in the Vault role.

    private_key
        The private key corresponding to the public key the certificate should
        be issued for. Either this or ``public_key`` is required.

    private_key_passphrase
        If ``private_key`` is specified and encrypted, the passphrase to decrypt it.

    public_key
        The public key the certificate should be issued for.
        Either this or ``public_key`` is required.

    days_valid
        If ``not_after`` is unspecified, the number of days from the time of issuance
        the certificate should be valid for. Defaults to ``30`` for host certificates
        and ``1`` for client certificates.

    critical_options
        A mapping of critical option name to option value to set on the certificate.
        If an option does not take a value, specify it as ``true``.

    extensions
        A mapping of extension name to extension value to set on the certificate.
        If an extension does not take a value, specify it as ``true``.

    valid_principals
        A list of valid principals.

    all_principals
        Allow any principals. Defaults to false.
    """
    ignored_params = (
        "signing_private_key",
        "signing_private_key_passphrase",
        "serial_number",
        "not_before",
        "not_after",
        "copypath",
        "path",
        "overwrite",
        "raw",
    )
    for ignored in ignored_params:
        if kwargs.get(ignored) is not None:
            log.warning(
                f"Ignoring '{ignored}', this cannot be set for the Vault backend"
            )
            kwargs.pop(ignored)
    if not kwargs.get("private_key") and not kwargs.get("public_key"):
        raise SaltInvocationError(
            "Need a valid public key source, either 'private_key' or 'public_key'"
        )
    if kwargs.get("valid_principals"):
        kwargs["valid_principals"] = ",".join(kwargs["valid_principals"])
    elif kwargs.get("all_principals"):
        kwargs["valid_principals"] = "*"
    else:
        raise SaltInvocationError(
            "Either valid_principals or all_principals must be specified"
        )
    if not signing_policy:
        raise SaltInvocationError(
            "Need 'signing_policy' specified, which actually refers to a role name"
        )

    ttl = kwargs.get("ttl")
    if ttl is None and kwargs.get("days_valid"):
        # hours is the largest suffix apparently
        ttl = f"{kwargs['days_valid'] * 24}h"

    pubkey = __salt__["ssh_pki.get_public_key"](
        kwargs.get("private_key") or kwargs.get("public_key")
    )
    ca_server = ca_server or "ssh"

    return sign_key(
        signing_policy,
        pubkey,
        ttl=ttl,
        valid_principals=kwargs.get("valid_principals"),
        cert_type=kwargs.get("cert_type"),
        key_id=kwargs.get("key_id"),
        critical_options=kwargs.get("critical_options"),
        extensions=kwargs.get("extensions"),
        mount=ca_server,
    )["signed_key"]


def get_signing_policy(signing_policy, ca_server=None):
    """
    Returns an SSH role formatted as a signing policy.
    Compatibility layer between ``ssh_pki`` and this module.
    This currently does not support all functionality Vault offers,
    e.g. dynamic principals (templates/allow_subdomains) or allowed
    extensions/options, so ``ssh_pki.certificate_managed`` might always
    reissue a certificate in case these options are used.

    CLI Example:

    .. code-block:: bash

        salt '*' vault_ssh.get_signing_policy www

    signing_policy
        The name of the SSH role to return.

    ca_server
        The name of the mount point the SSH secret backend is mounted at.
    """
    ca_server = ca_server or "ssh"
    role = read_role(signing_policy, mount=ca_server)
    if role["key_type"] != "ca":
        raise SaltInvocationError("The specified Vault role is not a CA role")
    policy = {"allowed_valid_principals": []}

    if role.get("allow_host_certificates"):
        if role.get("allowed_domains_template") or role.get("allow_subdomains"):
            # Patterns are unsupported by the current ssh_pki modules.
            # Ensure the certificate is not always recreated.
            allowed_domains = ["*"]
        else:
            allowed_domains = role.get("allowed_domains", "").split(",")
        policy["allowed_valid_principals"].extend(allowed_domains)

    if role.get("allow_user_certificates"):
        if role.get("allowed_users_template"):
            # Patterns are unsupported by the current ssh_pki modules.
            # Ensure the certificate is not always recreated.
            allowed_users = ["*"]
        else:
            allowed_users = role.get("allowed_users", "").split(",")
        policy["allowed_valid_principals"].extend(allowed_users)

    if "*" in policy["allowed_valid_principals"]:
        policy.pop("allowed_valid_principals")
        policy["all_principals"] = True

    policy["allowed_critical_options"] = role.get("allowed_critical_options", "").split(
        ","
    )
    policy["allowed_extensions"] = role.get("allowed_critical_options", "").split(",")
    policy["default_critical_options"] = role.get("default_critical_options", {})
    policy["default_extensions"] = role.get("default_extensions", {})
    policy["default_valid_principals"] = (
        [role["default_user"]] if "default_user" in role else []
    )

    if role.get("ttl"):
        policy["ttl"] = role["ttl"] or None
    if role.get("max_ttl"):
        policy["max_ttl"] = role["max_ttl"]

    if not role.get("allow_user_key_ids"):
        policy["key_id"] = None

    policy["signing_public_key"] = read_ca(mount=ca_server)
    return policy


def _get_file_or_data(data):
    """
    Try to load a string as a file, otherwise return the string
    """
    if data.startswith("----- BEGIN"):
        return data
    try:
        if Path(data).is_file():
            return Path(data).read_text()
    except (OSError, TypeError, ValueError):
        pass
    return data
