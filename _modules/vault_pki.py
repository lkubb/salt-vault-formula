"""
Execution module to manage the Vault PKI secret engine.
"""

import logging

import salt.utils.stringutils
import vaultutil as vault
from salt.exceptions import CommandExecutionError, SaltInvocationError

log = logging.getLogger(__name__)

ROLE_PARAMS = (
    "issuer_ref",
    "ttl",
    "max_ttl",
    "allow_localhost",
    "allowed_domains",
    "allowed_domains_template",
    "allow_bare_domains",
    "allow_subdomains",
    "allow_glob_domains",
    "allow_wildcard_certificates",
    "allow_any_name",
    "enforce_hostnames",
    "allow_ip_sans",
    "allowed_uri_sans",
    "allowed_uri_sans_template",
    "allowed_other_sans",
    "allowed_serial_numbers",
    "server_flag",
    "client_flag",
    "code_signing_flag",
    "email_protection_flag",
    "key_type",
    "key_bits",
    "signature_bits",
    "use_pss",
    "key_usage",
    "ext_key_usage",
    "ext_key_usage_oids",
    "use_csr_common_name",
    "use_csr_sans",
    "ou",
    "organization",
    "country",
    "locality",
    "province",
    "street_address",
    "postal_code",
    "generate_lease",
    "no_store",
    "require_cn",
    "policy_identifiers",
    "basic_constraints_valid_for_non_ca",
    "not_before_duration",
    "not_after",
    "cn_validations",
)


def list_issuers(mount="pki"):
    """
    List issuers and their keys. Returns dict ``{issuer_name: key_id, ...}``.

    .. note::
        Uses an unauthenticated endpoint.

    `API method docs <https://www.vaultproject.io/api-docs/secret/pki#list-issuers>`_.

    CLI Example:

    .. code-block:: bash

            salt '*' vault_pki.list_issuers

    mount
        The mount path the PKI backend is mounted to. Defaults to ``pki``.
    """
    endpoint = f"{mount}/issuers"
    try:
        res = vault.query("LIST", endpoint, __opts__, __context__, is_unauthd=True)[
            "data"
        ]
        # {"keys": ["ab...", ...], "key_info": {"ab..": "imported-root", ...}}
        # can one issuer have multiple keys? this will not work then TODO
        return {name: issuer_id for issuer_id, name in res["key_info"].items()}
    except vault.VaultNotFoundError:
        return {}
    except vault.VaultException as err:
        raise CommandExecutionError(f"{err.__class__}: {err}") from err


def fetch_issuer(ref, mount="pki"):
    """
    Lookup issuer metadata. Returns dict ``{issuer_name: key_id, ...}`` or None.

    This includes information about the name, the key material, if an explicitly
    constructed chain has been set, what the behavior is for signing longer TTL'd
    certificates, and what usage modes are set on this issuer.

    `API method docs <https://www.vaultproject.io/api-docs/secret/pki#read-issuer>`_.

    CLI Example:

    .. code-block:: bash

            salt '*' vault_pki.list_issuers

    ref
        Reference to an issuer, either by Vault-generated identifier,
        the literal string ``default`` to refer to the currently configured default issuer,
        or the name assigned to an issuer.

    mount
        The mount path the PKI backend is mounted to. Defaults to ``pki``.
    """
    endpoint = f"{mount}/issuer/{ref}"
    try:
        return vault.query("GET", endpoint, __opts__, __context__)["data"]
    except vault.VaultServerError:
        return None
    except vault.VaultException as err:
        raise CommandExecutionError(f"{err.__class__}: {err}") from err


def get_default_issuer(mount="pki"):
    """
    Return the issuer ID of the default issuer.

    `API method docs <https://www.vaultproject.io/api-docs/secret/pki#read-issuers-configuration>`_.

    CLI Example:

    .. code-block:: bash

            salt '*' vault_pki.get_default_issuer

    mount
        The mount path the PKI backend is mounted to. Defaults to ``pki``.
    """
    endpoint = f"{mount}/config/issuers"
    try:
        return vault.query("GET", endpoint, __opts__, __context__)["data"]["default"]
    except vault.VaultException as err:
        raise CommandExecutionError(f"{err.__class__}: {err}") from err


def set_default_issuer(ref, mount="pki"):
    """
    Set the default issuer.

    `API method docs <https://www.vaultproject.io/api-docs/secret/pki#set-issuers-configuration>`_.

    CLI Example:

    .. code-block:: bash

            salt '*' vault_pki.set_default_issuer myca

    mount
        The mount path the PKI backend is mounted to. Defaults to ``pki``.
    """
    endpoint = f"{mount}/config/issuers"
    payload = {"default": ref}
    try:
        return vault.query("POST", endpoint, __opts__, __context__, payload=payload)[
            "data"
        ]["default"]
    except vault.VaultException as err:
        raise CommandExecutionError(f"{err.__class__}: {err}") from err


def fetch_issuer_cert(ref="default", mount="pki"):
    """
    Fetch an issuer's certificate and CA chain.
    Returns ``{"ca_chain": ["-----...", ...], "certificate": "-----BEGIN CERTIFICATE..."}``.

    .. note::
        Uses an unauthenticated endpoint.

    `API method docs <https://www.vaultproject.io/api-docs/secret/pki#read-issuer-certificate>`_.

    CLI Example:

    .. code-block:: bash

            salt '*' vault_pki.fetch_issuer_cert

    ref
        Reference to an issuer, either by Vault-generated identifier,
        the literal string ``default`` to refer to the currently configured default issuer,
        or the name assigned to an issuer. Defaults to ``default``.

    mount
        The mount path the PKI backend is mounted to. Defaults to ``pki``.
    """
    endpoint = f"{mount}/cert/ca"
    if "default" != ref:
        endpoint = f"/pki/issuer/{ref}/json"
    try:
        return vault.query("GET", endpoint, __opts__, __context__, is_unauthd=True)[
            "data"
        ]
    except vault.VaultException as err:
        raise CommandExecutionError(f"{err.__class__}: {err}") from err


def list_roles(mount="pki"):
    """
    List available role names.

    `API method docs <https://www.vaultproject.io/api-docs/secret/pki#list-roles>`_.

    CLI Example:

    .. code-block:: bash

            salt '*' vault_pki.list_roles

    mount
        The mount path the PKI backend is mounted to. Defaults to ``pki``.
    """
    endpoint = f"{mount}/roles"
    try:
        return vault.query("LIST", endpoint, __opts__, __context__)["data"]["keys"]
    except vault.VaultNotFoundError:
        return []
    except vault.VaultException as err:
        raise CommandExecutionError(f"{err.__class__}: {err}") from err


def fetch_role(name, mount="pki"):
    """
    Fetch a role definition. Returns None if not found.

    `API method docs <https://www.vaultproject.io/api-docs/secret/pki#read-role>`_.

    CLI Example:

    .. code-block:: bash

            salt '*' vault_pki.fetch_role myrole

    mount
        The mount path the PKI backend is mounted to. Defaults to ``pki``.
    """
    endpoint = f"{mount}/role/{name}"
    try:
        return vault.query("GET", endpoint, __opts__, __context__)["data"]
    except vault.VaultNotFoundError:
        return None
    except vault.VaultException as err:
        raise CommandExecutionError(f"{err.__class__}: {err}") from err


def write_role(name, update=False, mount="pki", **kwargs):
    """
    Create/update a role. Specify parameters as kwargs. For available parameters,
    see the `API method docs <https://www.vaultproject.io/api-docs/secret/pki#create-update-role>`_.

    CLI Example:

    .. code-block:: bash

            salt '*' vault_pki.write_role myrole

    name
        The name of the role to create/update.

    update
        Do not overwrite, only update specified values.
        Requires Vault v1.11.0 and ``patch`` capability.
        Defaults to False.

    mount
        The mount path the PKI backend is mounted to. Defaults to ``pki``.
    """
    invalid = set(kwargs) - set(ROLE_PARAMS)
    if invalid:
        raise CommandExecutionError(
            f"The following params are invalid: {', '.join(invalid)}."
        )
    endpoint = f"{mount}/role/{name}"
    method = "POST" if not update else "PATCH"

    log.debug(f"Creating/updating Vault PKI role `{name}`.")
    try:
        return vault.query(method, endpoint, __opts__, __context__, payload=kwargs)
    except vault.VaultException as err:
        raise CommandExecutionError(f"{err.__class__}: {err}") from err


def delete_role(name, mount="pki"):
    """
    Delete a role. Deleting a role does not revoke certificates previously issued under this role.

    `API method docs <https://www.vaultproject.io/api-docs/secret/pki#delete-role>`_.

    CLI Example:

    .. code-block:: bash

            salt '*' vault_pki.delete_role myrole

    mount
        The mount path the PKI backend is mounted to. Defaults to ``pki``.
    """
    endpoint = f"{mount}/role/{name}"
    log.debug(f"Deleting Vault PKI role `{name}`.")
    try:
        return vault.query("DELETE", endpoint, __opts__, __context__)
    except vault.VaultException as err:
        raise CommandExecutionError(f"{err.__class__}: {err}") from err


def get_urls(mount="pki"):
    """
    Fetch the URLs to be encoded in generated certificates.
    No URL configuration will be returned until the configuration is set.

    `API method docs <https://www.vaultproject.io/api-docs/secret/pki#read-urls>`_.

    CLI Example:

    .. code-block:: bash

            salt '*' vault_pki.get_urls

    mount
        The mount path the PKI backend is mounted to. Defaults to ``pki``.
    """
    endpoint = f"{mount}/config/urls"
    try:
        return vault.query("GET", endpoint, __opts__, __context__)["data"]
    except vault.VaultException as err:
        raise CommandExecutionError(f"{err.__class__}: {err}") from err


def set_urls(
    issuing_certificates=None,
    crl_distribution_endpoints=None,
    ocsp_servers=None,
    mount="pki",
):
    """
    Set issuing certificate endpoints, CRL distribution points, and OCSP server
    endpoints that will be encoded into issued certificates. This behaves
    as PATCH. To unset a value, set it to an empty string.

    `API method docs <https://www.vaultproject.io/api-docs/secret/pki#set-urls>`_.

    CLI Example:

    .. code-block:: bash

            salt '*' vault_pki.set_urls ocsp_servers=ocsp.my.ca

    issuing_certificates
        Specifies the URL values for the Issuing Certificate field as a list.
        (see RFC 5280 Section 4.2.2.1 for details)

    crl_distribution_endpoints
        Specifies the URL values for the CRL Distribution Points field as a list.
        (see RFC 5280 Section 4.2.1.13 for details)

    ocsp_servers
        Specifies the URL values for the OCSP Servers field as a list.
        (see RFC 5280 Section 4.2.2.1 for details)

    mount
        The mount path the PKI backend is mounted to. Defaults to ``pki``.
    """
    endpoint = f"{mount}/config/urls"
    payload = {}

    if issuing_certificates is not None:
        payload["issuing_certificates"] = issuing_certificates
    if crl_distribution_endpoints is not None:
        payload["crl_distribution_endpoints"] = crl_distribution_endpoints
    if ocsp_servers is not None:
        payload["ocsp_servers"] = ocsp_servers

    if not payload:
        raise CommandExecutionError("You need to specify at least one parameter.")

    log.debug(f"Setting Vault PKI URLs {', '.join(payload.keys())}.")
    try:
        return vault.query("POST", endpoint, __opts__, __context__, payload=payload)
    except vault.VaultException as err:
        raise CommandExecutionError(f"{err.__class__}: {err}") from err


def get_intermediate_csr(
    common_name,
    mount="pki",
    exclude_cn_from_sans=False,
    alt_names=None,
    ip_sans=None,
    uri_sans=None,
    other_sans=None,
    key_type="rsa",
    key_bits=0,
    signature_bits=0,
    **kwargs,
):
    """
    Get a certificate signing request for an intermediate CA in PEM-format.

    `API method docs <https://www.vaultproject.io/api-docs/secret/pki#generate-intermediate-csr>`_.

    CLI Example:

    .. code-block:: bash

            salt '*' vault_pki.get_intermediate_csr "Vault CA"

    common_name
        Specifies the requested CN for the certificate. If more than one
        ``common_name`` is desired, specify the alternative names in
        the ``alt_names`` list.

    mount
        The mount path the PKI backend is mounted to. Defaults to ``pki``.

    exclude_cn_from_sans
        Do not include the given ``common_name`` in DNS or Email Subject Alternate Names.
        Useful if the CN is not a hostname or email address, but is instead some
        human-readable identifier.
        Defaults to False.

    alt_names
        Specifies the requested Subject Alternative Names (SAN) as a list.
        These can be host names or email addresses; they will be parsed into
        their respective fields.

    ip_sans
        Specifies the requested IP Subject Alternative Names in a list.

    uri_sans
        Specifies the requested URI Subject Alternative Names in a list.

    other_sans
        Specifies custom OID/UTF8-string SANs in a list. These must match values
        specified on the role in allowed_other_sans.
        The format is the same as OpenSSL:
        ``<oid>;<type>:<value>`` where the only current valid type is UTF8.

    key_type
        Specifies the desired key type; must be ``rsa``, ``ed25519`` or ``ec``.

    key_bits
        Specifies the number of bits to use for the generated keys.
        Allowed values are 0 (universal default);
        with ``key_type=rsa``, allowed values are: 2048 (default), 3072, or 4096;
        with ``key_type=ec``, allowed values are: 224, 256 (default), 384, or 521;
        ignored with ``key_type=ed25519``.

    signature_bits
        Specifies the number of bits to use in the signature algorithm; accepts
        256 for SHA-2-256, 384 for SHA-2-384, and 512 for SHA-2-512.
        Defaults to 0 to automatically detect based on issuer's key length
        (SHA-2-256 for RSA keys, and matching the curve size for NIST P-Curves).

    kwargs
        ``ou``, ``organization``, ``country`` can be specified as kwargs.
    """
    # currently only supports internal, not exported/existing/kms
    ca_type = "internal"
    endpoint = f"{mount}/intermediate/generate/{ca_type}"
    payload = {
        "common_name": common_name,
        "exclude_cn_from_sans": exclude_cn_from_sans,
        "format": "pem",
        "key_type": key_type,
        "key_bits": key_bits,
        "signature_bits": signature_bits,
    }

    if alt_names is not None:
        payload["alt_names"] = ",".join(alt_names)
    if ip_sans is not None:
        payload["ip_sans"] = ",".join(ip_sans)
    if uri_sans is not None:
        payload["uri_sans"] = ",".join(uri_sans)
    if other_sans is not None:
        payload["other_sans"] = ",".join(other_sans)

    for subject in ["ou", "organization", "country"]:
        if subject in kwargs:
            payload[subject] = kwargs[subject]
    log.debug(f"Fetching certificate signing request for `{common_name}`.")
    try:
        return vault.query("POST", endpoint, __opts__, __context__, payload=payload)[
            "data"
        ]["csr"]
    except vault.VaultException as err:
        raise CommandExecutionError(f"{err.__class__}: {err}") from err


def set_intermediate_cert(cert, chain=None, mount="pki"):
    """
    Import a PEM-encoded CA certificate.

    `API method docs <https://www.vaultproject.io/api-docs/secret/pki#import-ca-certificates-and-keys>`_.

    CLI Example:

    .. code-block:: bash

            salt '*' vault_pki.set_intermediate_cert

    cert
        A string or (Salt) path to a file containing a PEM-encoded certificate to import.

    mount
        The mount path the PKI backend is mounted to. Defaults to ``pki``.
    """
    cert_chain = []
    for c in [cert] + (chain or []):
        if "BEGIN CERTIFICATE" not in c:
            c = __salt__["cp.get_file_str"](c)
        if not c or "BEGIN CERTIFICATE" not in c:
            raise CommandExecutionError(
                "Passed cert is invalid. Make sure it is "
                "either the certificate string or a valid file path."
            )
        c = __salt__["x509.get_pem_entry"](c, pem_type="CERTIFICATE")
        cert_chain.append(salt.utils.stringutils.to_str(c))

    endpoint = f"{mount}/intermediate/set-signed"
    payload = {"certificate": "\n".join(cert_chain)}

    log.debug("Importing intermediate CA certificate.")
    try:
        return vault.query("POST", endpoint, __opts__, __context__, payload=payload)[
            "data"
        ]["imported_issuers"]
    except vault.VaultException as err:
        raise CommandExecutionError(f"{err.__class__}: {err}") from err


def get_certificate(
    common_name,
    role,
    issuer_ref=None,
    csr=None,
    private_key=None,
    mount="pki",
    alt_names=None,
    ip_sans=None,
    uri_sans=None,
    other_sans=None,
    ttl=None,
    format_out="pem",
    private_key_format="der",
    exclude_cn_from_sans=False,
    not_after=None,
    remove_roots_from_chain=False,
):
    """
    Request a certificate.

    Returns the whole response , which includes ``lease_id`` and ``lease_duration``.
    The data is found in ``data``, which is a dict with ``certificate``, ``issuing_ca``,
    ``ca_chain`` [List], ``serial_number``. When csr is unspecified, it also
    includes ``private_key`` and ``private_key_type``.

    .. note::
        This function calls different endpoints, depending on the
        ``issuer_ref`` and ``csr`` parameters.

        - ``{mount}/issue/{role}`` (default)
        - ``{mount}/sign/{role}`` (csr specified)
        - ``{mount}/issuer/{ref}/issue/{role}`` (issuer_ref specified)
        - ``{mount}/issuer/{ref}/sign/{role}`` (issuer_ref + csr specified)

    API method docs:
    - `no CSR <https://www.vaultproject.io/api-docs/secret/pki#generate-certificate-and-key>`_.
    - `sign CSR <https://www.vaultproject.io/api-docs/secret/pki#sign-certificate>`_.

    CLI Example:

    .. code-block:: bash

            salt '*' vault_pki.get_certificate www.me.com www

    common_name
        Specifies the requested CN for the certificate. If more than one
        ``common_name`` is desired, specify the alternative names in
        the ``alt_names`` list.

    role
        Which role to use to issue the certificate.

    issuer_ref
        Reference to an existing issuer, either by Vault-generated identifier,
        the literal string ``default`` to refer to the currently configured
        default issuer, or the name assigned to an issuer.
        Choice of issuing CA is determined first by the role, then by this
        parameter.

    private_key
        A string or (Salt) path to a file containing a PEM-encoded private key
        to request a certificate for. Mind that this is currently limited
        to RSA keys due to limitations in the ``x509`` module. This can be lifted
        if one ports it to use ``pyca/cryptography`` (TODO).

    csr
        A string or (Salt) path to a file containing a PEM-encoded CSR to sign.
        If unspecified, Vault will generate a private key and send it in the
        response as well.

    mount
        The mount path the PKI backend is mounted to. Defaults to ``pki``.

    alt_names
        Specifies the requested Subject Alternative Names (SAN) as a list.
        These can be host names or email addresses; they will be parsed into
        their respective fields.

    ip_sans
        Specifies the requested IP Subject Alternative Names in a list.

    uri_sans
        Specifies the requested URI Subject Alternative Names in a list.

    other_sans
        Specifies custom OID/UTF8-string SANs in a list. These must match values
        specified on the role in allowed_other_sans.
        The format is the same as OpenSSL:
        ``<oid>;<type>:<value>`` where the only current valid type is UTF8.

    ttl
        Specifies the requested Time To Live. Cannot be greater than the role's
        ``max_ttl`` value. If not provided, the role's ttl value will be used.
        Note that the role values default to system values if not explicitly set.

    format_out
        Specifies the format for returned data. Can be ``pem``, ``der``, or ``pem_bundle``.
        If der, the output is base64 encoded. If pem_bundle, the certificate field
        will contain the certificate and, if the issuing CA is not a Vault-derived
        self-signed root, it will be concatenated with the certificate.
        Defaults to "pem".

    private_key_format
        Specifies the format for marshaling the private key within the private_key
        response field. Defaults to ``der``, which will return either base64-encoded
        DER or PEM-encoded DER, depending on the value of ``format_out``.
        The other option is ``pkcs8``, which will return the key marshalled as
        PEM-encoded PKCS8.
        Only available/relevant when generating a certificate, not signing a CSR.

    exclude_cn_from_sans
        Do not include the given ``common_name`` in DNS or Email Subject Alternate Names.
        Useful if the CN is not a hostname or email address, but is instead some
        human-readable identifier.
        Defaults to false.

    not_after
        Set the Not After field of the certificate with specified date value.
        The value format should be given in UTC format ``YYYY-MM-ddTHH:MM:SSZ``.

    remove_roots_from_chain
        If true, the returned ca_chain field will not include any self-signed
        CA certificates. Useful if end-users already have the root CA in their
        trust store. Defaults to false.
        Only honored when signing a CSR.
    """
    if issuer_ref is None:
        prefix = mount
    else:
        prefix = f"{mount}/issuer/{issuer_ref}"

    payload = {
        "common_name": common_name,
        "exclude_cn_from_sans": exclude_cn_from_sans,
        "format": format_out,
    }

    if private_key and csr:
        raise SaltInvocationError("Only specify either private_key or csr.")

    if private_key is not None:
        csr = __salt__["x509.create_csr"](text=True, private_key=private_key)

    if csr is not None:
        if "BEGIN CERTIFICATE REQUEST" not in csr:
            csr = __salt__["cp.get_file_str"](csr)
        csr = __salt__["x509.get_pem_entry"](csr, pem_type="CERTIFICATE REQUEST")
        endpoint = f"{prefix}/sign/{role}"
        payload["csr"] = csr
        payload["remove_roots_from_chain"] = remove_roots_from_chain
    else:
        endpoint = f"{prefix}/issue/{role}"
        payload["private_key_format"] = private_key_format

    if alt_names is not None:
        payload["alt_names"] = ",".join(alt_names)
    if ip_sans is not None:
        payload["ip_sans"] = ",".join(ip_sans)
    if uri_sans is not None:
        payload["uri_sans"] = ",".join(uri_sans)
    if other_sans is not None:
        payload["other_sans"] = ",".join(other_sans)
    if ttl is not None:
        payload["ttl"] = str(ttl)
    if not_after is not None:
        payload["not_after"] = not_after

    log.debug(f"Requesting certificate for `{common_name}` with role `{role}`.")
    try:
        return vault.query("POST", endpoint, __opts__, __context__, payload=payload)
    except vault.VaultException as err:
        raise CommandExecutionError(f"{err.__class__}: {err}") from err
