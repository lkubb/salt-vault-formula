"""
State module to manage the Vault PKI secret engine.
"""

import base64
import datetime
import logging
from pathlib import Path

import salt.utils.files
from salt.exceptions import CommandExecutionError

log = logging.getLogger(__name__)


def intermediate_ca(
    name,
    days_remaining=30,
    csr_path=None,
    certificate=None,
    salt_ca=None,
    salt_signing_policy=None,
    ca_chain=None,
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
    Creates an intermediate CA on the provided endpoint.

    .. note::
        The parameters are currently only used for initialization and changes
        will not be applied. This currently only manages the default issuer.

    name
        Specifies the requested Common Name for the intermediate CA certificate.
        If more than one ``name`` is desired, specify the alternative names in
        the ``alt_names`` list. Do not use this state to manage multiple issuers
        on a single mount.

    days_remaining
        Attempt to recreate the certificate if the number of days the certificate
        will be valid for is less than the number specified. Defaults to 30.

    csr_path
        Export the Certificate Signing Request to this path. If unspecified,
        this state will rely on the Salt-internal method of issuing certificates
        provided by the ``x509`` module. You will need to specify ``salt_ca``
        and ``salt_signing_policy`` then.
        If you rely on this manual signing process, this state will fail until
        a signed certificate is provided in ``certificate``.

    certificate
        A string or (Salt) path to a file containing the signed PEM-encoded
        certificate to import. Required when not relying on the ``x509`` module.

    salt_ca
        A minion that provides ``x509.sign_remote_certificate``. If this is unspecified,
        you will need to manually sign the CSR that will be exported to ``csr_path``.

    salt_signing_policy
        A valid signing policy that should be used to sign this CA certificate.
        All parameters for ``x509.create_certificate`` should be defined there.
        Required when using ``salt_ca``. See the ``x509`` module docs for details.

    ca_chain
        A list of certificates in correct order (root CA would be last) to import
        as CA chain.

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
    ret = {"name": name, "result": True, "comment": "", "changes": {}}

    if csr_path is None and (salt_ca is None or salt_signing_policy is None):
        ret["result"] = False
        ret[
            "comment"
        ] = "You need to specify either csr_path or salt_ca and salt_signing_policy."
        return ret

    def _import_intermediate_cert(certificate, chain, mount, ret):
        if __opts__["test"]:
            ret["result"] = None
            ret["comment"] = "Default issuer certificate would have been imported."
            ret["changes"]["imported"] = ["new_issuer"]
            return ret
        imported = __salt__["vault_pki.set_intermediate_cert"](
            certificate, chain, mount=mount
        )
        ret["comment"] = "Default issuer certificate has been imported."
        ret["changes"]["imported"] = imported
        return ret

    try:
        default_issuer = __salt__["vault_pki.get_default_issuer"](mount)

        if default_issuer:
            # Generating a CSR only will not create an issuer
            default_issuer_cert = __salt__["vault_pki.fetch_issuer_cert"](mount=mount)[
                "certificate"
            ]
            if _valid_for(default_issuer_cert, days_remaining):
                # TODO: verify parameters
                ret["comment"] = (
                    "Default issuer is already configured. "
                    f"The certificate will still be valid in {days_remaining} days."
                )
                return ret

        # This should mean a signed certificate is available
        if csr_path is not None and certificate is not None:
            return _import_intermediate_cert(certificate, ca_chain, mount, ret)

        # If using manual signing and the CSR file exists, but we're here,
        # that means it hasn't been signed yet. Fail this state to avoid
        # dependent ones from executing
        if csr_path is not None and __salt__["file.file_exists"](csr_path):
            ret["result"] = False
            ret["comment"] = (
                "A CSR has already been generated, but no "
                "signed certificate to import was provided. "
                "Please remove the CSR file if you want to regenerate it."
            )
            return ret

        if __opts__["test"]:
            ret["result"] = None
            ret["comment"] = (
                "A CSR would have been generated. Depending on your "
                "configuration, it would have been exported or automatically signed."
            )
            ret["changes"]["generated_csr"] = "internal"
            return ret

        # This means a CSR has to be created
        csr = __salt__["vault_pki.get_intermediate_csr"](
            name,
            mount=mount,
            exclude_cn_from_sans=exclude_cn_from_sans,
            alt_names=alt_names,
            ip_sans=ip_sans,
            uri_sans=uri_sans,
            other_sans=other_sans,
            key_type=key_type,
            key_bits=key_bits,
            signature_bits=signature_bits,
            **kwargs,
        )

        if csr_path is not None:
            with salt.utils.files.fopen(csr_path, "w") as f:
                f.write(csr)
            ret["result"] = False
            ret["comment"] = (
                "A CSR has been generated. You will need to sign it. "
                "Failing this state is expected."
            )
            ret["changes"]["generated_csr"] = csr_path
            return ret

        certificate = __salt__["x509.create_certificate"](
            text=True, ca_server=salt_ca, csr=csr, signing_policy=salt_signing_policy
        )
        return _import_intermediate_cert(certificate, ca_chain, mount, ret)

    except CommandExecutionError as err:
        ret["result"] = False
        ret["comment"] = str(err)
        ret["changes"] = {}

    return ret


def role_present(name, mount="pki", **kwargs):
    """
    Make sure a PKI role is present. Specify parameters as kwargs. For available parameters,
    see the `API method docs <https://www.vaultproject.io/api-docs/secret/pki#create-update-role>`_.

    name
        The name of the role.

    mount
        The mount path the PKI backend is mounted to. Defaults to ``pki``.
    """
    ret = {"name": name, "result": True, "comment": "", "changes": {}}

    try:
        current = __salt__["vault_pki.fetch_role"](name, mount=mount)

        if current:
            added = set(kwargs) - set(current)
            changed = []
            removed = set(current) - set(kwargs)
            for param, val in kwargs.items():
                if current.get(param, "__unset__") != val:
                    changed.append(param)
            if not (added or changed or removed):
                ret["comment"] = "Role is present as specified"
                return ret
            ret["changes"] = {"added": added, "changed": changed, "removed": removed}

        if __opts__["test"]:
            ret["result"] = None
            ret[
                "comment"
            ] = f"Role `{name}` would have been {'updated' if current else 'created'}"
            if not current:
                ret["changes"]["created"] = name
            return ret

        __salt__["vault_pki.write_role"](name, mount=mount, update=False, **kwargs)
        new = __salt__["vault_pki.fetch_role"](name, mount=mount)

        if new is None:
            raise CommandExecutionError(
                "There were no errors during role management, but it is reported as absent."
            )
        if new != kwargs:
            ret["result"] = False
            ret["comment"] = (
                "There were no errors during role management, but "
                "the reported parameters do not match."
            )
            return ret

    except CommandExecutionError as err:
        ret["result"] = False
        ret["comment"] = str(err)
        ret["changes"] = {}

    return ret


def role_absent(name, mount="pki"):
    """
    Make sure a PKI role is absent.

    name
        The name of the role.

    mount
        The mount path the PKI backend is mounted to. Defaults to ``pki``.
    """
    ret = {"name": name, "result": True, "comment": "", "changes": {}}

    try:
        current = __salt__["vault_pki.fetch_role"](name, mount=mount)

        if current is None:
            ret["comment"] = f"Role `{name}` is already absent."
            return ret

        ret["changes"]["deleted"] = name

        if __opts__["test"]:
            ret["result"] = None
            ret["comment"] = f"Role `{name}` would have been deleted."
            return ret

        __salt__["vault_pki.delete_role"](name, mount=mount)

        if __salt__["vault_pki.fetch_role"](name, mount=mount) is not None:
            raise CommandExecutionError(
                "There were no errors during role deletion, but it is still reported as present."
            )
        ret["comment"] = f"Role `{name}` has been deleted."

    except CommandExecutionError as err:
        ret["result"] = False
        ret["comment"] = str(err)
        ret["changes"] = {}

    return ret


def urls_set(
    name,
    issuing_certificates=None,
    crl_distribution_endpoints=None,
    ocsp_servers=None,
    mount="pki",
):
    """
    Set issuing certificate endpoints, CRL distribution points, and OCSP server
    endpoints that will be encoded into issued certificates. Unset values will
    not be managed. To make sure a value is unset, set it to an empty string.

    name
        Unused.

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
    ret = {"name": name, "result": True, "comment": "", "changes": {}}

    def _compare_url_list(val, current):
        if val is None:
            return False
        if not isinstance(val, list):
            val = [val]
        return val == current

    try:
        current = __salt__["vault_pki.get_urls"](mount=mount)
        changes = []

        if _compare_url_list(issuing_certificates, current["issuing_certificates"]):
            changes.append("issuing_certificates")
        if _compare_url_list(
            crl_distribution_endpoints, current["crl_distribution_endpoints"]
        ):
            changes.append("crl_distribution_endpoints")
        if _compare_url_list(ocsp_servers, current["ocsp_servers"]):
            changes.append("ocsp_servers")

        if not changes:
            ret["comment"] = "URLs are already set as specified."
            return ret

        ret["changes"]["updated"] = changes

        if __opts__["test"]:
            ret["result"] = None
            ret["comment"] = "URLs would have been updated."
            return ret

        __salt__["vault_pki.set_urls"](
            issuing_certificates=issuing_certificates,
            crl_distribution_endpoints=crl_distribution_endpoints,
            ocsp_servers=ocsp_servers,
            mount=mount,
        )

        new = __salt__["vault_pki.get_urls"](mount=mount)

        if (
            _compare_url_list(issuing_certificates, new["issuing_certificates"])
            or _compare_url_list(
                crl_distribution_endpoints, new["crl_distribution_endpoints"]
            )
            or _compare_url_list(ocsp_servers, new["ocsp_servers"])
        ):
            raise CommandExecutionError(
                "There were no errors during URL management, but there are still differences."
            )

        ret["comment"] = "URLs have been updated."

    except CommandExecutionError as err:
        ret["result"] = False
        ret["comment"] = str(err)
        ret["changes"] = {}

    return ret


def certificate_managed(
    name,
    common_name,
    role,
    issuer_ref=None,
    private_key=None,
    private_key_save_path=None,
    csr=None,
    days_remaining=3,
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
    **kwargs,
):
    """
    Make sure a valid certificate is present. Parameters to ``file.managed``
    can be specified as kwargs, provided ``format_out`` is ``pem``.
    Mind that most parameters are used as initialization ones, meaning
    if a valid certificate exists at the path, they are not checked for
    changes. TODO

    name
        Path to the certificate.

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

    private_key_save_path
        If ``private_key`` and ``csr`` is unset, Vault will generate a private
        key and send it with the certificate. This specifies the path it is saved to.
        Defaults to the path of the certificate with ``.key`` file extension.

    csr
        A string or (Salt) path to a file containing a PEM-encoded CSR to sign.

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
        Only available/relevant when Vault generates a key.

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
    ret = {
        "name": name,
        "result": True,
        "comment": "",
        "changes": {},
        "sub_state_run": [],
    }

    def _write_binary(path, data, umask="0133"):
        raw = base64.b64decode(data)
        with salt.utils.files.set_umask(umask):
            with salt.utils.files.fopen(path, "wb") as f:
                f.write(raw)

    def _write_file(path, data, ret, **kwargs):
        file_args, _ = _get_file_args(path, **kwargs)
        file_args["contents"] = data
        ret_file = __states__["file.managed"](**kwargs)
        ret_file["low"] = {
            "name": str(path),
            "state": "file",
            "__id__": __low__["__id__"],
            "fun": "managed",
        }
        ret["sub_state_run"].append(ret_file)

    def _append_suffix(path, suffix="", extension=None):
        path = Path(path)
        stem = path.stem + suffix
        res = path.with_stem(stem)
        if extension is None:
            return res
        return res.with_suffix(f".{extension}")

    try:
        current = None
        if __salt__["file.file_exists"](name):
            current = True
            if _valid_for(name, days_remaining):
                ret["comment"] = (
                    "Certificate exists and will still be valid in "
                    f"{days_remaining} days."
                )
                return ret

        ret["changes"][f"{'re' if current is not None else ''}created"] = name

        if __opts__["test"]:
            ret["result"] = None
            ret["comment"] = (
                f"Certificate `{name}` would have been "
                f"{'re' if current is not None else ''}created."
            )
            return ret

        res = __salt__["vault_pki.get_certificate"](
            common_name,
            role,
            issuer_ref=issuer_ref,
            csr=csr,
            private_key=private_key,
            mount=mount,
            alt_names=alt_names,
            ip_sans=ip_sans,
            uri_sans=uri_sans,
            other_sans=other_sans,
            ttl=ttl,
            format_out=format_out,
            private_key_format=private_key_format,
            exclude_cn_from_sans=exclude_cn_from_sans,
            not_after=not_after,
            remove_roots_from_chain=remove_roots_from_chain,
        )

        ret[
            "comment"
        ] = f"Certificate `{name}` has been {'re' if current is not None else ''}created."

        if "der" == format_out:
            _write_binary(name, res["data"]["certificate"])
            _write_binary(_append_suffix(name, "chain"), res["data"]["ca_chain"])
            if "private_key" in res["data"]:
                pk_path = private_key_save_path or _append_suffix(name, "", "key")
                _write_binary(pk_path, res["data"]["private_key"], umask="0377")
            return res

        _write_file(name, res["data"]["certificate"], ret, **kwargs)
        _write_file(
            _append_suffix(name, "chain"), res["data"]["ca_chain"], ret, **kwargs
        )
        if "private_key" in res["data"]:
            pk_path = private_key_save_path or _append_suffix(name, "", "key")
            kwargs["mode"] = "0400"
            _write_file(
                _append_suffix(pk_path, "", "key"),
                res["data"]["private_key"],
                ret,
                **kwargs,
            )

    except CommandExecutionError as err:
        ret["result"] = False
        ret["comment"] = str(err)
        ret["changes"] = {}

    return ret


def _get_file_args(name, **kwargs):
    valid_file_args = [
        "user",
        "group",
        "mode",
        "makedirs",
        "dir_mode",
        "backup",
        "create",
        "follow_symlinks",
        "check_cmd",
    ]
    file_args = {}
    extra_args = {}
    for k, v in kwargs.items():
        if k in valid_file_args:
            file_args[k] = v
        else:
            extra_args[k] = v
    file_args["name"] = name
    return file_args, extra_args


def _valid_for(cert, days):
    """
    x509.will_expire is supposed to work like this, but actually only works
    for files, not PEM strings.
    """
    current = __salt__["x509.read_certificate"](cert)
    valid_until = datetime.datetime.fromisoformat(current["Not After"])
    valid_at = datetime.datetime.now() + datetime.timedelta(days=days)
    return valid_at < valid_until
