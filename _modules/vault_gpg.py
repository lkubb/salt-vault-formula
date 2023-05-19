"""
Interface with the `Vault GPG secret engine <https://github.com/LeSuisse/vault-gpg-plugin/tree/main>`_.

Configuration instructions are documented in the :ref:`vault execution module docs <vault-setup>`.
The API docs can be found `here <https://github.com/LeSuisse/vault-gpg-plugin/blob/main/docs/http-api.md>`_.
"""

import base64
import logging
import os.path
from pathlib import Path

import vaultutil as vault
from salt.exceptions import CommandExecutionError

log = logging.getLogger(__name__)

__func_alias__ = {"list_": "list", "import_": "import"}


def create(
    name,
    real_name=None,
    email=None,
    comment=None,
    key_bits=None,
    exportable=False,
    transparency_log_address=None,
    mount="gpg",
):
    """
    Create a GPG key.

    CLI Example:

    .. code-block:: bash

            salt '*' vault_gpg.create mykey

    Required policy:

    .. code-block::

        path "<mount>/keys/<name>" {
            capabilities = ["create"]
        }

    name
        The name of the key.

    real_name
        Specifies the real name of the identity associated with the GPG key to create.

    email
        Specifies the email of the identity associated with the GPG key to create.

    comment
        Specifies the comment of the identity associated with the GPG key to create.

    key_bits
        Specifies the bitlength of the generated GPG key. Defaults to ``2048``.

    exportable
        Specifies if the raw key is exportable. Defaults to false.

    transparency_log_address
        Specifies the `Rekor transparency log address <https://github.com/sigstore/rekor>`_
        used to publish the signatures.

    mount
        The mount path the GPG backend is mounted to. Defaults to ``gpg``.
    """
    endpoint = f"{mount}/keys/{name}"
    payload = {
        "generate": True,
        "real_name": real_name,
        "email": email,
        "comment": comment,
        "key_bits": key_bits,
        "exportable": exportable,
        "transparency_log_address": transparency_log_address,
    }
    payload = {k: v for k, v in payload.items() if v is not None}
    try:
        return vault.query("POST", endpoint, __opts__, __context__, payload=payload)
    except vault.VaultException as err:
        raise CommandExecutionError(f"{err.__class__}: {err}") from err


def import_(
    name,
    key,
    exportable=False,
    transparency_log_address=None,
    mount="gpg",
):
    """
    Import a GPG key.

    CLI Example:

    .. code-block:: bash

            cat my.key | salt '*' vault_gpg.import mykey key="$(</dev/stdin)"

    Required policy:

    .. code-block::

        path "<mount>/keys/<name>" {
            capabilities = ["create"]
        }

    name
        The name of the key.

    key
        The ASCII-armored GPG private key to import.

    exportable
        Specifies if the raw key is exportable. Defaults to false.

    transparency_log_address
        Specifies the `Rekor transparency log address <https://github.com/sigstore/rekor>`_
        used to publish the signatures.

    mount
        The mount path the GPG backend is mounted to. Defaults to ``gpg``.
    """
    endpoint = f"{mount}/keys/{name}"
    payload = {
        "generate": False,
        "key": key,
        "exportable": exportable,
        "transparency_log_address": transparency_log_address,
    }
    payload = {k: v for k, v in payload.items() if v is not None}
    try:
        return vault.query("POST", endpoint, __opts__, __context__, payload=payload)
    except vault.VaultException as err:
        raise CommandExecutionError(f"{err.__class__}: {err}") from err


def list_(mount="gpg"):
    """
    List configured keys.

    CLI Example:

    .. code-block:: bash

            salt '*' vault_gpg.list

    Required policy:

    .. code-block::

        path "<mount>/keys" {
            capabilities = ["list"]
        }

    mount
        The mount path the GPG backend is mounted to. Defaults to ``gpg``.
    """
    endpoint = f"{mount}/keys"
    try:
        return vault.query("LIST", endpoint, __opts__, __context__)["data"]["keys"]
    except vault.VaultNotFoundError:
        return []
    except vault.VaultException as err:
        raise CommandExecutionError(f"{err.__class__}: {err}") from err


def read(name, mount="gpg"):
    """
    Read a configured key's information. Returns None if it does not exist.
    Returns a dictionary with keys ``exportable``, ``fingerprint`` and ``public_key``.

    CLI Example:

    .. code-block:: bash

            salt '*' vault_gpg.read mykey

    Required policy:

    .. code-block::

        path "<mount>/keys/<name>" {
            capabilities = ["read"]
        }

    name
        The name of the key.

    mount
        The mount path the GPG backend is mounted to. Defaults to ``gpg``.
    """
    endpoint = f"{mount}/keys/{name}"
    try:
        return vault.query("GET", endpoint, __opts__, __context__)["data"]
    except vault.VaultNotFoundError:
        return None
    except vault.VaultException as err:
        raise CommandExecutionError(f"{err.__class__}: {err}") from err


def delete(name, mount="gpg"):
    """
    Delete a GPG key.

    CLI Example:

    .. code-block:: bash

            salt '*' vault_gpg.delete mykey

    Required policy:

    .. code-block::

        path "<mount>/keys/<name>" {
            capabilities = ["delete"]
        }

    name
        The name of the key.

    mount
        The mount path the GPG backend is mounted to. Defaults to ``gpg``.
    """
    endpoint = f"{mount}/keys/{name}"
    try:
        return vault.query("DELETE", endpoint, __opts__, __context__)
    except vault.VaultException as err:
        raise CommandExecutionError(f"{err.__class__}: {err}") from err


def export(name, mount="gpg"):
    """
    Export a configured private key (ASCII-armored).
    Requires the key to be exportable.

    CLI Example:

    .. code-block:: bash

            salt '*' vault_gpg.export mykey

    Required policy:

    .. code-block::

        path "<mount>/export/<name>" {
            capabilities = ["read"]
        }

    name
        The name of the key.

    mount
        The mount path the GPG backend is mounted to. Defaults to ``gpg``.
    """
    endpoint = f"{mount}/export/{name}"
    try:
        return vault.query("GET", endpoint, __opts__, __context__)["data"]["key"]
    except vault.VaultException as err:
        raise CommandExecutionError(f"{err.__class__}: {err}") from err


def update(name, transparency_log_address, mount="gpg"):
    """
    Tune GPG key configuration values. Currently only supports changing
    ``transparency_log_address``.

    CLI Example:

    .. code-block:: bash

            salt '*' vault_gpg.update mykey https://mynewaddr.es/s

    Required policy:

    .. code-block::

        path "<mount>/keys/<name>/config" {
            capabilities = ["create", "update"]  # not sure which one tbh
        }

    name
        The name of the key.

    transparency_log_address
        Specifies the `Rekor transparency log address <https://github.com/sigstore/rekor>`_
        used to publish the signatures.

    mount
        The mount path the GPG backend is mounted to. Defaults to ``gpg``.
    """
    endpoint = f"{mount}/keys/{name}/config"
    payload = {
        "transparency_log_address": transparency_log_address,
    }
    try:
        return vault.query("POST", endpoint, __opts__, __context__, payload=payload)
    except vault.VaultException as err:
        raise CommandExecutionError(f"{err.__class__}: {err}") from err


def sign(name, data, algorithm=None, encoding=None, mount="gpg"):
    """
    Sign data with a configured GPG key.
    Returns the (detached) signature and Rekor transparency log details,
    if configured (dict keys: ``signature`` and ``log_entry`` with ``address`` and ``uuid``).

    CLI Example:

    .. code-block:: bash

            salt '*' vault_gpg.sign mykey data="Hello there"
            salt '*' vault_gpg.sign mykey data=/my/important/file

    Required policy:

    .. code-block::

        path "<mount>/sign/<name>" {
            capabilities = ["create", "update"]  # not sure which one tbh
        }

    name
        The name of the key.

    data
        The data to sign. Can be a path local to the minion this function is run on,
        a string (or a Python bytes type).
        Mind that the data is read into memory, which might be relevant
        if you are signing a very large file.

    algorithm
        Specifies the hash algorithm to use.
        Valid: ``sha2-224``, ``sha2-256``, ``sha2-384``, ``sha2-512``.
        Defaults to ``sha2-256``.

    encoding
        Specifies the encoding format for the returned signature.
        Valid: ``base64``, ``ascii-armor``.
        Defaults to ``base64``.

    mount
        The mount path the GPG backend is mounted to. Defaults to ``gpg``.
    """
    data = _get_file_or_data(data)
    endpoint = f"{mount}/sign/{name}"
    payload = {
        "algorithm": algorithm,
        "format": encoding,
        "input": base64.b64encode(data).decode(),
    }
    payload = {k: v for k, v in payload.items() if v is not None}
    try:
        return vault.query("POST", endpoint, __opts__, __context__, payload=payload)[
            "data"
        ]
    except vault.VaultPermissionDeniedError:
        algorithm = payload.pop("algorithm", "sha2-256")
        endpoint = f"{mount}/sign/{name}/{algorithm}"
        try:
            return vault.query(
                "POST", endpoint, __opts__, __context__, payload=payload
            )["data"]
        except vault.VaultException as err:
            raise CommandExecutionError(f"{err.__class__}: {err}") from err
    except vault.VaultException as err:
        raise CommandExecutionError(f"{err.__class__}: {err}") from err


def verify(name, data, signature, mount="gpg"):
    """
    Verify signed data with a configured GPG key.

    CLI Example:

    .. code-block:: bash

            salt '*' vault_gpg.verify mykey data="Hello there" signature="wsBcBAABCgAQBQJZme..."
            salt '*' vault_gpg.verify mykey data="Hello there" signature="-----BEGIN PGP SIGNATURE..."
            salt '*' vault_gpg.verify mykey data=/my/important/file signature=/my/important/file.asc

    Required policy:

    .. code-block::

        path "<mount>/verify/<name>" {
            capabilities = ["create", "update"]  # not sure which one tbh
        }

    name
        The name of the key.

    data
        The signed data. Can be a path local to the minion this function is run on,
        a string (or a Python bytes type).
        Mind that the data is read into memory, which might be relevant
        if you are verifying a very large file.

    signature
        The (detached) signature. Can be a path local to the minion this function is run on,
        a string (or a Python bytes type).

    mount
        The mount path the GPG backend is mounted to. Defaults to ``gpg``.
    """
    data = _get_file_or_data(data)
    signature = _get_file_or_data(signature)
    try:
        base64.b64decode(signature)
        encoding = "base64"
    except ValueError:
        if not signature.startswith(b"-----BEGIN PGP SIGNATURE-----"):
            raise
        encoding = "ascii-armor"
    endpoint = f"{mount}/verify/{name}"
    payload = {
        "signature": signature.decode(),
        "format": encoding,
        "input": base64.b64encode(data).decode(),
    }
    payload = {k: v for k, v in payload.items() if v is not None}
    try:
        return vault.query("POST", endpoint, __opts__, __context__, payload=payload)[
            "data"
        ]["valid"]
    except vault.VaultException as err:
        raise CommandExecutionError(f"{err.__class__}: {err}") from err
    return False


def decrypt(name, data, signer_key=None, decode=True, decode_utf8=True, mount="gpg"):
    """
    Decrypt data with a configured GPG key.

    CLI Example:

    .. code-block:: bash

            salt '*' vault_gpg.decrypt mykey data="wsBcBAABCgAQBQJZme..."
            salt '*' vault_gpg.decrypt mykey data="-----BEGIN PGP MESSAGE..."
            salt '*' vault_gpg.decrypt mykey data=/my/important/file

    Required policy:

    .. code-block::

        path "<mount>/decrypt/<name>" {
            capabilities = ["create", "update"]  # not sure which one tbh
        }

    name
        The name of the key.

    data
        The ciphertext. Can be a path local to the minion this function is run on,
        a string (or a Python bytes type).
        Mind that the data is read into memory, which might be relevant
        if you are decrypting a very large file.

    signer_key
        The (ASCII-armored) GPG key of the signer.
        Can be a path local to the minion this function is run on,
        a string (or a Python bytes type). If present, the ciphertext must be signed
        and the signature valid, otherwise the decryption will fail.

    decode
        The API endpoint responds with the plaintext encoded in base64.
        Decode the return value using base64. Defaults to true.

    decode_utf8
        When decode is true, also decode the bytes returned by decoding base64
        into a string (using UTF-8). Defaults to true.

    mount
        The mount path the GPG backend is mounted to. Defaults to ``gpg``.
    """
    endpoint = f"{mount}/decrypt/{name}"
    try:
        res = _decrypt_cmd(endpoint=endpoint, data=data, signer_key=signer_key)[
            "plaintext"
        ]
        if not decode:
            return res
        res = base64.b64decode(res)
        if not decode_utf8:
            return res
        return res.decode()
    except vault.VaultException as err:
        raise CommandExecutionError(f"{err.__class__}: {err}") from err


def show_session_key(name, data, signer_key=None, mount="gpg"):
    """
    Decrypt and return the session key of the provided ciphertext using the configured GPG key.

    CLI Example:

    .. code-block:: bash

            salt '*' vault_gpg.show_session_key mykey data="wsBcBAABCgAQBQJZme..."
            salt '*' vault_gpg.show_session_key mykey data="-----BEGIN PGP MESSAGE..."
            salt '*' vault_gpg.show_session_key mykey data=/my/important/file

    Required policy:

    .. code-block::

        path "<mount>/show-session-key/<name>" {
            capabilities = ["create", "update"]  # not sure which one tbh
        }

    name
        The name of the key.

    data
        The ciphertext. Can be a path local to the minion this function is run on,
        a string (or a Python bytes type).
        Mind that the data is read into memory, which might be relevant
        if you are decrypting a very large file.

    signer_key
        The (ASCII-armored) GPG key of the signer.
        Can be a path local to the minion this function is run on,
        a string (or a Python bytes type). If present, the ciphertext must be signed
        and the signature valid, otherwise the decryption will fail.

    mount
        The mount path the GPG backend is mounted to. Defaults to ``gpg``.
    """
    endpoint = f"{mount}/show-session-key/{name}"
    try:
        return _decrypt_cmd(endpoint=endpoint, data=data, signer_key=signer_key)[
            "session_key"
        ]
    except vault.VaultException as err:
        raise CommandExecutionError(f"{err.__class__}: {err}") from err


def _decrypt_cmd(endpoint, data, signer_key):
    """
    The semantics of decrypt and show-session-key are very similar, hence keep this DRY.
    """
    data = _get_file_or_data(data)
    signer_key = _get_file_or_data(signer_key)
    try:
        base64.b64decode(data)
        encoding = "base64"
    except ValueError:
        if not data.startswith(b"-----BEGIN PGP MESSAGE-----"):
            raise
        encoding = "ascii-armor"
    payload = {
        "signer_key": signer_key.decode(),
        "format": encoding,
        "ciphertext": base64.b64encode(data).decode(),
    }
    payload = {k: v for k, v in payload.items() if v is not None}
    try:
        return vault.query("POST", endpoint, __opts__, __context__, payload=payload)[
            "data"
        ]
    except vault.VaultException as err:
        raise CommandExecutionError(f"{err.__class__}: {err}") from err


def _get_file_or_data(data):
    """
    Return file contents as bytes, otherwise encode ciphertext string.
    """
    try:
        if os.path.isfile(data):
            return Path(data).read_bytes()
    except (TypeError, ValueError):
        pass
    try:
        return data.encode()
    except AttributeError:
        pass
    return data
