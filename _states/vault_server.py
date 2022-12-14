"""
Custom state module for managing a Hashicorp Vault server.
This is intended to complement the official module.
"""

from salt.exceptions import CommandExecutionError, SaltInvocationError


def initialized(
    name,
    output,
    key_shares,
    key_threshold,
    pgp_keys=None,
    root_token_pgp_key=None,
    vault_addr="https://127.0.0.1:8200",
):
    """
    Make sure Vault is initialized.

    name
        Not used.

    output
        Specify a directory where to put the unseal keys and
        the root token that was generated. It is highly advised
        to supply pgp_keys and root_token_pgp_key to ensure
        the data is not compromised.

    key_shares
        Number of key shares to split the generated root key into.

    key_threshold
        Number of key shares required to reconstruct the root key.
        This must be less than or equal to key_shares.

    pgp_keys
        List of PGP public keys to use to encrypt the key shards. The
        number of entries must match key_shares.
        Either a list of files on disk/armored public keys or
        a list of Keybase usernames, each one formatted as ``keybase:<username>``.
        When supplied, the generated unseal keys will be encrypted and
        base64-encoded in the order specified in this list.

    root_token_pgp_key
        Path to a file on disk or an armored public key to use to encrypt the
        initial root token with. Can also be a Keybase username, formatted as
        ``keybase:<username>``. When supplied, the generated root token will be
        encrypted and base64-encoded with the given public key.

    vault_addr
        URL of the Vault API endpoint. Defaults to "https://127.0.0.1:8200".
    """

    ret = {"name": name, "result": True, "comment": "", "changes": {}}

    try:
        if __salt__["vault_server.is_initialized"](vault_addr):
            ret["comment"] = "Vault server is already initialized."
            return ret

        ret["changes"] = {"initialized": vault_addr}

        if __opts__["test"]:
            ret["result"] = None
            ret["comment"] = "Vault server would have been initialized."
            return ret

        ret["comment"] = "Vault server has been initialized."

        out = __salt__["vault_server.initialize"](
            key_shares=key_shares,
            key_threshold=key_threshold,
            pgp_keys=pgp_keys,
            root_token_pgp_key=root_token_pgp_key,
            vault_addr=vault_addr,
        )

        __salt__["file.mkdir"](output, mode="0700")

        def write_secret(path, secret):
            __salt__["file.touch"](path)
            __salt__["file.set_mode"](path, "0600")
            __salt__["file.write"](path, secret)

        for i, key in enumerate(out["unseal_keys_b64"]):
            write_secret(__salt__["file.join"](output, f"unseal_key_{i}"), key)
        write_secret(__salt__["file.join"](output, "root_token"), out["root_token"])

    except (CommandExecutionError, SaltInvocationError) as e:
        ret["result"] = False
        ret["comment"] = str(e)
        ret["changes"] = {}
        return ret

    return ret
