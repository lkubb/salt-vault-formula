"""
Interface with the `Vault GPG secret engine <https://github.com/LeSuisse/vault-gpg-plugin/tree/main>`_.

Configuration instructions are documented in the :ref:`vault execution module docs <vault-setup>`.
"""

import logging

from salt.exceptions import CommandExecutionError

log = logging.getLogger(__name__)


def keychain_present(name, user=None, gnupghome=None, keyring=None, mount="gpg"):
    """
    Ensure the named GPG key has been imported in the specified GPG keychain.
    This is wraps ``gpg.import_key``, hence requires ``python-gnupg``.

    name
        The name of the key.

    user
        Which user's keychain to access, defaults to user Salt is running as.
        Passing the user as ``salt`` will set the GnuPG home directory to
        ``/etc/salt/gpgkeys``.

    gnupghome
        Specify the location where the GPG keyring and related files are stored.

    keyring
        Limit the operation to this specific keyring, specified as
        a local filesystem path.

    mount
        The mount path the GPG backend is mounted to. Defaults to ``gpg``.
    """
    ret = {
        "name": name,
        "result": True,
        "comment": "The keychain is in the correct state",
        "changes": {},
    }

    try:
        key = __salt__["vault_gpg.read"](name, mount=mount)
        fp = key["fingerprint"].upper()
        if __salt__["gpg.get_key"](
            fingerprint=fp, user=user, gnupghome=gnupghome, keyring=keyring
        ):
            return ret
        ret["changes"]["imported"] = fp
        if __opts__["test"]:
            ret["result"] = None
            ret["comment"] = f"The named key {name} would have been imported"
            return ret
        __salt__["gpg.import_key"](
            text=key["public_key"], user=user, gnupghome=gnupghome, keyring=keyring
        )
        if not __salt__["gpg.get_key"](
            fingerprint=fp, user=user, gnupghome=gnupghome, keyring=keyring
        ):
            raise CommandExecutionError(
                "No errors were detected, but the key is still not present"
            )
        ret["comment"] = f"The named key {name} has been imported"
    except CommandExecutionError as err:
        ret["result"] = False
        ret["comment"] = str(err)
        ret["changes"] = {}
    return ret
