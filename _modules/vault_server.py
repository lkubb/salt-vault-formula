"""
Custom execution module for managing a Hashicorp Vault server.
This is intended to complement the official module.
"""

from pathlib import Path

import salt.utils.path
from salt.exceptions import CommandExecutionError, SaltInvocationError

__virtualname__ = "vault_server"


def __virtual__():
    if salt.utils.path.which("vault"):
        return True
    return (False, "Could not find vault executable in $PATH.")


def _vault(
    command,
    args=None,
    options=None,
    runas=None,
    cwd=None,
    json=True,
    raise_error=True,
    expect_error=False,
    output_loglevel=None,
    env=None,
    vault_addr="https://127.0.0.1:8200",
):
    """
    Generic helper for calling vault-cli. Does not rely on HVAC
    python lib to avoid introducing another dependency.
    """

    command = [command] if not isinstance(command, list) else command
    args = args or []
    options = options or []
    env = env or {}

    env["VAULT_ADDR"] = vault_addr
    options.append(("non-interactive", True))

    if json:
        options.append(("format", "json"))

    options = _parse_args(options, include_equal=True)
    cmd = ["vault"] + command + options

    if args is not None:
        cmd += ["--"] + args

    out = __salt__["cmd.run_all"](
        " ".join(cmd),
        cwd=cwd,
        env=env,
        runas=runas,
        ignore_retcode=expect_error,
        output_loglevel=output_loglevel,
    )

    if not expect_error and raise_error and out["retcode"]:
        raise CommandExecutionError(
            "Failed running vault {}.\nstderr: {}\nstdout: {}".format(
                " ".join(command), out["stderr"], out["stdout"]
            )
        )

    if not out["retcode"] and json:
        out["parsed"] = salt.utils.json.loads(out["stdout"])
    return out


def _parse_args(args, include_equal=True):
    """
    Helper for parsing lists of arguments into a flat list.
    """
    tpl = "--{}={}" if include_equal else "--{} {}"
    return [
        tpl.format(*arg) if isinstance(arg, tuple) else "--{}".format(arg)
        for arg in args
    ]


def is_initialized(vault_addr="https://127.0.0.1:8200"):
    # exit code: 0=yes 1=error 2=no
    out = _vault("status", env=env, expect_error=True, vault_addr=vault_addr)
    return out["retcode"] == 0


def initialize(
    key_shares,
    key_threshold,
    pgp_keys=None,
    root_token_pgp_key=None,
    rekey=False,
    vault_addr="https://127.0.0.1:8200",
):
    options = [
        ("key-shares", key_shares),
        ("key-threshold", key_threshold),
    ]

    cmd = ["operator"]
    cmd.append("rekey -init" if rekey else "init")

    pgp_keys_tmp = []

    if pgp_keys:
        pgp_keys = [pgp_keys] if not isinstance(pgp_keys, list) else pgp_keys
        pgp_keys_parsed = []

        for key in pgp_keys:
            if key.startswith("-----BEGIN PGP PUBLIC KEY BLOCK-----"):
                tmp = __salt__["temp.file"]()
                __salt__["file.write"](tmp, key)
                pgp_keys_tmp.append(tmp)
                key = tmp
            pgp_keys_parsed.append(key)

        options.append(("pgp-keys", ",".join(pgp_keys_parsed)))

    if not rekey and root_token_pgp_key:
        if root_token_pgp_key.startswith("-----BEGIN PGP PUBLIC KEY BLOCK-----"):
            tmp = __salt__["temp.file"]()
            __salt__["file.write"](tmp, root_token_pgp_key)
            pgp_keys_tmp.append(tmp)
            root_token_pgp_key = tmp
        options.append(("root-token-pgp-key", root_token_pgp_key))

    out = _vault(
        cmd, options=options, env=env, output_loglevel="quiet", vault_addr=vault_addr
    )

    if pgp_keys_tmp:
        for tmp in pgp_keys_tmp:
            __salt__["file.remove"](tmp)
    return out["parsed"]

    # Example output:
    # {
    #   "unseal_keys_b64": [
    #     "nxURLn+RvN6KVr01U7vUuGkotIZCcq9VmBe3k2T5QTc="
    #   ],
    #   "unseal_keys_hex": [
    #     "9f15112e7f91bcde8a56bd3553bbd4b86928b4864272af559817b79364f94137"
    #   ],
    #   "unseal_shares": 1,
    #   "unseal_threshold": 1,
    #   "recovery_keys_b64": [],
    #   "recovery_keys_hex": [],
    #   "recovery_keys_shares": 5,
    #   "recovery_keys_threshold": 3,
    #   "root_token": "hvs.hSdvta7Qk9Y19ZauIBas2sSa"
    # }
