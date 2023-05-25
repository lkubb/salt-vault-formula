"""
Manage Vault plugins.

This should be in the main ``vault`` module probably,
but for ease of maintenance it is currently separate.
"""

import logging

from salt.exceptions import CommandExecutionError, SaltInvocationError

log = logging.getLogger(__name__)


def registered(
    name, plugin_type, sha256, version=None, command=None, args=None, env=None
):
    """
    Ensure a plugin is registered as specified.

    name
        The name of the plugin to manage.

    plugin_type
        The type of the plugin to manage. Either ``auth``, ``database`` or ``secret``.

    sha256
        The sha256 hexdigest of the binary.

    version
        The plugin version. Will only be written on changes.

    command
        Specifies the command used to execute the plugin. This is relative to the plugin directory.
        If unspecified, defaults to the plugin_name.

    args
        List of arguments used to execute the plugin. Optional.

    env
        List of environment variables used during the execution of the plugin.
        Each entry is of the form "key=value".
    """
    ret = {"name": name, "result": True, "comment": "", "changes": {}}

    try:
        changes = {}
        try:
            # Filtering for the sha and version is a workaround for the Vault API
            # currently being suboptimal regarding versioned plugins – they are not listed
            # in the type-specific endpoints.
            current = __salt__["vault_plugin.show"](
                plugin_type, name, filter_sha=sha256, filter_version=version
            )
            if current["sha256"] != sha256:
                changes["hash"] = {"old": current["sha256"], "new": sha256}
            if command is not None and current["command"] != command:
                changes["command"] = {"old": current["command"], "new": command}
            if args is not None and current["args"] != args:
                changes["args"] = {"old": current["args"], "new": args}
            if env is not None and current["env"] != env:
                changes["env"] = {"old": current["env"], "new": env}
        except CommandExecutionError as err:
            if "VaultNotFoundError" not in str(err):
                raise
            current = None
            changes["registered"] = name

        if current and not changes:
            ret["comment"] = "Plugin is registered as specified"
            return ret

        if __opts__["test"]:
            ret["result"] = None
            ret["changes"] = changes
            if current:
                ret["comment"] = "The plugin definition would have been updated"
            else:
                ret["comment"] = "The plugin would have been registered"
            return ret

        __salt__["vault_plugin.register"](
            plugin_type=plugin_type,
            plugin_name=name,
            sha256=sha256,
            command=command,
            args=args,
            env=env,
            version=version,
        )
        if current:
            ret["comment"] = "The plugin definition has been updated"
        else:
            ret["comment"] = "The plugin has been registered"
        ret["changes"] = changes
    except (CommandExecutionError, SaltInvocationError) as err:
        ret["result"] = False
        ret["comment"] = str(err)

    return ret


def unregistered(name, plugin_type):
    """
    Ensure a plugin is not registered.

    name
        The name of the plugin to manage.

    plugin_type
        The type of the plugin to manage. Either ``auth``, ``database`` or ``secret``.
    """
    ret = {"name": name, "result": True, "comment": "", "changes": {}}

    try:
        try:
            __salt__["vault_plugin.show"](plugin_type, name)
        except CommandExecutionError as err:
            if "VaultNotFoundError" not in str(err):
                raise
            ret["comment"] = "The plugin is already unregistered"
            return ret

        if __opts__["test"]:
            ret["result"] = None
            ret["changes"]["deregistered"] = name
            ret["comment"] = "The plugin would have been deregistered"
            return ret

        __salt__["vault_plugin.deregister"](plugin_type=plugin_type, plugin_name=name)
        ret["comment"] = "The plugin has been deregistered"
        ret["changes"]["deregistered"] = name
    except (CommandExecutionError, SaltInvocationError) as err:
        ret["result"] = False
        ret["comment"] = str(err)

    return ret
