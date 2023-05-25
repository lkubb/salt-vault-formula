"""
Manage Vault plugins.

This should be in the main ``vault`` module probably,
but for ease of maintenance it is currently separate.
"""

import logging

import salt.utils.versions
import vaultutil as vault
from salt.exceptions import (CommandExecutionError, SaltException,
                             SaltInvocationError)

log = logging.getLogger(__name__)
__func_alias__ = {"list_": "list"}


def list_(plugin_type):
    """
    List all registered plugins of a specific type.

    .. note::

        Though undocumented, this might require ``sudo`` capability.

    CLI Example:

    .. code-block:: bash

        salt '*' vault_plugin.list auth

    Required policy:

    .. code-block:: vaultpolicy

        path "sys/plugins/catalog/<plugin_type>" {
            capabilities = ["list", "sudo"]
        }

    plugin_type
        The plugin type to list. Either ``auth``, ``database`` or ``secret``.
    """
    _check_type(plugin_type)
    endpoint = f"sys/plugins/catalog/{plugin_type}"

    try:
        return vault.query("LIST", endpoint, __opts__, __context__)["data"]["keys"]
    except SaltException as err:
        raise CommandExecutionError("{}: {}".format(type(err).__name__, err)) from err


def list_all():
    """
    Show all registered plugins, including detailed information.

    CLI Example:

    .. code-block:: bash

        salt '*' vault_plugin.list_all

    Required policy:

    .. code-block:: vaultpolicy

        path "sys/plugins/catalog" {
            capabilities = ["read"]
        }
    """
    try:
        return vault.query("GET", "sys/plugins/catalog", __opts__, __context__)["data"]
    except SaltException as err:
        raise CommandExecutionError("{}: {}".format(type(err).__name__, err)) from err


def show(plugin_type, plugin_name, filter_sha=None, filter_version=None):
    """
    Show information about a specific plugin.

    CLI Example:

    .. code-block:: bash

        salt '*' vault_plugin.show database mysql-database-plugin

    Required policy:

    .. code-block:: vaultpolicy

        path "sys/plugins/catalog/<plugin_type>/<plugin_name>" {
            capabilities = ["read", "sudo"]
        }

    plugin_type
        The type of the plugin to show. Either ``auth``, ``database`` or ``secret``.

    plugin_name
        The name of the plugin to show.

    filter_sha
        The registered SHA256 hash of the plugin to filter for. Optional.
        This might be necessary to account for the detailed endpoints not
        listing versioned plugins.

    filter_version
        The registered plugin version to filter for. Optional.
        This might be necessary to account for the detailed endpoints not
        listing versioned plugins.

    strict
        Only return results matching the filters exactly. Defaults to true.
        If false, will return other plugin versions or hashes in case the
        queried one is not available. By default, tries to return the
        highest version available.
    """
    _check_type(plugin_type)
    if filter_version:
        filter_version = filter_version.lstrip("v")
    try:
        plugin = vault.query(
            "GET",
            f"sys/plugins/catalog/{plugin_type}/{plugin_name}",
            __opts__,
            __context__,
        )["data"]
        if (filter_sha and plugin["sha256"] != filter_sha) or (
            filter_version and plugin["version"].lstrip("v") != filter_version
        ):
            raise vault.VaultNotFoundError()
        return plugin
    except vault.VaultNotFoundError:
        # versioned plugins are not listed in the type-specific endpoints
        try:
            plugins = list_all()
            matches = []
            for plugin in plugins["detailed"]:
                if plugin["name"] == plugin_name and plugin["type"] == plugin_type:
                    matches.append(plugin)
            if matches:
                best = None
                # Filter for the best-matching or highest version to return
                for plugin in matches:
                    if plugin["sha256"] == filter_sha:
                        best = plugin
                        break
                    if best is None:
                        best = plugin
                        continue
                    if not filter_version:
                        pass
                    elif plugin["version"].lstrip("v") == filter_version:
                        if best["version"].lstrip("v") != filter_version:
                            best = plugin
                        continue
                    elif best["version"].lstrip("v") == filter_version:
                        continue
                    curr_version = (
                        plugin["version"].split("+", maxsplit=1)[0].lstrip("v")
                    )
                    best_version = best["version"].split("+", maxsplit=1)[0].lstrip("v")
                    if not curr_version:
                        continue
                    if not best_version:
                        best = plugin
                        continue
                    if salt.utils.versions.version_cmp(curr_version, best_version) > 0:
                        best = plugin
                # This endpoint does not behave the same way as the specific one,
                # so emulate it. It's not ideal.
                if "args" not in best:
                    best["args"] = []
                if "command" not in best:
                    best["command"] = best["name"]
                    return best
            raise vault.VaultNotFoundError()
        except SaltException as err:
            raise CommandExecutionError(
                "{}: {}".format(type(err).__name__, err)
            ) from err
    except SaltException as err:
        raise CommandExecutionError("{}: {}".format(type(err).__name__, err)) from err


def is_registered(plugin_type, plugin_name, sha256=None):
    """
    Check whether a plugin with a given name, and optionally
    sha256 hexdigest, is registered.

    CLI Example:

    .. code-block:: bash

        salt '*' vault_plugin.is_registered database mysql-database-plugin

    Required policy: see ``list`` and ``show``.

    plugin_type
        The type of the plugin to show. Either ``auth``, ``database`` or ``secret``.

    plugin_name
        The name of the plugin to show.

    sha256
        The registered hash of the plugin. Optional.
    """
    _check_type(plugin_type)
    if plugin_name not in list_(plugin_type):
        return False
    if sha256 is None:
        return True
    return show(plugin_type, plugin_name)["sha256"] == sha256


def register(
    plugin_type, plugin_name, sha256, command=None, args=None, env=None, version=None
):
    """
    Register a plugin.

    CLI Example:

    .. code-block:: bash

        salt '*' vault_plugin.register database mymysql-database-plugin deadbeefcafebabe...

    Required policy:

    .. code-block:: vaultpolicy

        path "sys/plugins/catalog/<plugin_type>/<plugin_name>" {
            capabilities = ["create", "update", "sudo"]
        }

    plugin_type
        The type of the plugin to show. Either ``auth``, ``database`` or ``secret``.

    plugin_name
        The name of the plugin to show.

    sha256
        The sha256 hexdigest of the binary.

    command
        Specifies the command used to execute the plugin. This is relative to the plugin directory.
        If unspecified, defaults to the plugin_name.

    args
        List of arguments used to execute the plugin. Optional.

    env
        List of environment variables used during the execution of the plugin.
        Each entry is of the form "key=value".

    version
        Specifies the semantic version of this plugin.
    """
    _check_type(plugin_type)
    if command is None:
        command = plugin_name

    payload = {
        "command": command,
        "sha256": sha256,
    }

    if version is not None:
        payload["version"] = version
    if args is not None:
        payload["args"] = args
    if env is not None:
        payload["env"] = env
    try:
        vault.query(
            "POST",
            f"sys/plugins/catalog/{plugin_type}/{plugin_name}",
            __opts__,
            __context__,
            payload=payload,
        )
        return True
    except SaltException as err:
        raise CommandExecutionError("{}: {}".format(type(err).__name__, err)) from err


def deregister(plugin_type, plugin_name, version=None):
    """
    Deregister a plugin.

    CLI Example:

    .. code-block:: bash

        salt '*' vault_plugin.deregister database mymysql-database-plugin

    Required policy:

    .. code-block:: vaultpolicy

        path "sys/plugins/catalog/<plugin_type>/<plugin_name>" {
            capabilities = ["delete", "sudo"]
        }

    plugin_type
        The type of the plugin to show. Either ``auth``, ``database`` or ``secret``.

    plugin_name
        The name of the plugin to show.

    version
        Specifies the semantic version of the plugin to delete.
    """
    _check_type(plugin_type)
    endpoint = f"sys/plugins/catalog/{plugin_type}/{plugin_name}"
    if version is not None:
        endpoint += f"?version={version}"
    try:
        vault.query("DELETE", endpoint, __opts__, __context__)
        return True
    except SaltException as err:
        raise CommandExecutionError("{}: {}".format(type(err).__name__, err)) from err


def reload(plugin_name=None, mounts=None, globally=False):
    """
    Reload mounted plugin backends.

    CLI Example:

    .. code-block:: bash

        salt '*' vault_plugin.reload elasticsearch-database-plugin
        salt '*' vault_plugin.reload mounts='[database]'

    Required policy:

    .. code-block:: vaultpolicy

        path "sys/plugins/reload/backend" {
            capabilities = ["update"]
        }

    plugin_name
        The name of the plugin to reload, as registered in the plugin catalog.

    mounts
        List of mount paths of the plugin backends to reload.

    globally
        By default, this reloads the plugin or mounts on this Vault instance.
        If true, will begin reloading the plugin on all instances of a cluster.
    """
    if not (plugin_name or mounts):
        raise SaltInvocationError("Either plugin_name or mounts is required")
    endpoint = "sys/plugins/reload/backend"
    payload = {}
    if plugin_name:
        payload["plugin"] = plugin_name
    if mounts:
        if not isinstance(mounts, list):
            mounts = [mounts]
        payload["mounts"] = mounts
    if globally:
        payload["scope"] = "global"
    try:
        vault.query("POST", endpoint, __opts__, __context__, payload=payload)
        return True
    except SaltException as err:
        raise CommandExecutionError("{}: {}".format(type(err).__name__, err)) from err


def _check_type(plugin_type):
    if plugin_type not in ["auth", "database", "secret"]:
        raise SaltInvocationError(f"Invalid plugin type: {plugin_type}")
