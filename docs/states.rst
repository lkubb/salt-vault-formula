Available states
----------------

The following states are found in this formula:

.. contents::
   :local:


``vault``
^^^^^^^^^
*Meta-state*.

This installs Vault,
manages the Vault and system swap configuration
and then starts the Vault service.
Also ensures the cluster is initialized if ``vault:init``
is not false.


``vault.package``
^^^^^^^^^^^^^^^^^
Installs Vault (+ necessary service unit overrides) only.


``vault.package.repo``
^^^^^^^^^^^^^^^^^^^^^^
This state will install the configured vault repository.
This works for apt/dnf/yum/zypper-based distributions only by default.


``vault.config``
^^^^^^^^^^^^^^^^
Ensures the system and Vault is configured as specified.


``vault.config.file``
^^^^^^^^^^^^^^^^^^^^^
Manages the Vault configuration.
Has a dependency on `vault.package`_.


``vault.config.system``
^^^^^^^^^^^^^^^^^^^^^^^
Manages system settings required for Vault: disable swap.
Includes `vault.package`_.


``vault.cert``
^^^^^^^^^^^^^^
Generates a TLS certificate + key for Vault.
Depends on `vault.package`_.


``vault.service``
^^^^^^^^^^^^^^^^^
Starts the vault service and enables it at boot time.
Has a dependency on `vault.config`_.


``vault.initialize``
^^^^^^^^^^^^^^^^^^^^
Ensures a running Vault cluster has been initialized.
Will output key shares and initial root token to file paths.
**Ensure you provide the correct GPG keys in order to encrypt
the output.**


``vault.database``
^^^^^^^^^^^^^^^^^^
Manages database connections and their roles.


``vault.pki``
^^^^^^^^^^^^^



``vault.pki.base``
^^^^^^^^^^^^^^^^^^
Manages PKI backend URL endpoints.


``vault.pki.ca``
^^^^^^^^^^^^^^^^
Manages intermediate CAs on PKI backend mounts.


``vault.pki.roles``
^^^^^^^^^^^^^^^^^^^
Manages present and absent roles on configured PKI mounts.


``vault.plugins``
^^^^^^^^^^^^^^^^^
Manages present/absent custom plugins.
For present ones, pulls binaries from a URI and registers them.


``vault.ssh``
^^^^^^^^^^^^^
Manages SSH secret backend roles and, if required, CAs.


``vault.ssh.ca``
^^^^^^^^^^^^^^^^



``vault.ssh.roles``
^^^^^^^^^^^^^^^^^^^



``vault.clean``
^^^^^^^^^^^^^^^
*Meta-state*.

Undoes everything performed in the ``vault`` meta-state
in reverse order, i.e.
stops the service,
removes the configuration file and then
uninstalls the package.


``vault.package.clean``
^^^^^^^^^^^^^^^^^^^^^^^
Removes Vault and service unit overrides.
Has a dependency on `vault.config.clean`_.


``vault.package.repo.clean``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^
This state will remove the configured vault repository.
This works for apt/dnf/yum/zypper-based distributions only by default.


``vault.config.clean``
^^^^^^^^^^^^^^^^^^^^^^
Removes the Vault configuration only and has a
dependency on `vault.service.clean`_.


``vault.cert.clean``
^^^^^^^^^^^^^^^^^^^^
Removes generated Vault TLS certificate + key.
Depends on `vault.service.clean`_.


``vault.service.clean``
^^^^^^^^^^^^^^^^^^^^^^^
Stops the vault service and disables it at boot time.


``vault.database.clean``
^^^^^^^^^^^^^^^^^^^^^^^^
Removes managed database connections and their roles.
Requires ``remove_all_data_for_sure`` to be set to true
to prevent accidental damage.


``vault.pki.clean``
^^^^^^^^^^^^^^^^^^^
Does nothing at the moment.


``vault.plugins.clean``
^^^^^^^^^^^^^^^^^^^^^^^



``vault.ssh.clean``
^^^^^^^^^^^^^^^^^^^
Removes managed SSH roles and SSH CAs.
For CAs, requires ``remove_all_data_for_sure`` to be set to true
to prevent accidental damage.


