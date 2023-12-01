.. _readme:

Vault Formula
=============

|img_sr| |img_pc|

.. |img_sr| image:: https://img.shields.io/badge/%20%20%F0%9F%93%A6%F0%9F%9A%80-semantic--release-e10079.svg
   :alt: Semantic Release
   :scale: 100%
   :target: https://github.com/semantic-release/semantic-release
.. |img_pc| image:: https://img.shields.io/badge/pre--commit-enabled-brightgreen?logo=pre-commit&logoColor=white
   :alt: pre-commit
   :scale: 100%
   :target: https://github.com/pre-commit/pre-commit

Manage Hashicorp Vault with Salt.

This formula contains several custom modules. The ``vault`` modules should be backwards-compatible with the ones currently found in Salt and might become available there at some point. For details, see `#62684 <https://github.com/saltstack/salt/pull/62684>`_ and `#63314 <https://github.com/saltstack/salt/pull/63314>`_.

.. contents:: **Table of Contents**
   :depth: 1

General notes
-------------

See the full `SaltStack Formulas installation and usage instructions
<https://docs.saltstack.com/en/latest/topics/development/conventions/formulas.html>`_.

If you are interested in writing or contributing to formulas, please pay attention to the `Writing Formula Section
<https://docs.saltstack.com/en/latest/topics/development/conventions/formulas.html#writing-formulas>`_.

If you want to use this formula, please pay attention to the ``FORMULA`` file and/or ``git tag``,
which contains the currently released version. This formula is versioned according to `Semantic Versioning <http://semver.org/>`_.

See `Formula Versioning Section <https://docs.saltstack.com/en/latest/topics/development/conventions/formulas.html#versioning>`_ for more details.

If you need (non-default) configuration, please refer to:

- `how to configure the formula with map.jinja <map.jinja.rst>`_
- the ``pillar.example`` file
- the `Special notes`_ section

Special notes
-------------


Configuration
-------------
An example pillar is provided, please see `pillar.example`. Note that you do not need to specify everything by pillar. Often, it's much easier and less resource-heavy to use the ``parameters/<grain>/<value>.yaml`` files for non-sensitive settings. The underlying logic is explained in `map.jinja`.


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


``vault.leases``
^^^^^^^^^^^^^^^^
Manages cached leases and associated beacons.


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


``vault.secrets``
^^^^^^^^^^^^^^^^^
Manages Vault KV secrets.


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


``vault.leases.clean``
^^^^^^^^^^^^^^^^^^^^^^
Removes managed leases.


``vault.pki.clean``
^^^^^^^^^^^^^^^^^^^
Does nothing at the moment.


``vault.plugins.clean``
^^^^^^^^^^^^^^^^^^^^^^^



``vault.secrets.clean``
^^^^^^^^^^^^^^^^^^^^^^^
Removes managed secrets.


``vault.ssh.clean``
^^^^^^^^^^^^^^^^^^^
Removes managed SSH roles and SSH CAs.
For CAs, requires ``remove_all_data_for_sure`` to be set to true
to prevent accidental damage.



Contributing to this repo
-------------------------

Commit messages
^^^^^^^^^^^^^^^

**Commit message formatting is significant!**

Please see `How to contribute <https://github.com/saltstack-formulas/.github/blob/master/CONTRIBUTING.rst>`_ for more details.

pre-commit
^^^^^^^^^^

`pre-commit <https://pre-commit.com/>`_ is configured for this formula, which you may optionally use to ease the steps involved in submitting your changes.
First install  the ``pre-commit`` package manager using the appropriate `method <https://pre-commit.com/#installation>`_, then run ``bin/install-hooks`` and
now ``pre-commit`` will run automatically on each ``git commit``. ::

  $ bin/install-hooks
  pre-commit installed at .git/hooks/pre-commit
  pre-commit installed at .git/hooks/commit-msg

State documentation
~~~~~~~~~~~~~~~~~~~
There is a script that semi-autodocuments available states: ``bin/slsdoc``.

If a ``.sls`` file begins with a Jinja comment, it will dump that into the docs. It can be configured differently depending on the formula. See the script source code for details currently.

This means if you feel a state should be documented, make sure to write a comment explaining it.

Testing
-------

Linux testing is done with ``kitchen-salt``.

Requirements
^^^^^^^^^^^^

* Ruby
* Docker

.. code-block:: bash

   $ gem install bundler
   $ bundle install
   $ bin/kitchen test [platform]

Where ``[platform]`` is the platform name defined in ``kitchen.yml``,
e.g. ``debian-9-2019-2-py3``.

``bin/kitchen converge``
^^^^^^^^^^^^^^^^^^^^^^^^

Creates the docker instance and runs the ``vault`` main state, ready for testing.

``bin/kitchen verify``
^^^^^^^^^^^^^^^^^^^^^^

Runs the ``inspec`` tests on the actual instance.

``bin/kitchen destroy``
^^^^^^^^^^^^^^^^^^^^^^^

Removes the docker instance.

``bin/kitchen test``
^^^^^^^^^^^^^^^^^^^^

Runs all of the stages above in one go: i.e. ``destroy`` + ``converge`` + ``verify`` + ``destroy``.

``bin/kitchen login``
^^^^^^^^^^^^^^^^^^^^^

Gives you SSH access to the instance for manual testing.
