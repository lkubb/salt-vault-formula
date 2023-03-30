# vim: ft=sls

{#-
    *Meta-state*.

    This installs Vault,
    manages the Vault and system swap configuration
    and then starts the Vault service.
    Also ensures the cluster is initialized.
#}

include:
  - .package
  - .config
  - .service
  - .initialize
