# vim: ft=sls

{#-
    *Meta-state*.

    This installs the vault package,
    manages the vault configuration file
    and then starts the associated vault service.
    Also ensures the cluster is initialized.
#}

include:
  - .package
  - .config
  - .service
  - .initialize
