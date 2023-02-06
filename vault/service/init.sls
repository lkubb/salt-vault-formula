# vim: ft=sls

{#-
    Starts the vault service and enables it at boot time.
    Has a dependency on `vault.config`_.
#}

include:
  - .running
