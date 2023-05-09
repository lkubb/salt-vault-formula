# vim: ft=sls

{#-
    Generates a TLS certificate + key for Vault.
    Depends on `vault.package`_.
#}

include:
  - .managed
