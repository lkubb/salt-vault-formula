# vim: ft=sls

{#-
    *Meta-state*.

    This installs Vault,
    manages the Vault and system swap configuration
    and then starts the Vault service.
    Also ensures the cluster is initialized if ``vault:init``
    is not false.
#}

include:
  - .package
  - .config
  - .service
{%- if vault.init %}
  - .initialize
{%- endif %}
