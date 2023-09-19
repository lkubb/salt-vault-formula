# vim: ft=sls

{#-
    *Meta-state*.

    This installs Vault,
    manages the Vault and system swap configuration
    and then starts the Vault service.
    Also ensures the cluster is initialized if ``vault:init``
    is not false.
#}

{%- set tplroot = tpldir.split("/")[0] %}
{%- from tplroot ~ "/map.jinja" import mapdata as vault with context %}

include:
  - .package
  - .config
  - .cert
  - .service
{%- if vault.init %}
  - .initialize
{%- endif %}
