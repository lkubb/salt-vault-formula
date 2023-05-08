# vim: ft=sls

{#-
    Ensures a running Vault cluster has been initialized.
    Will output key shares and initial root token to file paths.
    **Ensure you provide the correct GPG keys in order to encrypt
    the output.**
#}

{%- set tplroot = tpldir.split("/")[0] %}
{%- set sls_service_running = tplroot ~ ".service.running" %}
{%- from tplroot ~ "/map.jinja" import mapdata as vault with context %}

include:
  - {{ sls_service_running }}

{%- if vault.init %}

Vault server has been initialized:
  vault_server.initialized:
    - output: {{ vault.init.output }}
    - key_shares: {{ vault.init.key_shares }}
    - key_threshold: {{ vault.init.key_threshold }}
    - pgp_keys: {{ vault.init.pgp_keys | json }}
    - root_token_pgp_key: {{ vault.init.root_token_pgp_key | json }}
    - vault_addr: {{ vault.init.vault_addr or vault.config.api_addr }}
    - require:
      - sls: {{ sls_service_running }}
{%- endif %}
