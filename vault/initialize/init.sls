# -*- coding: utf-8 -*-
# vim: ft=sls

{%- set tplroot = tpldir.split('/')[0] %}
{%- set sls_service_running = tplroot ~ '.service.running' %}
{%- from tplroot ~ "/map.jinja" import mapdata as vault with context %}

include:
  - {{ sls_service_running }}

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
