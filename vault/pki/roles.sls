# -*- coding: utf-8 -*-
# vim: ft=sls

{%- set tplroot = tpldir.split('/')[0] %}
{%- set sls_service_running = tplroot ~ '.service.running' %}
{%- from tplroot ~ "/map.jinja" import mapdata as vault with context %}

include:
  - {{ sls_service_running }}


{%- for role in vault.pki.roles_present %}

Vault role {{ role.name }} is present:
  vault_pki.role_present:
{%-   for var, val in role.items() %}
    - {{ var }}: {{ val }}
{%-   endfor %}
    - require:
      - sls: {{ sls_service_running }}
{%- endfor %}


{%- for role in vault.pki.roles_absent %}

Vault role {{ role.name }} is absent:
  vault_pki.role_absent:
{%-   for var, val in role.items() %}
    - {{ var }}: {{ val }}
{%-   endfor %}
    - require:
      - sls: {{ sls_service_running }}
{%- endfor %}
