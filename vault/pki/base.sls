# -*- coding: utf-8 -*-
# vim: ft=sls

{%- set tplroot = tpldir.split('/')[0] %}
{%- set sls_service_running = tplroot ~ '.service.running' %}
{%- from tplroot ~ "/map.jinja" import mapdata as vault with context %}

include:
  - {{ sls_service_running }}


{%- for mount in vault.pki.urls %}

Vault PKI mount URLs are managed for mount {{ mount.get("mount", "pki") }}:
  vault_pki.urls_set:
{%-   for var, val in mount.items() %}
    - {{ var }}: {{ val }}
{%-   endfor %}
    - require:
      - sls: {{ sls_service_running }}
{%- endfor %}
