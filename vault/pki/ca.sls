# vim: ft=sls

{#-
    Manages intermediate CAs on PKI backend mounts.
#}

{%- set tplroot = tpldir.split("/")[0] %}
{%- set sls_service_running = tplroot ~ ".service.running" %}
{%- from tplroot ~ "/map.jinja" import mapdata as vault with context %}

include:
  - {{ sls_service_running }}


{%- for ca in vault.pki.ca %}

Vault intermediate CA is present on {{ ca.get("mount", "pki") }}:
  vault_pki.intermediate_ca:
{%-   for var, val in ca.items() %}
    - {{ var }}: {{ val }}
{%-   endfor %}
    - require:
      - sls: {{ sls_service_running }}
{%- endfor %}
