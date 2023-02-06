# vim: ft=sls

{#-
    Removes the Vault configuration only and has a
    dependency on `vault.service.clean`_.
#}

{%- set tplroot = tpldir.split("/")[0] %}
{%- set sls_service_clean = tplroot ~ ".service.clean" %}
{%- from tplroot ~ "/map.jinja" import mapdata as vault with context %}

include:
  - {{ sls_service_clean }}

Vault configuration is absent:
  file.absent:
    - name: {{ vault.lookup.config }}
    - require:
      - sls: {{ sls_service_clean }}
