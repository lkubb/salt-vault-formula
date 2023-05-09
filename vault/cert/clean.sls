# vim: ft=sls

{#-
    Removes generated Vault TLS certificate + key.
    Depends on `vault.service.clean`_.
#}

{%- set tplroot = tpldir.split("/")[0] %}
{%- set sls_service_clean = tplroot ~ ".service.clean" %}
{%- from tplroot ~ "/map.jinja" import mapdata as vault with context %}

include:
  - {{ sls_service_clean }}

{%- if vault.cert %}

Vault key/cert is absent:
  file.absent:
    - names:
      - {{ vault.cert.path_key }}
      - {{ vault.cert.path_cert }}
    - require:
      - sls: {{ sls_service_clean }}
{%- endif %}
