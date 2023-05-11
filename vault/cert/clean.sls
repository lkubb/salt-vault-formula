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
      - {{ vault.lookup.paths.api_key }}
      - {{ vault.lookup.paths.api_cert }}
      - {{ vault.lookup.paths.client_key }}
      - {{ vault.lookup.paths.client_cert }}
      - {{ vault.lookup.paths.ca_cert }}
    - require:
      - sls: {{ sls_service_clean }}
{%- endif %}
