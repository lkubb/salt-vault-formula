# vim: ft=sls

{#-
    Removes Vault and service unit overrides.
    Has a dependency on `vault.config.clean`_.
#}

{%- set tplroot = tpldir.split("/")[0] %}
{%- set sls_config_clean = tplroot ~ ".config.clean" %}
{%- from tplroot ~ "/map.jinja" import mapdata as vault with context %}

include:
  - {{ sls_config_clean }}
  - {{ slsdotpath }}.repo.clean

Vault service overrides are absent:
  file.absent:
    - name: /etc/systemd/system/vault.service.d/salt.conf

Vault is removed:
  pkg.removed:
    - name: {{ vault.lookup.pkg.name }}
    - require:
      - sls: {{ sls_config_clean }}
