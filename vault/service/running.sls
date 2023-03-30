# vim: ft=sls

{%- set tplroot = tpldir.split("/")[0] %}
{%- set sls_config_file = tplroot ~ ".config.file" %}
{%- from tplroot ~ "/map.jinja" import mapdata as vault with context %}

include:
  - {{ sls_config_file }}

Vault is running:
  service.running:
    - name: {{ vault.lookup.service.name }}
    - enable: true
    # Only reload configuration on changes, do not restart.
    # The latter would require unsealing again.
    # Only a few values are reloaded though!
    - reload: true
    - watch:
      - sls: {{ sls_config_file }}
