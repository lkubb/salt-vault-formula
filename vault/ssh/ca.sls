# vim: ft=sls

{%- set tplroot = tpldir.split("/")[0] %}
{%- set sls_service_running = tplroot ~ ".service.running" %}
{%- from tplroot ~ "/map.jinja" import mapdata as vault with context %}

include:
  - {{ sls_service_running }}

{%- for mount, mount_config in vault.ssh.items() %}
{%-   if mount_config.get("roles", {}).values() | selectattr("key_type", "equalto", "ca") | list %}

Vault SSH CA on mount {{ mount }} initialized:
  vault_ssh.ca_present:
{%-     for param, val in mount_config.get("ca", {}).items() %}
    - {{ param }}: {{ val | json }}
{%-     endfor %}
    - mount: {{ mount }}
    - require:
      - sls: {{ sls_service_running }}
{%-   endif %}
{%- endfor %}

