# vim: ft=sls

{%- set tplroot = tpldir.split("/")[0] %}
{%- set sls_service_running = tplroot ~ ".service.running" %}
{%- set sls_ssh_ca = tplroot ~ ".ssh.ca" %}
{%- from tplroot ~ "/map.jinja" import mapdata as vault with context %}

include:
  - {{ sls_service_running }}
  - {{ sls_ssh_ca }}

{%- for mount, mount_config in vault.ssh.items() %}
{%-   for role, role_config in mount_config.get("roles", {}).items() %}

Vault SSH role {{ role }} for mount {{ mount }} is present:
  vault_ssh.role_present:
    - name: {{ role }}
    - mount: {{ mount }}
{%-     for param, val in role_config.items() %}
    - {{ param }}: {{ val | json }}
{%-     endfor %}
    - require:
      - sls: {{ sls_service_running }}
{%-     if role_config["key_type"] == "ca" %}
      - Vault SSH CA on mount {{ mount }} initialized
{%-     endif %}
{%-   endfor %}

{%-   for role in mount_config.get("roles_absent", []) %}

Vault SSH role {{ role }} for mount {{ mount }} is absent:
  vault_ssh.role_absent:
    - name: {{ role }}
    - mount: {{ mount }}
    - require:
      - sls: {{ sls_service_running }}
{%-   endfor %}
{%- endfor %}
