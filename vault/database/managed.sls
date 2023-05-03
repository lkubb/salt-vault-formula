# vim: ft=sls

{%- set tplroot = tpldir.split("/")[0] %}
{%- set sls_service_running = tplroot ~ ".service.running" %}
{%- from tplroot ~ "/map.jinja" import mapdata as vault with context %}

include:
  - {{ sls_service_running }}

{%- for mount, mount_config in vault.database.items() %}
{%-   for name, conf in mount_config.items() %}

Vault database connection {{ name }} for mount {{ mount }} is present:
  vault_db.connection_present:
    - name: {{ name }}
    - mount: {{ mount }}
{%-     if "allowed_roles" not in conf %}
    - allowed_roles: {{ conf.get("roles", []) | list | json }}
{%-     endif %}
{%-     for var, val in conf.items() %}
{%-       if var == "roles" %}
{%-         continue %}
{%-       endif %}
    - {{ var }}: {{ val | json }}
{%-     endfor %}
    - require:
      - sls: {{ sls_service_running }}

{%-     for rolename, roleconf in conf.get("roles", {}).items() %}

Vault database role {{ rolename }} for mount {{ mount }} is present:
  vault_db.role_present:
    - name: {{ rolename }}
    - mount: {{ mount }}
    - connection: {{ name }}
{%-       for var, val in roleconf.items() %}
    - {{ var }}: {{ val | json }}
{%-       endfor %}
    - require:
      - Vault database connection {{ name }} for mount {{ mount }} is present
{%-     endfor %}
{%-   endfor %}
{%- endfor %}
