# vim: ft=sls

{#-
    Removes managed database connections and their roles.
    Requires ``remove_all_data_for_sure`` to be set to true
    to prevent accidental damage.
#}

{%- set tplroot = tpldir.split("/")[0] %}
{%- from tplroot ~ "/map.jinja" import mapdata as vault with context %}

{%- if vault.remove_all_data_for_sure %}

{%-   for mount, mount_config in vault.database.items() %}
{%-     for name, conf in mount_config.items() %}
{%-       for rolename, roleconf in conf.get("roles", {}).items() %}

Vault database role {{ rolename }} for mount {{ mount }} is absent:
  vault_db.role_absent:
    - name: {{ role.name }}
    - mount: {{ mount }}
{%-       endfor %}

Vault database connection {{ name }} for mount {{ mount }} is absent:
  vault_db.connection_absent:
    - name: {{ name }}
    - mount: {{ mount }}
{%-     endfor %}
{%-   endfor %}
{%- endif %}
