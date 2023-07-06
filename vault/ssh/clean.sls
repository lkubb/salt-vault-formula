# vim: ft=sls

{#-
    Removes managed SSH roles and SSH CAs.
    For CAs, requires ``remove_all_data_for_sure`` to be set to true
    to prevent accidental damage.
#}

{%- set tplroot = tpldir.split("/")[0] %}
{%- from tplroot ~ "/map.jinja" import mapdata as vault with context %}

{%- for mount, mount_config in vault.ssh.items() %}
{%-   for role, role_config in mount_config.get("roles", {}).items() %}

Vault SSH role {{ role }} for mount {{ mount }} is absent:
  vault_ssh.role_absent:
    - name: {{ role }}
    - mount: {{ mount }}
{%-   endfor %}

{%-   if vault.remove_all_data_for_sure and mount_config.get("roles", {}).values() | selectattr("key_type", "equalto", "ca") | list %}

Vault SSH CA on mount {{ mount }} initialized:
  vault_ssh.ca_absent:
    - mount: {{ mount }}
{%-   endif %}
{%- endfor %}
