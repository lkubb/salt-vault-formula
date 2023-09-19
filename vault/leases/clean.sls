# vim: ft=sls

{#-
    Removes managed leases.
#}

{%- set tplroot = tpldir.split("/")[0] %}
{%- from tplroot ~ "/map.jinja" import mapdata as vault with context %}

{%- for lease, config in vault.leases.database.items() %}

Lease {{ lease.name }} is uncached:
  vault_db.creds_uncached:
    - name: {{ lease.role_name }}
    - static: {{ lease.get("static", false) }}
    - cache: {{ lease.get("cache", true) }}
    - mount: {{ lease.get("mount", "database") }}
{%-   if lease.get("beacon") %}
    - beacon: true
{%-   endif %}
{%- endfor %}
