# vim: ft=sls

{%- set tplroot = tpldir.split("/")[0] %}
{%- from tplroot ~ "/map.jinja" import mapdata as vault with context %}

{%- for lease, config in vault.leases.database.items() %}

Lease {{ lease }} is cached:
  vault_db.creds_cached:
    - name: {{ config.role }}
    - valid_for: {{ config.get("valid_for", 900) }}
    - static: {{ config.get("static", false) }}
    - cache: {{ config.get("cache", true) }}
    - mount: {{ config.get("mount", "database") }}
    - renew_increment: {{ config.get("renew_increment", "null") }}
    - revoke_delay: {{ config.get("revoke_delay", "null") }}
    - meta: {{ config.get("meta", "null") }}
    - check_server: {{ config.get("check_server", false) }}
{%-   if config.get("beacon") %}
    - beacon: true
    - beacon_interval: {{ config.get("beacon_interval", 300) }}
    - min_ttl: {{ config.get("min_ttl", 630) }}
{%-   endif %}
{%- endfor %}
