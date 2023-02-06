# vim: ft=sls

{#-
    Stops the vault service and disables it at boot time.
#}

{%- set tplroot = tpldir.split("/")[0] %}
{%- from tplroot ~ "/map.jinja" import mapdata as vault with context %}

Vault is dead:
  service.dead:
    - name: {{ vault.lookup.service.name }}
    - enable: False
