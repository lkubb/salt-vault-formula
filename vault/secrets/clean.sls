# vim: ft=sls

{#-
    Removes managed secrets.
#}

{%- set tplroot = tpldir.split("/")[0] %}
{%- from tplroot ~ "/map.jinja" import mapdata as vault with context %}


Managed secrets are absent:
  vault_secret.absent:
    - names: {{ vault.secrets | list }}
    - operation: {{ "delete" if not vault.remove_all_data_for_sure else "wipe" }}
