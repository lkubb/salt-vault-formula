# vim: ft=sls

{%- set tplroot = tpldir.split("/")[0] %}
{%- from tplroot ~ "/map.jinja" import mapdata as vault with context %}

{%- for path, config in vault.secrets.items() %}

Secret at {{ path }} is managed:
  vault_secret.present:
    - name: {{ path }}
    {{ config | dict_to_sls_yaml_params | indent(4) }}
{%- endfor %}

{%- for secret in vault.secrets_absent %}

{%-   set operation = "delete" %}
{%-   set path = secret %}
{%-   if secret is mapping %}
{%-     set operation = secret.get("operation", "delete") %}
{%-     set path = secret["path"] %}
{%-   endif %}

Unwanted secret at {{ path }} is absent:
  vault_secret.absent:
    - name: {{ path }}
    - operation: {{ operation }}
{%- endfor %}
