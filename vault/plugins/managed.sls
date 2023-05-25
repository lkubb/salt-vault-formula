# vim: ft=sls

{%- set tplroot = tpldir.split("/")[0] %}
{%- set sls_service_running = tplroot ~ ".service.running" %}
{%- from tplroot ~ "/map.jinja" import mapdata as vault with context %}

include:
  - {{ sls_service_running }}

{%- for plugin in vault.plugins %}

Vault plugin {{ plugin.name }} is present:
  file.managed:
    - name: {{ vault.config.plugin_directory | path_join(plugin.name) }}
    - source: {{ plugin.source | json }}
    - source_hash: {{ plugin.hash }}
{%- for param in ["source_hash_sig", "signature", "signed_by_any", "signed_by_all", "keyring", "gnupghome"] %}
{%-   if plugin.get(param) %}
    - {{ param }}: {{ plugin[param] | json }}
{%-   endif %}
{%- endfor %}
    - makedirs: true
    - mode: '0740'
    - dir_mode: '0750'
    - user: {{ vault.lookup.user }}
    - group: {{ vault.lookup.group }}
    - require:
      - sls: {{ sls_service_running }}

Vault plugin {{ plugin.name }} is registered:
  vault_plugin.registered:
    - name: {{ plugin.name }}
    - plugin_type: {{ plugin.type }}
    - sha256: {{ salt["file.get_source_sum"](source=plugin.source, source_hash=plugin.hash)["hsum"] }}
    - args: {{ plugin.get("args", "null") }}
    - env: {{ plugin.get("env", "null") }}
    - version: {{ plugin.get("version", "null") }}
    - require:
      - Vault plugin {{ plugin.name }} is present
{%- endfor %}

{%- for plugin in vault.plugins_absent %}

Vault plugin {{ plugin.name }} is degistered:
  vault_plugin.deregistered:
    - name: {{ plugin.name }}
    - plugin_type: {{ plugin.type }}

Vault plugin {{ plugin.name }} is absent:
  file.absent:
    - name: {{ vault.config.plugin_directory | path_join(plugin.name) }}
    - require:
      - Vault plugin {{ plugin.name }} is degistered
{%- endfor %}
