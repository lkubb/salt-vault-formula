# -*- coding: utf-8 -*-
# vim: ft=sls

{%- set tplroot = tpldir.split('/')[0] %}
{%- set sls_service_running = tplroot ~ '.service.running' %}
{%- from tplroot ~ "/map.jinja" import mapdata as vault with context %}

include:
  - {{ sls_service_running }}

{%- for plugin in vault.plugins %}

Vault plugin {{ plugin.name }} is present:
  file.managed:
    - name: {{ vault.config.plugin_directory | path_join(plugin.name) }}
    - source: {{ plugin.source | json }}
    - source_hash: {{ plugin.hash }}
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
    - sha256: {{ plugin.hash }}
    - args: {{ plugin.get("args", "null") }}
    - env: {{ plugin.get("env", "null") }}
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
