# -*- coding: utf-8 -*-
# vim: ft=sls

{%- set tplroot = tpldir.split('/')[0] %}
{%- from tplroot ~ "/map.jinja" import mapdata as vault with context %}

Managed Vault plugins are absent:
  file.absent:
    - names:
{%- for plugin in plugins %}
      - {{ vault.config.plugin_directory | path_join(plugin.name) }}
{%- endfor %}
