# -*- coding: utf-8 -*-
# vim: ft=sls

{%- set tplroot = tpldir.split('/')[0] %}
{%- set sls_config_file = tplroot ~ '.config.file' %}
{%- from tplroot ~ "/map.jinja" import mapdata as vault with context %}

include:
  - {{ sls_config_file }}

vault-service-running-service-running:
  service.running:
    - name: {{ vault.lookup.service.name }}
    - enable: True
    # only reload configuration on changes, do not restart
    # the latter would require unsealing again
    - reload: true
    - watch:
      - sls: {{ sls_config_file }}
