# -*- coding: utf-8 -*-
# vim: ft=sls

{%- set tplroot = tpldir.split('/')[0] %}
{%- from tplroot ~ "/map.jinja" import mapdata as vault with context %}

vault-service-clean-service-dead:
  service.dead:
    - name: {{ vault.lookup.service.name }}
    - enable: False
