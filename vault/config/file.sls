# -*- coding: utf-8 -*-
# vim: ft=sls

{%- set tplroot = tpldir.split('/')[0] %}
{%- set sls_package_install = tplroot ~ '.package.install' %}
{%- from tplroot ~ "/map.jinja" import mapdata as vault with context %}
{%- from tplroot ~ "/libtofs.jinja" import files_switch with context %}

include:
  - {{ sls_package_install }}

vault-config-file-file-managed:
  file.serialize:
    - name: {{ vault.lookup.config }}
    - serializer: json
    - mode: '0644'
    - user: root
    - group: {{ vault.lookup.rootgroup }}
    - makedirs: True
    - require:
      - sls: {{ sls_package_install }}
    - dataset: {{ vault.config | json }}
