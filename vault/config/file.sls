# vim: ft=sls

{#-
    Manages the Vault configuration.
    Has a dependency on `vault.package`_.
#}

{%- set tplroot = tpldir.split("/")[0] %}
{%- set sls_package_install = tplroot ~ ".package.install" %}
{%- from tplroot ~ "/map.jinja" import mapdata as vault with context %}
{%- from tplroot ~ "/libtofs.jinja" import files_switch with context %}

include:
  - {{ sls_package_install }}

Vault configuration is managed:
  file.serialize:
    - name: {{ vault.lookup.config }}
    - serializer: json
    - mode: '0644'
    - user: root
    - group: {{ vault.lookup.rootgroup }}
    - makedirs: true
    - require:
      - sls: {{ sls_package_install }}
    - dataset: {{ vault.config | json }}
