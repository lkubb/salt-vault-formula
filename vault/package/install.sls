# vim: ft=sls

{%- set tplroot = tpldir.split("/")[0] %}
{%- from tplroot ~ "/map.jinja" import mapdata as vault with context %}
{%- from tplroot ~ "/libtofs.jinja" import files_switch with context %}

include:
  - {{ slsdotpath }}.repo

Vault is installed:
  pkg.{{ "installed" if vault.version != "latest" else "latest" }}:
    - name: {{ vault.lookup.pkg.name }}
{%- if vault.version and "latest" != vault.version %}
    - version: {{ vault.version }}
{%- endif %}

# This is necessary to use json-style configuration.
# There is no inbuilt Salt serializer for hcl
Vault service overrides are installed:
  file.managed:
    - name: /etc/systemd/system/vault.service.d/salt.conf
    - source: {{ files_switch(["service_override.conf", "service_override.conf.j2"],
                              lookup="Vault service overrides are installed",
                 )
              }}
    - mode: '0644'
    - user: root
    - group: {{ vault.lookup.rootgroup }}
    - makedirs: True
    - template: jinja
    - require:
      - Vault is installed
    - context:
        vault: {{ vault | json }}

Custom Vault modules are present:
  saltutil.sync_all:
    - refresh: true
    - unless:
      - {{ "vault_server" in salt["saltutil.list_extmods"]().get("states", []) | lower }}
