# vim: ft=sls

{%- set tplroot = tpldir.split("/")[0] %}
{%- set sls_config_file = tplroot ~ ".config.file" %}
{%- set sls_cert_managed = tplroot ~ ".cert.managed" %}
{%- from tplroot ~ "/map.jinja" import mapdata as vault with context %}

include:
  - {{ sls_config_file }}
  - {{ sls_cert_managed }}

Vault is running:
  service.running:
    - name: {{ vault.lookup.service.name }}
    - enable: true
    # Only reload configuration on changes, do not restart.
    # The latter would require unsealing again.
    # Only a few values are reloaded though!
    - reload: true
    - watch:
      - sls: {{ sls_config_file }}
      - sls: {{ sls_cert_managed }}

{%- if vault.manage_firewall and grains["os_family"] == "RedHat" %}
{%-   set api_port = (vault | traverse("config:listener:tcp:address", ":8200")).split(":") | last | int %}

Vault service is known:
  firewalld.service:
    - name: vault
    - ports:
      - {{ api_port }}/tcp
      - {{ (vault | traverse("config:listener:tcp:cluster_address", ":" ~ (api_port + 1))).split(":") | last }}/tcp
    - require:
      - Vault is running

Vault ports are open:
  firewalld.present:
    - name: public
    - services:
      - vault
    - require:
      - Vault service is known
{%- endif %}
