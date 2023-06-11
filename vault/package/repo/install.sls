# vim: ft=sls

{%- set tplroot = tpldir.split("/")[0] %}
{%- from tplroot ~ "/map.jinja" import mapdata as vault with context %}

{%- for reponame, enabled in vault.lookup.enablerepo.items() %}
{%-   set config = vault.lookup.repos[reponame] %}
{%-   if enabled %}

Vault {{ reponame }} repository is available:
  pkgrepo.managed:
{%-     for conf, val in config.items() %}
    - {{ conf }}: {{ val }}
{%-     endfor %}
{%-     if vault.lookup.pkg_manager in ["dnf", "yum", "zypper"] %}
    - enabled: 1
{%-     endif %}
    - require_in:
      - Vault is installed

{%-   else %}

Vault {{ reponame }} repository is disabled:
  pkgrepo.absent:
{%-     for conf in ["name", "ppa", "ppa_auth", "keyid", "keyid_ppa", "copr"] %}
{%-       if conf in config %}
    - {{ conf }}: {{ config[conf] }}
{%-       endif %}
{%-     endfor %}
    - require_in:
      - Vault is installed
{%-   endif %}
{%- endfor %}
