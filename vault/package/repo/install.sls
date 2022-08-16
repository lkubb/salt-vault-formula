# -*- coding: utf-8 -*-
# vim: ft=sls

{%- set tplroot = tpldir.split('/')[0] %}
{%- from tplroot ~ "/map.jinja" import mapdata as vault with context %}
{%- from tplroot ~ "/libtofs.jinja" import files_switch with context %}

{%- if grains['os'] in ['Debian', 'Ubuntu'] %}

Ensure Vault APT repository can be managed:
  pkg.installed:
    - pkgs:
      - python3-apt                    # required by Salt
      - gpg                           # to dearmor keys and verify fingerprint
{%-   if 'Ubuntu' == grains['os'] %}
      - python-software-properties    # to better support PPA repositories
{%-   endif %}
{%- endif %}

{%- for reponame, enabled in vault.lookup.enablerepo.items() %}
{%-   set config = vault.lookup.repos[reponame] %}
{%-   if enabled %}
{%-     if 'apt' == vault.lookup.pkg_manager %}
{%-       set tmpfile = salt["temp.file"]() %}

Vault {{ reponame }} signing key is available:
  file.managed:
    - name: {{ tmpfile }}
    - source: {{ files_switch(["hashicorp.gpg"],
                          lookup='Vault ' ~ reponame ~ ' signing key is available')
              }}
      - {{ config.keyring.source }}
{%-       if config.keyring.source_hash is false %}
    - skip_verify: true
{%-       else %}
    - source_hash: {{ config.keyring.source_hash }}
{%-       endif %}
    - user: root
    - group: {{ vault.lookup.rootgroup }}
    - mode: '0644'
    - dir_mode: '0755'
    - makedirs: true
    - unless:
      - fun: file.file_exists
        path: {{ config.keyring.file }}
  cmd.run:
    - name: >-
        mkdir -p '{{ salt["file.dirname"](config.keyring.file) }}' &&
        cat '{{ tmpfile }}' | gpg --dearmor > '{{ config.keyring.file }}' &&
        gpg --no-default-keyring --keyring '{{ config.keyring.file }}' --list-keys |
        grep '{{ config.keyring.fingerprint }}'
    - onchanges:
      - file: {{ tmpfile }}
    - require:
      - Ensure Vault APT repository can be managed
    - require_in:
      - Vault {{ reponame }} repository is available
{%-     endif %}

Vault {{ reponame }} repository is available:
  pkgrepo.managed:
{%-     for conf, val in config.items() %}
{%-       if conf != "keyring" %}
    - {{ conf }}: {{ val }}
{%-       endif %}
{%-     endfor %}
{%-     if vault.lookup.pkg_manager in ['dnf', 'yum', 'zypper'] %}
    - enabled: 1
{%-     elif 'apt' == vault.lookup.pkg_manager %}
    # This state module is not actually idempotent in many circumstances
    # https://github.com/saltstack/salt/pull/61986
    # workaround for this formula
    - unless:
      - fun: file.file_exists
        path: {{ config.file }}
{%-     endif %}
    - require_in:
      - vault-package-install-pkg-installed

{%-   else %}

Vault {{ reponame }} repository is disabled:
  pkgrepo.absent:
{%-     for conf in ['name', 'ppa', 'ppa_auth', 'keyid', 'keyid_ppa', 'copr'] %}
{%-       if conf in config %}
    - {{ conf }}: {{ config[conf] }}
{%-       endif %}
{%-     endfor %}
    - require_in:
      - vault-package-install-pkg-installed

{%-     if 'apt' == vault.lookup.pkg_manager %}

Vault {{ reponame }} signing key is absent:
  file.absent:
    - name: {{ config.keyring.file }}
{%-     endif %}
{%-   endif %}
{%- endfor %}
