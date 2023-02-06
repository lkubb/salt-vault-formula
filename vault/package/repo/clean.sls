# vim: ft=sls

{#-
    This state will remove the configured vault repository.
    This works for apt/dnf/yum/zypper-based distributions only by default.
#}

{%- set tplroot = tpldir.split("/")[0] %}
{%- from tplroot ~ "/map.jinja" import mapdata as vault with context %}


{%- if vault.lookup.pkg_manager not in ["apt", "dnf", "yum", "zypper"] %}
{%-   if salt["state.sls_exists"](slsdotpath ~ "." ~ vault.lookup.pkg_manager ~ ".clean") %}

include:
  - {{ slsdotpath ~ "." ~ vault.lookup.pkg_manager ~ ".clean" }}
{%-   endif %}

{%- else %}
{%-   for reponame, enabled in vault.lookup.enablerepo.items() %}
{%-     if enabled %}

{%-       if 'apt' == vault.lookup.pkg_manager %}

Vault {{ reponame }} signing key is absent:
  file.absent:
    - name: {{ vault.lookup.repos[reponame].keyring.file }}
{%-       endif %}

Vault {{ reponame }} repository is absent:
  pkgrepo.absent:
{%-       for conf in ["name", "ppa", "ppa_auth", "keyid", "keyid_ppa", "copr"] %}
{%-         if conf in vault.lookup.repos[reponame] %}
    - {{ conf }}: {{ vault.lookup.repos[reponame][conf] }}
{%-         endif %}
{%-       endfor %}
{%-     endif %}
{%-   endfor %}
{%- endif %}
