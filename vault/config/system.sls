# -*- coding: utf-8 -*-
# vim: ft=sls

{%- set tplroot = tpldir.split('/')[0] %}
{%- set sls_package_install = tplroot ~ '.package.install' %}
{%- from tplroot ~ "/map.jinja" import mapdata as vault with context %}
{%- from tplroot ~ "/libtofs.jinja" import files_switch with context %}

include:
  - {{ sls_package_install }}

{%- if vault.disable_swap %}
{%-   set fstab_swaps = [] %}
{%-   for mountpoint, conf in salt["mount.fstab"]().items() %}
{%-     if conf.fstype == "swap" %}
{%-       do fstab_swaps.append([mountpoint, conf.device]) %}
{%-     endif %}
{%-   endfor %}

{%-   if fstab_swaps %}

Swap volumes are removed from fstab:
  mount.fstab_absent:
    - names:
{%-     for mountpoint, device in fstab_swaps %}
      - {{ device }}:
        - fs_file: {{ mountpoint }}
{%-     endfor %}
{%-   endif %}

Active swaps are unmounted:
  cmd.run:
    - name: swapoff -a
    - onlyif:
      - fun: mount.swaps
{%- endif %}
