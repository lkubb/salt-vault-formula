# vim: ft=sls

{%- set tplroot = tpldir.split("/")[0] %}
{%- set sls_package_install = tplroot ~ ".package.install" %}
{%- from tplroot ~ "/map.jinja" import mapdata as vault with context %}

include:
  - {{ sls_package_install }}

{%- if vault.cert %}

Vault API certificate private key is managed:
  x509.private_key_managed:
    - name: {{ vault.lookup.paths.api_key }}
    - algo: rsa
    - keysize: 2048
    - new: true
{%-   if salt["file.file_exists"](vault.lookup.paths.api_key) %}
    - prereq:
      - Vault API certificate is managed
{%-   endif %}
    - makedirs: True
    - user: root
    - group: {{ vault.lookup.group }}
    - mode: '0640'
    - require:
      - sls: {{ sls_package_install }}

Vault API certificate is managed:
  x509.certificate_managed:
    - name: {{ vault.lookup.paths.api_cert }}
    - ca_server: {{ vault.cert.ca_server or "null" }}
    - signing_policy: {{ vault.cert.signing_policy or "null" }}
    - signing_cert: {{ vault.cert.signing_cert or "null" }}
    - signing_private_key: {{ vault.cert.signing_private_key or
                              (vault.lookup.paths.api_key if not vault.cert.ca_server and not vault.cert.signing_cert
                              else "null") }}
    - private_key: {{ vault.lookup.paths.api_key }}
    - days_valid: {{ vault.cert.days_valid or "null" }}
    - days_remaining: {{ vault.cert.days_remaining or "null" }}
    - days_valid: {{ vault.cert.days_valid or "null" }}
    - authorityKeyIdentifier: keyid:always
    - basicConstraints: critical, CA:false
    - subjectKeyIdentifier: hash
{%-   if vault.cert.san %}
    - subjectAltName:  {{ vault.cert.san | json }}
{%-   else %}
    - subjectAltName:
      - dns: {{ vault.cert.cn or grains.fqdns | reject("==", "localhost.localdomain") | first | d(grains.id) }}
      - ip: {{ vault.cert.cn or grains.fqdns | reject("==", "localhost.localdomain") | first | d(grains.id) }}
{%-   endif %}
    - CN: {{ vault.cert.cn or grains.fqdns | reject("==", "localhost.localdomain") | first | d(grains.id) }}
    - mode: '0640'
    - user: root
    - group: {{ vault.lookup.group }}
    - makedirs: True
    - append_certs: {{ vault.cert.intermediate | json }}
    - require:
      - sls: {{ sls_package_install }}
{%-   if not salt["file.file_exists"](vault.lookup.paths.api_key) %}
      - Vault API certificate private key is managed
{%-   endif %}

Vault client certificate private key is managed:
  x509.private_key_managed:
    - name: {{ vault.lookup.paths.client_key }}
    - algo: rsa
    - keysize: 2048
    - new: true
{%-   if salt["file.file_exists"](vault.lookup.paths.client_key) %}
    - prereq:
      - Vault client certificate is managed
{%-   endif %}
    - makedirs: True
    - user: root
    - mode: '0640'
    - group: {{ vault.lookup.group }}
    - require:
      - sls: {{ sls_package_install }}

Vault client certificate is managed:
  x509.certificate_managed:
    - name: {{ vault.lookup.paths.client_cert }}
    - ca_server: {{ vault.cert.ca_server or "null" }}
    - signing_policy: {{ vault.cert.signing_policy or "null" }}
    - signing_cert: {{ vault.cert.signing_cert or "null" }}
    - signing_private_key: {{ vault.cert.signing_private_key or
                              (vault.lookup.paths.client_key if not vault.cert.ca_server and not vault.cert.signing_cert
                              else "null") }}
    - private_key: {{ vault.lookup.paths.client_key }}
    - days_valid: {{ vault.cert.days_valid or "null" }}
    - days_remaining: {{ vault.cert.days_remaining or "null" }}
    - days_valid: {{ vault.cert.days_valid or "null" }}
    - authorityKeyIdentifier: keyid:always
    - basicConstraints: critical, CA:false
    - subjectKeyIdentifier: hash
{%-   if vault.cert.san %}
    - subjectAltName:  {{ vault.cert.san | json }}
{%-   else %}
    - subjectAltName:
      - dns: {{ vault.cert.cn or grains.fqdns | reject("==", "localhost.localdomain") | first | d(grains.id) }}
      - ip: {{ vault.cert.cn or grains.fqdns | reject("==", "localhost.localdomain") | first | d(grains.id) }}
{%-   endif %}
    - CN: {{ vault.cert.cn or grains.fqdns | reject("==", "localhost.localdomain") | first | d(grains.id) }}
    - mode: '0640'
    - user: root
    - group: {{ vault.lookup.group }}
    - makedirs: True
    - append_certs: {{ vault.cert.intermediate | json }}
    - require:
      - sls: {{ sls_package_install }}
{%-   if not salt["file.file_exists"](vault.lookup.paths.client_key) %}
      - Vault client certificate private key is managed
{%-   endif %}

Ensure CA certificates are trusted for Vault:
  x509.pem_managed:
    - name: {{ vault.lookup.paths.ca_cert }}
    # ensure root and intermediate CA certs are in the truststore
    - text: {{ ([vault.cert.root] + vault.cert.intermediate) | join("\n") | json }}
    - user: root
    - group: {{ vault.lookup.group }}
    - mode: '0644'
    - require:
      - sls: {{ sls_package_install }}
{%- else %}

Certs are not managed:
  test.nop:
    - name: This is required to be able to watch this file.
{%- endif %}
