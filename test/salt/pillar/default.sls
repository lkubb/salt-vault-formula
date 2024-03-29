# vim: ft=yaml
---
vault:
  lookup:
    master: template-master
    # Just for testing purposes
    winner: lookup
    added_in_lookup: lookup_value
    pkg:
      name: vault
    enablerepo:
      stable: true
    config: '/etc/vault.d/salt.json'
    service:
      name: vault
    group: vault
    paths:
      api_cert: /opt/vault/tls/server.pem
      api_key: /opt/vault/tls/server.key
      ca_cert: /opt/vault/tls/ca.pem
      client_cert: /opt/vault/tls/client.pem
      client_key: /opt/vault/tls/client.key
    user: vault
  cert:
    ca_server: null
    cn: null
    days_remaining: 3
    days_valid: 7
    intermediate: []
    root: null
    san: null
    signing_cert: null
    signing_policy: null
    signing_private_key: null
  config: {}
  database: {}
  disable_swap: false
  init:
    key_shares: 3
    key_threshold: 2
    output: /root/vault_init
    pgp_keys: []
    root_token_pgp_key: null
    vault_addr: null
  leases:
    database: {}
  manage_firewall: true
  pki:
    ca: []
    roles_absent: []
    roles_present: []
    urls: []
  plugins: []
  plugins_absent: []
  remove_all_data_for_sure: false
  secrets: {}
  secrets_absent: []
  ssh: {}
  version: null

  tofs:
    # The files_switch key serves as a selector for alternative
    # directories under the formula files directory. See TOFS pattern
    # doc for more info.
    # Note: Any value not evaluated by `config.get` will be used literally.
    # This can be used to set custom paths, as many levels deep as required.
    files_switch:
      - any/path/can/be/used/here
      - id
      - roles
      - osfinger
      - os
      - os_family
    # All aspects of path/file resolution are customisable using the options below.
    # This is unnecessary in most cases; there are sensible defaults.
    # Default path: salt://< path_prefix >/< dirs.files >/< dirs.default >
    #         I.e.: salt://vault/files/default
    # path_prefix: template_alt
    # dirs:
    #   files: files_alt
    #   default: default_alt
    # The entries under `source_files` are prepended to the default source files
    # given for the state
    # source_files:
    #   vault-config-file-file-managed:
    #     - 'example_alt.tmpl'
    #     - 'example_alt.tmpl.jinja'

    # For testing purposes
    source_files:
      vault-config-file-file-managed:
        - 'example.tmpl.jinja'

  # Just for testing purposes
  winner: pillar
  added_in_pillar: pillar_value
