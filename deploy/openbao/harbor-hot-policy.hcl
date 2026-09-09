# harbor-hot may only use the signing and user-data Transit keys. It cannot read key
# configuration, export key material, rotate/delete keys, or access any other
# OpenBao engine.
path "transit/encrypt/harbor-eu" {
  capabilities = ["update"]
}

path "transit/decrypt/harbor-eu" {
  capabilities = ["update"]
}

# User DEKs are isolated from signing-key envelopes.
path "transit/encrypt/harbor-users-eu" {
  capabilities = ["update"]
}
path "transit/decrypt/harbor-users-eu" {
  capabilities = ["update"]
}
