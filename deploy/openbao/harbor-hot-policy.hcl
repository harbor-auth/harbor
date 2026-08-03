# harbor-hot may only use the single regional Transit key. It cannot read key
# configuration, export key material, rotate/delete keys, or access any other
# OpenBao engine.
path "transit/encrypt/harbor-eu" {
  capabilities = ["update"]
}

path "transit/decrypt/harbor-eu" {
  capabilities = ["update"]
}
