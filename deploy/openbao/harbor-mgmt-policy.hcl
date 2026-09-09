# Management can enroll/decrypt user data, but cannot use signing-key Transit.
path "transit/encrypt/harbor-users-eu" {
  capabilities = ["update"]
}
path "transit/decrypt/harbor-users-eu" {
  capabilities = ["update"]
}
