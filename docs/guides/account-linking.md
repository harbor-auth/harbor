# Adding Harbor to a website with existing accounts

Harbor authenticates a person and returns an app-specific subject. Your website
owns its customer records, login sessions, account recovery, purchases and
subscriptions. Add Harbor as another credential for the existing customer ID.
Do not replace that ID or automatically merge accounts with matching emails.

## Configure and validate OIDC

Create a Web backend application in Harbor Cloud for a Rails/server app. Store
its secret only on the server. Register the exact local/production callbacks.
Enable `email` in Allowed permissions if useful, then request `openid email`.
Request `offline_access` only if you need to refresh Harbor tokens; the website's
own session does not require it.

Use a maintained OIDC client with discovery, Authorization Code + S256 PKCE,
random state and nonce, signature/issuer/audience/expiry checks and mandatory ID
token validation. Keep the pre-login transaction in real server storage, tied to
an opaque browser session; consume it once and expire it after five minutes.
Your callback URL must come from configuration, not an untrusted Host header.
UserInfo is a Bearer request to the discovered endpoint. Require its `sub` to
match the validated ID-token `sub`. Do not decode a JWT and trust its JSON.

The Cloud `/developers` page includes a Node `openid-client` v6 reference using
Redis for the one-time login transaction. Its callback returns:

```ts
{
  issuer: validatedIdToken.iss,
  subject: validatedIdToken.sub,
  email: userInfo.email_verified === true ? userInfo.email : undefined
}
```

For another framework, use its OIDC client for the same checks. Harbor supplies
email via UserInfo, not the ID token. If the user declines, show “Sign-in was
cancelled. Try again or use your existing sign-in method.” Missing optional email
must not stop returning users from signing in by their linked identity.

## Durable mapping

For a PostgreSQL website with an existing `users` table, add one credential table:

```sql
CREATE TABLE external_identities (
  id uuid PRIMARY KEY,
  user_id bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  issuer text NOT NULL,
  subject text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (issuer, subject)
);
CREATE INDEX external_identities_user ON external_identities(user_id);
```

Use your existing user's actual ID type. Issuer and subject are exact strings.
Do not normalize their case, derive them from email, or use `grant_id` as the
mapping key. Grant IDs change on reconnect; `(issuer, subject)` stays stable.
Do not persist access/ID tokens in this table.

## Callback decision and first-login screen

After the OIDC library validates the callback and UserInfo:

1. Look up the exact `(issuer, subject)`. If it is linked to an active local
   customer, rotate the website session and sign in that same customer.
2. Otherwise create a short-lived **pending link**, containing only the verified
   issuer/subject, creation time and optional email hint. Store it server-side,
   bind it to this browser and consume it once. It grants no local account
   access. Keep its browser binding separate from the login session ID, so the
   site's normal session rotation during password/MFA login does not lose it.
3. Show “Connect your existing account” and “Create a new account.” Explain that
   an existing customer must sign in once using the method they already use.
   Do not create a user record merely because this was an unfamiliar Harbor
   login. Do not expose whether an email matched a local customer.

“Connect your existing account” runs the site's normal password/passkey/recovery
flow, including MFA and current account restrictions. Require a fresh ownership
proof after this pending link began. An email match can help the user select an
account, but `email_verified: true` never substitutes for that proof. Recovery
must use the contact and policy already stored on the local account, not an
arbitrary Harbor-supplied address.

After ownership proof, show “Connect Harbor to this account” as a CSRF-protected
POST. Consume the pending link and attach the credential in a database
transaction. A Rails service for that final step is:

```ruby
# pending is read from one-time server storage, never from POST issuer/sub fields.
# authenticated_user and proof_time come from the site's normal login/MFA service.
def connect_harbor!(pending:, authenticated_user:, proof_time:)
  raise ExpiredLink unless pending && pending.expires_at > Time.current
  raise FreshLoginRequired unless proof_time && proof_time >= pending.created_at

  ExternalIdentity.transaction do
    authenticated_user.lock!
    raise AccountUnavailable unless authenticated_user.active?
    identity = ExternalIdentity.create_or_find_by!(
      issuer: pending.issuer, subject: pending.subject
    ) { |record| record.user_id = authenticated_user.id }
    raise AlreadyLinked unless identity.user_id == authenticated_user.id
    identity
  end
end
```

The unique database constraint resolves simultaneous callbacks. An identity
already linked to another customer must fail; never reassign or merge it. On a
transient database failure after consuming the pending link, restart Harbor
sign-in. Do not fall back to matching email. Rotate the local session after
success and invalidate the browser's pending-link binding.

“Create a new account” must be an explicit, CSRF-protected decision using your
normal signup policy. Create the new customer and credential in one database
transaction. If the site's contact-email uniqueness rule finds an existing
customer, offer the normal sign-in/recovery flow; never overwrite that customer.
Keep the pending identity only for the short continuation window.

## Operational behavior and acceptance checks

Existing email, subscriptions, orders and authorization roles stay on the same
local customer. Changing Harbor email does not transfer account ownership.
Unlinking Harbor should require fresh local authentication and leave another
working sign-in/recovery method. Harbor disconnect stops Harbor token use; your
website controls its own existing sessions and logout policy.

Test with your real database/session store: returning linked customer; unfamiliar
Harbor login before linking; known/unknown/absent/changed email; recovery and MFA;
expired/cancelled flow; foreign-browser or replayed callback; concurrent linking;
identity already owned by another customer; signup collision; disconnect and
reconnect preserving the local customer. Test invalid UserInfo subject, issuer,
audience, signature, state, nonce and PKCE. Do not stub these authorization checks.

References: [OIDC scope claims](https://openid.net/specs/openid-connect-core-1_0.html#ScopeClaims),
[OIDC identity stability](https://openid.net/specs/openid-connect-core-1_0.html#ClaimStability),
[openid-client](https://github.com/panva/openid-client), and
[subject-bound UserInfo](https://github.com/panva/openid-client/blob/main/docs/functions/fetchUserInfo.md).
