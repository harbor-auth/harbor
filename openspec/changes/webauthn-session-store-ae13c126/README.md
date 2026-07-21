# webauthn-session-store

Redis-backed WebAuthn session store for multi-replica safety, replacing InMemorySessionStore with SET NX EX saves and Lua atomic GET+DEL takes.
