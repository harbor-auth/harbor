-- Additive: legacy and federated accounts need not have identifiers.
SET lock_timeout = '3s';
SET statement_timeout = '30s';
CREATE TABLE account_identifiers (
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    region text NOT NULL,
    kind text NOT NULL,
    lookup_hash bytea NOT NULL,
    encrypted_value bytea NOT NULL,
    verified_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, kind),
    UNIQUE (region, kind, lookup_hash)
);
-- Erasure must remove the keyed lookup as well as destroy the value's DEK.
CREATE FUNCTION erase_account_identifiers() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.status = 'erased' THEN
        DELETE FROM account_identifiers WHERE user_id = NEW.id;
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER users_erase_identifiers AFTER UPDATE OF status ON users
FOR EACH ROW EXECUTE FUNCTION erase_account_identifiers();
