SET lock_timeout = '3s';
SET statement_timeout = '30s';

-- NULL identifies legacy registrations whose authenticator flags were lost.
-- They are initialized only after a successfully signed assertion. In
-- particular, false backup eligibility must never stand in for unknown.
ALTER TABLE credentials ADD COLUMN webauthn_flags smallint
    CHECK (webauthn_flags BETWEEN 0 AND 255);
