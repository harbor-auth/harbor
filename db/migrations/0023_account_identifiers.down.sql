SET lock_timeout = '3s';
SET statement_timeout = '30s';
DROP TRIGGER users_erase_identifiers ON users;
DROP FUNCTION erase_account_identifiers();
DROP TABLE account_identifiers;
