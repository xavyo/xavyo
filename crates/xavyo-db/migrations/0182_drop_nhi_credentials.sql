-- Drop NHI credential tables — auth via OAuth2 client_credentials exclusively
DROP TABLE IF EXISTS nhi_credentials CASCADE;
DROP TABLE IF EXISTS gov_nhi_credentials CASCADE;
DROP TYPE IF EXISTS gov_nhi_credential_type CASCADE;
