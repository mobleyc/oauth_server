-- Database: oauth
-- Copied from https://gist.github.com/fernandomantoan/3ff4b90d7e9eae4a5d1e

-- DROP DATABASE oauth;

/*
CREATE DATABASE oauth
  WITH OWNER = postgres
       ENCODING = 'UTF8'
       TABLESPACE = pg_default
       LC_COLLATE = 'English_United States.1252'
       LC_CTYPE = 'English_United States.1252'
       CONNECTION LIMIT = -1;
*/

GRANT connect ON DATABASE oauth TO oauth_user;
GRANT USAGE ON SCHEMA public to oauth_user;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO oauth_user;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO oauth_user;


-- Used by JdbcClientDetailsService
create table oauth_client_details (
  client_id VARCHAR(256) PRIMARY KEY,
  resource_ids VARCHAR(256),
  client_secret VARCHAR(256),
  scope VARCHAR(256),
  authorized_grant_types VARCHAR(256),
  web_server_redirect_uri VARCHAR(256),
  authorities VARCHAR(256),
  access_token_validity INTEGER,
  refresh_token_validity INTEGER,
  additional_information VARCHAR(4096),
  autoapprove VARCHAR(256)
);

-- Used by JdbcClientTokenServices
-- Index on authentication_id
-- token_id - Primary key?
create table oauth_client_token (
  token_id VARCHAR(256),
  token bytea,
  authentication_id VARCHAR(256),
  user_name VARCHAR(256),
  client_id VARCHAR(256)
);

-- Used by JdbcTokenStore
-- Index on authentication_id, (user_name, client_id), client_id, user_name, refresh_token?
-- token_id - Primary key?
create table oauth_access_token (
  token_id VARCHAR(256),
  token bytea,
  authentication_id VARCHAR(256),
  user_name VARCHAR(256),
  client_id VARCHAR(256),
  authentication bytea,
  refresh_token VARCHAR(256)
);

-- Used by JdbcTokenStore
-- token_id - Primary key?
create table oauth_refresh_token (
  token_id VARCHAR(256),
  token bytea,
  authentication bytea
);

-- Used by JdbcAuthorizationCodeServices
create table oauth_code (
  code VARCHAR(256), authentication bytea
);

-- Used by JdbcApprovalStore
create table oauth_approvals (
  userId VARCHAR(256),
  clientId VARCHAR(256),
  scope VARCHAR(256),
  status VARCHAR(10),
  expiresAt TIMESTAMP,
  lastModifiedAt TIMESTAMP
);
