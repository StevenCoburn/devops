The Home Assistant config requires some manual first-time config. The steps below only need to be ran once.

- Disable telemetry
  - Edit postgresql.conf and set `timescaledb.telemetry_level=off`
- Create database, users, passwords, and change postgres password
- ```bash
  docker exec -it hass-db bash
  psql -U postgres
  ```
- ```sql
  ALTER USER postgres WITH PASSWORD '<PASSWORD>';
  CREATE USER homeassistant WITH PASSWORD '<PASSWORD>';
  CREATE USER grafana_reader WITH PASSWORD '<PASSWORD>';
  CREATE DATABASE homeassistant WITH encoding = 'UTF8';
  ALTER DATABASE homeassistant OWNER TO homeassistant;
  GRANT CONNECT ON DATABASE homeassistant TO grafana_reader;
  \c homeassistant
  CREATE EXTENSION IF NOT EXISTS timescaledb;
  GRANT SELECT ON ALL TABLES IN SCHEMA public TO grafana_reader;
  ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO grafana_reader;
  GRANT SELECT, USAGE ON ALL SEQUENCES IN SCHEMA public TO grafana_reader;
  ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, USAGE ON SEQUENCES TO grafana_reader;
  \q
  ```

The first time the LTSS is used, it must have superadmin (postrgres user) access to the database to install extensions. After that, it can use the homeassistant user.
