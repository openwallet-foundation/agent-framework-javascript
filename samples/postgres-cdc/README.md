This is a working CDC example for a local Postgres 12 / Redis.
It relies on wal2json for change notifications, see https://github.com/eulerto/wal2json.
It uses redis-cli to publish the notifications.

Demo usage:

- the CDC'ed database must pre-exist, it should first be created as follows
- run `cd cdc`
- run `docker run -p 5432:5432 -v ./postgres-data:/var/lib/postgresql/data -e POSTGRES_USER=postgres -e POSTGRES_PASSWORD=postgres postgres:12.16`
- using a postgresql client, create the 'test_db' database and a table
- Ctrl-C the docker container started above
- now run `docker compose up -d`
- checking configuration:

  - from docker desktop, open a terminal to redis container
  - from that terminal, run `redis-cli SUBSCRIBE test_db_changes`
  - using a postgresql client, perform some inserts, updates or deletes in the 'test_db' database

Real usage:

- you need to configure the env variables of the postgres service in the docker-compose.yml file
- the database name should be set to the messages repository name configured for the mediator
