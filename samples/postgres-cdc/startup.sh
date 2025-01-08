#!/bin/bash

# run postgres in the background so we can run pg_recvlogical
postgres -c wal_level=logical -c max_wal_senders=1 -c shared_preload_libraries=wal2json &
# ensure postgres is fully initialized before running pg_recvlogical
sleep 10s
# create replication slot if required
pg_recvlogical -d test_db --slot ${CDC_DB_NAME}_slot --create-slot --if-not-exists -P wal2json
# need a function for publishing otherwise bash shouts
publish_to_redis() {
  redis-cli -h $REDIS_HOST -p $REDIS_PORT PUBLISH $REDIS_CHANNEL $1
}
# listen to replication messages and publish them to redis
pg_recvlogical -d ${CDC_DB_NAME} --slot ${CDC_DB_NAME}_slot --start -o pretty-print=0 -f - | while read message; do publish_to_redis $message ; done
# uncomment the following if you comment the previous to keep the container running
# tail -f /dev/null
