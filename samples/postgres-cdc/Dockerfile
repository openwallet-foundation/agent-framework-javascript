FROM postgres:12.16

RUN apt-get update
RUN apt-get install -y postgresql-12-wal2json
RUN apt-get install -y redis-tools

COPY startup.sh .

ENV CDC_DB_NAME=CDC_DB_NAME

ENV REDIS_HOST=REDIS_HOST
ENV REDIS_PORT=6379
ENV REDIS_CHANNEL=REDIS_CHANNEL

USER postgres
CMD ./startup.sh