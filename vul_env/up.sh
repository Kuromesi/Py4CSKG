#!/bin/bash

hosts=("ftp_server" "mail_server" "web_server" "workstation" "monitor" "database_server")

# configure networks and hosts
docker-compose -f networks/docker-compose.yaml up -d
docker-compose -f hosts/docker-compose.yaml up -d

# sleep 5 seconds to start up
sleep 5

# configure services
for host in ${hosts[@]}; do
    docker-compose -f $host/docker-compose.yaml up -d
done