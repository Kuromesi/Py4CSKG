#!/bin/bash

hosts=("ftp_server" "mail_server" "web_server" "workstation" "monitor" "database_server")

# stop services
for host in ${hosts[@]}; do
    docker-compose -f $host/docker-compose.yaml down
done

# sleep 10 seconds to down
sleep 10

# stop networks and hosts
docker-compose -f networks/docker-compose.yaml down
docker-compose -f hosts/docker-compose.yaml down