#!/bin/bash
export DO_TOKEN='dop_v1_bad1fd8998ad71913963e0b5427ecd50d2c18f4fee52eceaa5927707a0a4c566'
IP='143.198.241.217'
ID=$(curl -s http://169.254.169.254/metadata/v1/id)
HAS_RESERVED_IP=$(curl -s http://169.254.169.254/metadata/v1/reserved_ip/ipv4/active)

if [ $HAS_RESERVED_IP = "false" ]; then
    n=0
    while [ $n -lt 10 ]
    do
        python /usr/local/bin/assign-ip $IP $ID && break
        n=$((n+1))
        sleep 3
    done
fi
