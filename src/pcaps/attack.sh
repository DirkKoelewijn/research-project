#!/usr/bin/env bash

device=eno1
capacity=900

echo "Replaying attack '$1' with normal traffic from '$2' on '${device}' with attack ratio $3 for $4 seconds..."


attack(){
    cmd="sudo tcpreplay -M $2 -l 100000 --duration=$3 -i ${device} $1"
    echo "> ${cmd}"
    ${cmd}
    return 0
}

ac=$(bc -l <<<"scale=0;$capacity*$3")

attack $1 ${ac%.*} $4 &
P1=$!
attack $2 $((capacity - ${ac%.*})) $4 &
P2=$!
wait ${P1} ${P2}
echo "Completed"