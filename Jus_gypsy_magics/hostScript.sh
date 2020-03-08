#!/bin/bash
# This script calls the given script making use of the following variables
# $1 script to run
# $2 start-delay
# $3 total-runs
# $4 downtime
# $5 host IP
# $6 port
# $7 runtime

sleep $2;
for i in `seq 1 $3`;
do
    sudo ./$1 $5 $6 &
    # need to include runtime, probably by killing process after t time
    # if runtime = 0 run for ever?? this might just be stupid though
    pid=$!
    if [ $7 != "0" ]
	then
		sleep $7;
		kill -9 $pid;
	fi
    sleep $4;
done
