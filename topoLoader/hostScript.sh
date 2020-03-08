#!/bin/bash
# This script calls the given script making use of the following variables
# $1 script to run
# $2 start-delay
# $3 total-runs
# $4 downtime
# $5 selfIP
# $6 selfPort
# $7 targetIP
# $8 targetPort
# $9 trafficClass
# $10 runtime



sleep $2;
for i in `seq 1 $3`;
do
    sudo ./$1 $5 $6 $7 $8 $9 &

    # if runtime = 0 run for ever?? this might just be stupid though
    pid=$!
    if [ ${10} != "0" ]
	then
		sleep ${10};
		ps axf | grep "python ./$1 $5 $6 $7 $8 $9" | grep -v grep | awk '{print "kill -9 " $1}'|sh;
		
	fi
    sleep $4;
done
