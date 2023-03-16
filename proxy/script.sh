#!/bin/bash
port="9087"
forbidden="forbidden_sites.txt"
log="access.log"
site="http://www.example.com"
path="/"

for j in {1..10}
do
	for i in {1..50}
	do
        	curl -x http://127.0.0.1:$port/ $site$path -I > ${i} &
	done

	wait

	curl https://$site$path -I > out

	for i in {1..50}
	do
		diff out ${i}
		rm ${i}
	done
done

pkill -f "./bin/myproxy $port $forbidden $log"
