#!/bin/bash
## RabbitMQ Queue Monitor .v01 ##

sudo rabbitmqctl -q list_queues -p /<CHANGEME> > /tmp/rabbitqueues

hostname=$("hostname")
threshold="100"
message="The rabbitmq server is having issues. Please investigate.\n"
body=`cat /tmp/rabbitqueues`
# Note: the second and third sed argument need to be adjusted.
cat /tmp/rabbitqueues | sed -e 's/<IGNORE-QUEUES//g' -e 's/IGNORE-QUEUES//g' | grep -o '[0-9]*' | while read line ; do
if [ $line -gt $threshold ]
    then
        echo -e "${message} \n ${hostname}.somedns.com \n \n ${body}" | mail -s "RabbitMQ Server Alert" account@someserver.com

fi
done

