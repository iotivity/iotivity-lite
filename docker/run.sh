#!/usr/bin/env bash
set -e

PREFIX_EXEC=""
if which logbt > /dev/null ; then
    logbt --setup
    PREFIX_EXEC="logbt -- "
fi


echo Spawning $NUM_DEVICES devices

umask 0000
mkdir -p /tmp/logbt-coredumps
pids=()
for ((i=0;i<$NUM_DEVICES;i++)); do
    ${PREFIX_EXEC} /iotivity-lite/port/linux/service $@ > /tmp/$i.log &
    pids+=($!)
done

# Naive check runs checks once a minute to see if either of the processes exited.
# This illustrates part of the heavy lifting you need to do if you want to run
# more than one service in a container. The container exits with an error
# if it detects that either of the processes has exited.
# Otherwise it loops forever, waking up every 60 seconds
while sleep 10; do 
for (( i=0; i<${#pids[@]}; i++ ));
do
    if ! kill -0 ${pids[$i]} 2>/dev/null; then
        echo "service[$i] with pid=${pids[$i]} is dead"
        exit 1
    fi
done
echo checking running devices
done