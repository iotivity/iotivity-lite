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
echo "called_from_lib:libfaketimeMT.so.1" > /tmp/tsan.suppressions
# gcc-11 on ubuntu 22.04 with thread sanitizer enabled reports a double lock when
# pthread_cond_signal is called under a locked mutex
# echo "mutex:signal_event_loop" >> /tmp/tsan.suppressions
for ((i=0;i<$NUM_DEVICES;i++)); do
    export ASAN_OPTIONS="atexit=1:log_path=/tmp/${i}.asan.log:verify_asan_link_order=0"
    # abort on first tsan problem found
    export TSAN_OPTIONS="halt_on_error=1:abort_on_error=1:second_deadlock_stack=1:log_path=/tmp/${i}.tsan.log:suppressions=/tmp/tsan.suppressions"
    export LD_PRELOAD=/usr/local/lib/faketime/libfaketimeMT.so.1
    ${PREFIX_EXEC} /iotivity-lite/port/linux/service $@ > /tmp/$i.log 2>&1 &
    pids+=($!)
done

terminate()
{
    echo "Terminate"
    for (( i=0; i<${#pids[@]}; i++ )); do
        kill -SIGTERM ${pids[$i]}
    done
}

trap terminate SIGTERM

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