#
# Regular cron jobs for the iotivity-constrained package
#
0 4	* * *	root	[ -x /usr/bin/iotivity-constrained_maintenance ] && /usr/bin/iotivity-constrained_maintenance
