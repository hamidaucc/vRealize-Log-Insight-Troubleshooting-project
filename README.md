# vRealize-Log-Insight-Troubleshooting-script in python
Purpose:
During troubleshooting of LI(Log insight), either on schedule session or EOD transfer or P1 & P2 call ,TSE usually checks  5 different  parts i. e os, storage, networking, Log insight itself and log analysis. It requires an enormous amount of  time to check  all of those parts manually one by one if the cluster has more than one node to discover the issue. To minimize time with less effort , glance at the cluster and  discover known issues, my script[  gss.py] will check all in one go and not only that, but also pull-out common errors and partial errors based on logs.

Objects:

	Scan general status of LI
	Discover issue with min time
	Minimize troubleshooting time
	 Provide KB base on common error
	Self-service to customer


Use cases:

	Cluster is down or not accessible
	Failed to login
	Worker node is not working
	Cluster is too slow
	Upgrade failed
	LI ingestion issue and more

           
          



Examine sector

	Networking : Current server time, ip address, subnet mask, gateway, DNS resolver, NTP, hostname, List of listening open ports, Listening neighbour, Routing, DNS name server info

	Operating system(photon OS): Disk Space info, root space info, Real time view of running process, CPU, memory consumption, storage, memory info, Disk IOPS


	LI(Log Insight): current LI version, uptime, cluster info, root password expires, Total vCPU,hosts
	Log Analysis:
•	Runtime.log
•	ui_runtime.log
•	Cassandra.log
•	system alert.log
•	upgrade.log
•	vSphere.log 
