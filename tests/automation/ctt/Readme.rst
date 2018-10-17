This document explains how to automate test runs of required test cases on CTT using TAF (Test Automation Framework) agent.
---------------------------------------------------------------------------------------------------------------------------

TAF agent is an automation tool that automates manual operations of user,
during the process of running the test cases on Conformance Test Tool using the CertificationApp.

Pre-conditions:
---------------
CertificationApp needs to be built in ‘linux/port’ folder.
CTT version 2.1.0.0

Steps to be followed:
---------------------

1. The test case number of the test case on CTT that needs to be run has to be mentioned in the server_config.txt file.

2. The dependent packages are to be installed by running run_taf_agent.sh [Terminal command- ./run_taf_agent.sh]

3.Generate the tafagent.exe [Terminal command- make (at ctt folder)].

4.Run the tafagent by giving the following terminal command (at ctt folder):
./tafagent server_config.txt 1 6 11 1.3 1 6

[Arguments passed in the above command(from left to right) are to make below mentioned selections
1 - QOS_CON
6 - IPv6
11 - security
1.3 - OCF version
1(Create Normal Resource) and 6(Create Group Resource) options on CertificationApp]

After above command execution, open CTT and go to 'Test Run->Automation'
------------------------------------------------------------------------

->Set the appropriate ‘NetworkInterface’ and set the following port values

->Basic API port as :32000

->Extended API port as: 32001

->Setup API port as:32002

->Set ‘Remote IP address’ be the IP address of Linux machine that runs the tafagent

->Then select the following using check boxes:  Basic API, Extended API and Setup API

->Then press ‘Connect’

CTT then connects to TAF agent, following which TAF agent would communicate with CertificationApp.