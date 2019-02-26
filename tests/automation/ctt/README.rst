Getting Started
---------------

- Grab source and dependencies using:
  ``git clone --recursive https://github.com/iotivity/iotivity-lite.git``
  and setup source tree. 
  For more information, please refer `this <https://github.com/iotivity/iotivity-lite/blob/master/README.rst>`_ README. 

- Please go `here <https://gerrit.iotivity.org/gerrit/#/c/29300/>`_ and click on ``Download``
  present on the top right-hand side of the web-page. Copy to clipboard, the ``git pull`` command with the ``https://`` URL.

- Move to iotivity-lite folder on the terminal and run the ``git pull`` command with the URL copied in the previous step so as to pull the patch having source codes of CertificationApp, tafagent etc., 

Contents
--------

- `Building CertificationApp and other sample applications on Linux`_
- `Steps to be followed to Run TAF Agent along with CTT`_

Building CertificationApp and other sample applications on Linux
----------------------------------------------------------------

- Move to the ``iotivity-lite/port/linux`` folder on the terminal.

- Generate CertificationApp.exe and other object files by running the below command
  ``make -f Makefile TCP=1``

Steps to be followed to Run TAF Agent along with CTT
----------------------------------------------------

- Mention all test case numbers(e.g., CT1.1.1, CT1.2.10 etc.,) of test cases on CTT that
  need to be run, in the ``server_config.txt`` file present in ``iotivity-lite/tests/automation/ctt`` folder. ``server_config.txt`` would also have relevant PICS details.

- Move to ``iotivity-lite/tests/automation/ctt`` folder on the terminal.

- Run ``./run_taf_agent.sh`` to execute run_taf_agent.sh and install dependent packages. 

- Please ensure that the appropriate ``libuv`` path is mentioned in the ``Makefile`` present in ``iotivity-lite/tests/automation/ctt``.
  (Note: libuv-v1.24.0 has been found to work fine. Some other versions may work fine as well)  

- Run ``make`` to generate tafagent.exe

- Run TAFAgent, *for instance*, as mentioned below
  ``./tafagent server_config.txt 1 6 13 2.0 1 6``

    [Arguments passed in the above command after server_config.txt are to make below mentioned selections: 
     1 for QOS_CON
     6 for IPv6
     13 for security
     2.0 for OCF version 2.0
     1 for choosing 'Create Normal Resource' option on CertificationApp
     6 for choosing 'Create Group Resource' option on CertificationApp]

    Note: Above mentioned arguments being passed to tafagent would change according to the need.

- After running TAFAgent, please wait till a message saying "Entering TAF Agent main loop..." appears on terminal and then open CTT, click on ``Test Run``and then on ``Automation``

- Set the appropriate ``NetworkInterface``

- Set the following port values

  - ``Basic API port`` as: 32000

  - ``Extended API port`` as: 32001

  - ``Setup API port`` as: 32002

- Set ``Remote IP address`` to be the IP address of Linux machine that runs the tafagent.

- Then select ``Basic API`` and ``Setup API`` by clicking on corresponding check boxes.
  (Check box corresponding to ``Extended API`` is to be left unchecked)

- Then click on ``Connect``.

- CTT then connects to TAF agent, following which TAF agent would communicate with CertificationApp.