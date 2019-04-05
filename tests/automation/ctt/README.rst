Getting Started
---------------

- Grab source and dependencies using:
  ``git clone https://gerrit.iotivity.org/gerrit/iotivity-lite``
  and setup source tree.
  For more information, please refer `this <https://github.com/iotivity/iotivity-lite/blob/master/README.rst>`_ README.

- Please go `here <https://gerrit.iotivity.org/gerrit/#/c/29300/>`_ and click on ``Download``
  (present on the top right-hand side of the web-page when using old UI OR above all the files on the RHS when using new UI). 
  Copy to clipboard, the ``git pull`` command with the ``https://`` URL.

- Move to iotivity-lite folder on the terminal and run the ``git pull`` command with the URL copied in the previous step so as to pull the patch
  having source codes of CertificationApp, tafagent etc.,

Contents
--------

- `Building CertificationApp and other sample applications on Linux`_
- `Steps to be followed to Run TAF Agent along with CTT`_

Building CertificationApp and other sample applications on Linux
----------------------------------------------------------------

- Move to the ``iotivity-lite/port/linux`` folder on the terminal.

- Generate CertificationApp.exe and other object files by running the below command
  ``make TCP=1 CLOUD=1 IDD=1``

Steps to be followed to Run TAF Agent along with CTT
----------------------------------------------------

- Move to ``iotivity-lite/tests/automation/ctt`` folder on the terminal.

- In "TAFAgent.h" present in "include" folder, set the char variable "globalIPv6_firstHextet[5]" to have the first hextet of the
  global IPv6 address of the machine on which "tafagent" and "CertificationApp" would be run.

- In the configuration file i.e., ``server_config.txt`` or ``client_config.txt`` file, please mention all test case numbers of test cases on CTT(e.g., CT1.1.1, CT1.2.10 etc.,) that need to be run.
  Configuration file should also have relevant PICS details.

- 'run_taf_agent.sh' has required commands to build CertificationApp.c, discover_device.c etc., present in ``iotivity-lite/port/linux`` folder.
  It has ``make`` command to build TAFAgent.c and generate the executable ``tafgent``. Further, it also has the command to run ``tafgent``.

- The command in 'run_taf_agent.sh' to run TAFAgent executable is as follows:
  ``./tafgent configurationFile QoS_arg IPversion_arg Security_arg OCFVersion_arg LocalMachineIPv4Addr_arg IUTInterfaceIndex_arg CTTScopeID TAF_mode CertAppInput1 CertAppInput2``
  E.g.: ``./tafagent server_config.txt 1 6 13 2.0.2 192.168.3.66 2 10 server 1 6``

- Arguments passed in the above line are
      i.    tafgent - TAFAgent.c executable
      ii.   configurationFile - "server_config.txt" to run server testcases or "client_config.txt" to run client testcases
      iii.  QoS_arg - Quality of Service Argument; sets the QoS
      iv.   IPversion_arg - IP version argument (4 or 6)
      v.    Security_arg - Argument that specifies security type(e.g. 13 - manufacturing certificate, 12 - random pin and 11 - Just Works)
      vi.   OCFVersion_arg - Argument that specifies OCF version(e.g. 2.0.2, 2.0.0, 1.3.0 etc.,)
      vii.  LocalMachineIPv4Addr_arg - Specifies the IPv4 address of the machine on which TAFAgent and CertificationApp run.
      viii. IUTInterfaceIndex_arg - Specifies the interface index of the interface on which TAFAgent and CertificationApp run.
      ix.   CTTScopeID - Specifies the scope ID of the interface on which CTT runs
      x.    TAFmode - Should be "server" or "client" depending on what the IUT should run as
      xi.   CertAppInput1 - An input to CertificationApp (e.g. 1 - to create a resource)
      xii.  CertAppInput2 - Another input to CertificationApp (e.g. 6 - to create a Group resource)

- Run ``./run_taf_agent.sh``. This generates following executables: CertificationApp, discover_device and tafgent (It also installs required packages).

- Please ensure that the appropriate ``libuv`` path is mentioned in the ``Makefile`` present in ``iotivity-lite/tests/automation/ctt``.
  (Note: libuv-v1.24.0 has been found to work fine. Some other versions *may* work fine as well).

- After running TAFAgent, please wait till a message saying "Entering TAF Agent main loop..." appears on terminal and then open CTT, click on ``Test Run``and then on ``Automation``

- Set the appropriate ``NetworkInterface``

- Set the following port values

  - ``Basic API port`` as: 32000

  - ``Extended API port`` as: 32001

  - ``Setup API port`` as: 32002

- Set ``Remote IP address`` to be the IP address of Linux machine that runs the tafagent.

- Then select ``Basic API`` and ``Setup API`` by clicking on corresponding check boxes.
  (*Check box corresponding to ``Extended API`` is to be left unchecked*)

- Then click on ``Connect``.

- CTT then connects to TAF agent, following which TAF agent would communicate with CertificationApp.