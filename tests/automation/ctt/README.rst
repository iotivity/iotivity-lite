Getting Started
---------------

- Refer the 'README.rst' in the
`link <https://github.com/iotivity/iotivity-liteS/blob/master/README.rst>`_,
to download the iotivity-lite files and setup the source tree.

- Open iotivity-lite folder, then open a terminal from within that
folder and using ``git pull https://gerrit.iotivity.org/gerrit/iotivity-lite refs/changes/23/26923/38``,
pull the patch having source codes of CertificationApp, tafagent etc.,

Contents
--------

- `Generating CertificationApp.exe`_
- `Steps to be followed to Run TAF Agent along with CTT`_

Generating CertificationApp.exe
-------------------------------

- Move to the folder specified by the path ``iotivity-lite/port/linux``
  and open a terminal from within that folder.

- Generate CertificationApp.exe using ``make -f Makefile``

- Execute CertificationApp using ``./CertificationApp``

- On successfully executing CertificationApp, an options-menu, as shown below,
  having a list of available server and client operations, gets displayed.

	-----------------------------------------------------
	Please Select an option from the menu and press Enter
	-----------------------------------------------------
		0   : Quit Certification App

	Server Operations:
		1   : Create Normal Resource
		2   : Create Invisible Resource
		3   : Create Resource With Complete URL
		4   : Create Secured Resource
		5   : Create 100 Light Resources
		6   : Create Group Resource
		7   : Delete All Resources
		8   : Delete Created Group

	Client Operations:
		9   : Find Introspection
		11  : Find specific type of resource
		12  : Find All Resources
		17  : Send GET Request
		22  : Send POST Request - Partial Update - User Input
		25  : Observe Resource - Retrieve Request with Observe
		26  : Cancel Observing Resource
		31  : Find Group
		33  : Update Group
		34  : Update Local Resource Manually
		107 : Create Air Conditioner Single Resource

Steps to be followed to Run TAF Agent along with CTT
----------------------------------------------------

- The test case numbers(e.g., CT1.1.1, CT1.2.10 etc.,) of test cases on CTT that
  need to be run, have to be mentioned in the ``server_config.txt`` file present
  in ``iotivity-lite/tests/automation/ctt``

- Move to ``iotivity-lite/tests/automation/ctt`` and open a terminal from
  within that folder

- Run ``./run_taf_agent.sh`` to execute run_taf_agent.sh and install the
  dependent packages

- Run ``make`` to generate tafagent.exe

- Run the tafagent using ``./tafagent server_config.txt 1 6 11 1.3 1 6``

    [Arguments passed in the above command(from left to right) are to make
     below mentioned selections
     1 for QOS_CON
     6 for IPv6
     11 for security
     1.3 for OCF version 1.3
     1 for choosing 'Create Normal Resource' option on CertificationApp
     6 for choosing 'Create Group Resource' option on CertificationApp]

- Then open CTT, click on ``Test Run``>``Automation``

- Set the appropriate ``NetworkInterface``

- Set the following port values

  - ``Basic API port`` as: 32000

  - ``Extended API port`` as: 32001

  - ``Setup API port`` as: 32002

- Set ``Remote IP address`` be the IP address of Linux machine that runs the
  tafagent

- Then select ``Basic API``, ``Extended API`` and ``Setup API`` by clicking
  corresponding check boxes.

- Then click ``Connect``

- CTT then connects to TAF agent, following which TAF agent would communicate
  with CertificationApp.