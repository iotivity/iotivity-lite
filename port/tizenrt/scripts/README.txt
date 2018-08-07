#############  TizenRT building steps ###################

step1:
	clone TizneRT from below mentioned link:

	https://github.com/Samsung/TizenRT/releases (download:  2.0_GBM_M1 stable release)

step2:
	create new directory with the same name "iotivity-constrained" inside the external folder in TizneRT.
	Ex:
		cd external
		mkdir iotivity-constrained

step3:
	Change the directory after creating the new directory
	Ex:
		cd iotivity-constrained

step4:
	clone iotivity-constrained code from open source
	Ex:
		git clone --recursive https://gerrit.iotivity.org/gerrit/iotivity-constrained

step5:
	checkout to samsung branch.
	Ex:
		git branch -a
		git checkout remotes/origin/samsung

step6:
	Run the Shell script from below mentioned directory path
	Ex:
		cd iotivity-constrained/port/tizenrt/scripts
		sh auto_build_TizenRT.sh

step7:
	change the directory to "os" folder in TizneRT and run the make.
	Ex:
		make
