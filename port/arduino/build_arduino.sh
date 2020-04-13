#!/bin/bash
# This script will build iotivity constrained for Arduino#
# Build system: Debian 32/64 Bits
# Author: 	Yann
# Date : 		06-April 2019
# Recipient: 	Iotivity Lite Gerrit

#Note: We use the script file to better handle build dependancies as the arduino makefile system
# used need to be patch before compilation can start: it may be easier to provide a dedicated arduino makefile

#######################################################################
#User interaction functions
#######################################################################
print_headings() {
	echo
	printf "%bBuild an application for iotivity constrained on Arduino(AVR and ARM)%b\n" "$DBG" "$DEFAULT"
	printf "%bBuild system: Linux Debian/Ubuntu%b\n" "$DBG" "$DEFAULT"
	printf "%bBuild Architecture: 32/64 bits%b\n" "$DBG" "$DEFAULT"
	printf "%bArduino path: \$(HOME)/arduino-home, if not set the option --ardhome='path to arduino home' %b\n" "$DBG" "$DEFAULT"
	printf "%bArduino Makefile path: \$(PWD)/Arduino-Makefile, if not set the option --ardmk='path to arduino makefile' %b\n" "$DBG" "$DEFAULT"
	echo
	printf "%busage: \n  -u|--upload)\tBuild and upload an app\n  -c|--clean)\tClean working path\n  -x|--xmem)\tEnable or disbale external memory(only on avr)%b\n" "$WRN" "$DEFAULT"
	printf "%b  -s|--secure)\tEnable or disable\n  ---arch)\tSelect a build architecture (avr/samd/sam)\n  --debug)\tSet log level( 1 / 2)%b\n" "$WRN" "$DEFAULT"
	printf "%b  --app)\tSelect an app (server/client)\n  --ardhome)\tSet path to arduino home\n  --ardmk)\tSet path to arduino makefile\n %b\n" "$WRN" "$DEFAULT"
	echo
	sleep 3
}

install_dependancies(){
	echo "*********************************************************************"
	printf "%b      Installing and updating arduino libraries%b\n" "$DBG" "$DEFAULT"
	echo "*********************************************************************"
	if [ -d $ARDUINO_HOME ]; then
		cd $ARDUINO_HOME/libraries
		for lib in "${LIBS[@]}"; do
			path=`echo $lib | cut -d '|' -f 1`
			if [ ! -d $path ]; then
				remote=`echo $lib | cut -d '|' -f 2`
				printf "%bInstalling missing library: $remote %b\n" "$WRN" "$DEFAULT"
				git clone $remote
			else
				printf "%bCleaning local libray: $path %b\n" "$WRN" "$DEFAULT"
				cd $path
				git clean -fdx .
				git reset --hard
				cd ../
			fi
			patch_file=$BUILD_PATCHES/$path.patch
			if [  -f $patch_file ]; then
				printf "%bApplying patch to $path %b\n" "$WRN" "$DEFAULT"
				patch -r - -s -N -p1 < $patch_file
				printf "%bPatch $patch_file succesfully applied%b\n\n" "$DBG" "$DEFAULT"
			fi
		done
  else
		printf "%bInstall arduino IDE and provide a valid path to proceed%b\n" "$ERR" "$DEFAULT"
		exit 1
	fi
	if [ $ARCH == "samd" ]; then
		SAMD_RANDOM_PATCH_FILE=$BUILD_PATCHES/samd_random.patch
		cd ~/.arduino15/packages/arduino/hardware/samd/1.6.20/cores
		patch -r - -s -N -p1 --dry-run < $SAMD_RANDOM_PATCH_FILE 2>/dev/null
		#If the patch has not been applied then the $? which is the exit status
		#for last command would have a success status code = 0
		if [ $? -eq 0 ]; then
			printf "%bAdding samd basic random support%b\n" "$DBG" "$DEFAULT"
			patch -r - -s -N -p1 < $SAMD_RANDOM_PATCH_FILE
			printf "%bPatch $SAMD_RANDOM_PATCH_FILE  succesfully applied%b\n\n" "$DBG" "$DEFAULT"
		else
			printf "%bRandom support for samd already added%b\n" "$WRN" "$DEFAULT"
		fi
	fi

}
install_arduino_makefile() {
	echo "*********************************************************************"
	printf "%b    Installing and updating arduino makefile%b\n" "$DBG" "$DEFAULT"
	echo "*********************************************************************"
	cd $ROOT
	if [ ! -d $ARDMK_DIR ]; then
		git clone $ARDMK_REMOTE
	else
		cd $ARDMK_DIR
		printf "%bCleaning local repository%b\n" "$WRN" "$DEFAULT"
		git clean -fdx .
		git reset --hard
		cd ../
	fi
	ARDMK_PATCH_FILE=$BUILD_PATCHES/arduino-mk.patch
	if [  -f $ARDMK_PATCH_FILE ]; then
		printf "%bApplying patch to $ARDMK_DIR %b\n" "$WRN" "$DEFAULT"
		patch -r - -s -N -p1 < $ARDMK_PATCH_FILE
		printf "%bPatch $patch succesfully applied%b\n" "$DBG" "$DEFAULT"
	fi
}

update_core_to_arduino() {
	echo "********************************************************************************"
	printf "%b    Enable arduino logs: This add log level to cope for memory constraints%b\n" "$DBG" "$DEFAULT"
	echo "*********************************************************************************"
	IOTIVIY_LITE_PATCH_FILE=$BUILD_PATCHES/iotivity_lite.patch
	cd ../../
	patch -r - -s -N -p1 --dry-run < $IOTIVIY_LITE_PATCH_FILE 2>/dev/null
	#If the patch has not been applied then the $? which is the exit status
	#for last command would have a success status code = 0
	if [ $? -eq 0 ]; then
    printf "%bAdding Arduino support to iotivity sources%b\n" "$DBG" "$DEFAULT"
    patch -r - -s -N -p1 < $IOTIVIY_LITE_PATCH_FILE
	else
		printf "%bSources have already been updated %b\n" "$WRN" "$DEFAULT"
	fi
}

build_application()
{

	echo "*********************************************************************"
	printf "%b      Build and Upload  a User application %b\n" "$DBG" "$DEFAULT"
	echo "*********************************************************************"
	cd $ROOT
  if [ $CLEAN -eq 1 ]; then
	  make ARCH=$ARCH APP=$APP DYNAMIC=1 SECURE=$SECURE IPV4=1 -f Makefile clean
  else
   if [ $UPLOAD -eq 1 ]; then
      make ARCH=$ARCH APP=$APP DYNAMIC=1 SECURE=$SECURE IPV4=1 NO_MAIN=1 XMEM=$XMEM VERBOSE=$VERBOSE -f Makefile upload
   else
      make ARCH=$ARCH APP=$APP DYNAMIC=1 SECURE=$SECURE IPV4=1 NO_MAIN=1 XMEM=$XMEM VERBOSE=$VERBOSE -f Makefile
   fi
  fi
	sleep 3
  echo
}

echo "####################################################################"
echo "#              Initialize build system "
echo "####################################################################"
# saner programming env: these switches turn some bugs into errors
#set -o errexit -o pipefail -o noclobber -o nounset
#Define installation environment
export ARDUINO_USER="$USER"
export ARDUINO_USER_GROUP=$(groups "$ARDUINO_USER" | sed 's/^.*\s:\s\(\S*\)\s.*$/\1/')
export ROOT=$PWD
export ARDUINO_HOME=$HOME/arduino-home
export ARDMK_DIR=$PWD/Arduino-Makefile
export ARDMK_REMOTE="https://github.com/sudar/Arduino-Makefile"

declare -a LIBS=('Ethernet2|https://github.com/adafruit/Ethernet2.git' 'pRNG|https://github.com/leomil72/pRNG.git' 'SdFat|https://github.com/greiman/SdFat.git' 'Time|https://github.com/PaulStoffregen/Time.git' )
export LIBS
export BUILD_PATCHES=$PWD/patches
export VERBOSE=0 # dont use DEBUG as te Arduino.mk set optimization to 0 when defined
export IPV4=1
export SECURE=0
export UPLOAD=0
export DYNAMIC=1
export XMEM=0
export ARCH=avr
export CLEAN=0
export APP='server'
export ERR="\033[31;1m"   # red output
export DBG="\033[32;1m" # greenoutput
export WRN="\033[33;1m" # yellow output
export DEFAULT="\033[0m"    # white output
##################################################

! getopt --test > /dev/null
if [[ ${PIPESTATUS[0]} -ne 4 ]]; then # PIPESTATUS is an array of exits code just like $?( status of last executed command)
    echo 'This requires GNU getopt.  On Mac OS X and FreeBSD, you have to install this separately; see below.'
    exit 1
fi
PARSED=`getopt -o csux --long clean,secure,upload,xmem,app:,arch:,ardmk:,ardhome:,debug:\
             -n '$0' -- "$@"`
if [ $? != 0 ] ; then echo "Terminating..." >&2 ; exit 1 ; fi

eval set -- "$PARSED"
while true; do
  case "$1" in
    -c | --clean ) CLEAN=1; shift ;;
    -s | --secure ) SECURE=1; shift ;;
    -u | --upload ) UPLOAD=1; shift ;;
    -x | --xmem ) XMEM=1; shift ;;
    --app ) APP="$2"; shift 2 ;;
    --arch ) ARCH="$2"; shift 2 ;;
    --ardmk ) ARDMK_DIR="$2"; shift 2 ;;
    --ardhome ) ARDUINO_HOME="$2"; shift 2 ;;
    --debug ) VERBOSE="$2"; shift 2 ;;
    -- ) shift; break ;;
    * ) break ;;
  esac
done
#Process the different installation functions
print_headings
echo "Options: $CLEAN $VERBOSE $SECURE $UPLOAD $XMEM $APP $ARCH $ARDMK_DIR $ARDUINO_HOME"
echo

update_core_to_arduino
install_dependancies
install_arduino_makefile
build_application

exit 0
