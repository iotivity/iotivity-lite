#!/bin/bash
# ****************************************************************************
# *
# * Copyright 2018 Samsung Electronics All Rights Reserved.
# *
# * Licensed under the Apache License, Version 2.0 (the "License");
# * you may not use this file except in compliance with the License.
# * You may obtain a copy of the License at
# *
# * http://www.apache.org/licenses/LICENSE-2.0
# *
# * Unless required by applicable law or agreed to in writing,
# * software distributed under the License is distributed on an
# * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# * either express or implied. See the License for the specific
# * language governing permissions and limitations under the License.
# *
# ****************************************************************************/

set -e
set -x

currentDir="$PWD"
rootDir="../.."

testApp="${1}"

memProfileScript="${currentDir}/${rootDir}/tests/port/linux/memory_profile.sh"
configFile="${currentDir}/${rootDir}/tests/port/linux/configFile.txt"

function readConfig()
{
	. ${configFile}
	echo -e "  Read Memory Profile Configuration: ${TEST_APP_RUN}"
	echo -e "  Read Memory Profile Configuration: ${TEST_MEMORY_APP} ${MEMORY_TRACE} ${MEMORY_PROFILE} ${MEMORY_APP_NOT_TEST}"
	echo
}

function doMemoryProfileTest()
{
	if [ ${MEMORY_APP_NOT_TEST} != ${testApp} ]
	then
		bash ${memProfileScript} ${MEMORY_TRACE} ${MEMORY_PROFILE} ${testApp}
	fi
}

function doRunTestApp()
{
	./${testApp}
}

readConfig

if [ "${TEST_RUN}" == "0" ]
then
	#noting to do
	echo -e ""
	exit
fi

if [ "${TEST_APP_RUN}" == "yes" ]
then
	doRunTestApp
fi

if [ "${TEST_MEMORY_APP}" == "yes" ]
then
	doMemoryProfileTest
fi
