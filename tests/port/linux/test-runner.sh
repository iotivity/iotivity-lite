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

currentDir="$PWD"
rootDir="../.."

memProfileScript="${currentDir}/${rootDir}/tests/port/linux/memory_profile.sh"
configFile="${currentDir}/${rootDir}/tests/port/linux/configFile.txt"

ReadConfig()
{
  . ${configFile}
  echo -e "  Read Memory Profile Configuration: ${MEMORY_TEST} ${MEMORY_TRACE} ${MEMORY_PROFILE} ${MEMORY_APP_NOT_TEST}"
  echo
}

doMemoryProfileTest()
{
	if [ ${MEMORY_APP_NOT_TEST} != ${testApp} ]
	then
		bash ${memProfileScript} ${MEMORY_TRACE} ${MEMORY_PROFILE} ${testApp}
	fi
}


testApp="${1}"

ReadConfig

if [ ${MEMORY_TEST} == "yes" ]
then
	doMemoryProfileTest
fi
