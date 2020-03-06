#! /bin/bash

# Copyright (c) 2020 Intel Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Usage instructions
#------------------------------------------------------------------------------
# This script is specifically designed to be run by the CI build. It can be run
# locally by copying this file to top directory of the iotivity-lite project.
# The `_clang-format` file must also be copied to the top directory of the
# iotivity-lite project.
#
#    cp tools/_clang-format _clang-format
#    cp tools/whitespace_commit_checker.sh whitespace_commit_checker.sh
#    ./whitespace_commit_checker.sh
#
# This only checks C/C++ files committed as in the last code commit.
# See tools/README if for instructions on how to run clang-format on more code
#------------------------------------------------------------------------------

# function to check for C/C++ file based on suffix
function isC() {
  if [[ ($1 == *.c) || ($1 == *.C) || ($1 == *.cc) ]]; then
    return 0
  elif [[ ($1 == *.cpp) || ($1 == *.cxx) || ($1 == *.c++) || ($1 == *.CPP) ]]; then
    return 0
  elif [[ ($1 == *.h) || ($1 == *.hpp) ]]; then
    return 0
  fi
  return 1
}

# trap will increment the 'failures' variable each time a one of the commands
# from this script returns failure. The diff command should return failure
# every time the output from clang-format is different than the input file.
failures=0
fail_filelist=""
trap 'failures=$((failures+1))' ERR

echo "***********************************************************************"
echo "RUNNING clang-format tool against committed code"
echo "***********************************************************************"

# Obtain a list of Added (A), Copied (C), Modified (M) and Renamed (R) files
# This will prevent running the script on deleted files.
filelist=`git diff --diff-filter=ACMR --name-only HEAD~1 HEAD`

for f in $filelist; do
  if isC $f; then
    echo "Running clang-format on ${f}"
    echo ""
    # the '-' at the end of the diff will cause the diff command to use the
    # output from clang-format as part of the diff input.
    clang-format -style=file ${f} | diff -u --color=auto ${f} -
    if [ $? -ne 0 ]; then
      fail_filelist+="${f} "
    fi
  fi
done

if (( failures == 0)); then
  echo "***********************************************************************"
  echo "GOOD formating."
  echo "***********************************************************************"
  exit 0;
else
  # A list of files that actually had white space issues was not kept this will
  # just print all of the C/C++ files. Even if the user runs a command on a file
  # that does not need to be change it will leave the file unchanged.
  echo "***********************************************************************"
  echo "Found $failures file(s) with BAD formatting!"
  echo ""
  echo "Please update the files formatting."
  echo ""
  echo "This can be done automatically by running the following commands from"
  echo "the top directory of iotivity-lite project"
  echo ""
  echo "    cp tools/_clang-format _clang-format"
  for f in $fail_filelist; do
      echo "    clang-format -style=file -i ${f}"
  done
  echo ""
  echo "The format tool can be added to git's pre-commit hook using the"
  echo "following command"
  echo ""
  echo "    cp tools/_clang-format _clang-format"
  echo "    cp tools/pre-commit .git/hooks/pre-commit"
  echo ""
  echo "Reference the tools/README file for more information about setting up"
  echo "and using the clang-format tool for formatting contributed code."
  echo "***********************************************************************"
  exit 1
fi