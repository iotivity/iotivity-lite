#!/bin/sh


match='-pedantic'
insert='-pedantic -ftest-coverage -fprofile-arcs'
file='Makefile'

iotivity="$PWD"

root_dir="${iotivity}/../../.."
linux_dir="${root_dir}/port/linux/"
cd $linux_dir


sed -i "s/$match/$insert/" $file

make clean
make qa_test
mkdir ${iotivity}/coverage_report
lcov -c -d ../../ -o ${iotivity}/coverage_report/new_coverage.info && lcov --remove ${iotivity}/coverage_report/new_coverage.info 'port/unittest/*' '/usr/include/*' 'api/unittest/*' -o ${iotivity}/coverage_report/main_coverage.info

genhtml ${iotivity}/coverage_report/main_coverage.info --output-directory ${iotivity}/coverage_report/

sed -i "s/$insert/$match/" $file


