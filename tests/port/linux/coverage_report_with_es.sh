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
make test EASYSETUP=1 DYNAMIC=1
mkdir ${iotivity}/coverage_report_with_es
lcov -c -d ../../ -o ${iotivity}/coverage_report_with_es/new_coverage.info && lcov --remove ${iotivity}/coverage_report_with_es/new_coverage.info 'port/unittest/*' '/usr/include/*' 'api/unittest/* service/easy-setup/unittest/' -o ${iotivity}/coverage_report_with_es/main_coverage.info

genhtml ${iotivity}/coverage_report_with_es/main_coverage.info --output-directory ${iotivity}/coverage_report_with_es/

sed -i "s/$insert/$match/" $file


