#!/bin/sh


match='-Wextra'
insert='-Wextra -ftest-coverage -fprofile-arcs'
file='Makefile'
build_command='make test '$@
iotivity="$PWD"

root_dir="${iotivity}/../../.."
linux_dir="${root_dir}/port/linux/"
cd $linux_dir


sed -i "s/$match/$insert/" $file

make clean
echo ${build_command}
${build_command}
mkdir ${iotivity}/coverage_report
lcov -c -d ../../ -o ${iotivity}/coverage_report/new_coverage.info && lcov --remove ${iotivity}/coverage_report/new_coverage.info 'port/unittest/*' 'deps/*' '/usr/include/*' 'api/unittest/*' 'messaging/coap/unittest/*' 'security/unittest/*' 'service/easy-setup/unittest/*' 'service/cloud-access/unittest/*' 'service/resource-directory/client/unittest/*' 'service/fota/unittest/*' 'service/st-app-fw/unittest/*' -o ${iotivity}/coverage_report/main_coverage.info

genhtml ${iotivity}/coverage_report/main_coverage.info --output-directory ${iotivity}/coverage_report/

sed -i "s/$insert/$match/" $file


