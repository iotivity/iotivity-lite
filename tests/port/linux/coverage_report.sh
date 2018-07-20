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
lcov -c -d ../../ -o ${iotivity}/coverage_report/new_coverage.info && lcov --remove ${iotivity}/coverage_report/new_coverage.info '/home/antu/git/oictest_repo/IotivityOrgSource/last/constrained_test/port/unittest/*' '/home/antu/git/oictest_repo/IotivityOrgSource/last/constrained_test/deps/*' '/usr/include/*' '/home/antu/git/oictest_repo/IotivityOrgSource/last/constrained_test/api/unittest/*' '/home/antu/git/oictest_repo/IotivityOrgSource/last/constrained_test/messaging/coap/unittest/*' '/home/antu/git/oictest_repo/IotivityOrgSource/last/constrained_test/security/unittest/*' '/home/antu/git/oictest_repo/IotivityOrgSource/last/constrained_test/service/easy-setup/unittest/' '/home/antu/git/oictest_repo/IotivityOrgSource/last/constrained_test/service/cloud-access/unittest/*' '/home/antu/git/oictest_repo/IotivityOrgSource/last/constrained_test/service/resource-directory/client/unittest/*' '/home/antu/git/oictest_repo/IotivityOrgSource/last/constrained_test/service/fota/unittest/*' '/home/antu/git/oictest_repo/IotivityOrgSource/last/constrained_test/service/st-app-fw/unittest/*' -o ${iotivity}/coverage_report/main_coverage.info

genhtml ${iotivity}/coverage_report/main_coverage.info --output-directory ${iotivity}/coverage_report/

sed -i "s/$insert/$match/" $file


