#!/bin/sh


match='-pedantic'
insert='-pedantic -ftest-coverage -fprofile-arcs'
file='Makefile'

sed -i "s/$match/$insert/" $file

make clean
make test
mkdir coverage_report
lcov -c -d ../../ -o coverage_report/new_coverage.info && lcov --remove coverage_report/new_coverage.info 'port/unittest/*' '/usr/include/*' 'api/unittest/*' -o coverage_report/main_coverage.info

genhtml coverage_report/main_coverage.info --output-directory coverage_report/

sed -i "s/$insert/$match/" $file


