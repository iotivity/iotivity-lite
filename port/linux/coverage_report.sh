#!/bin/sh

make test
mkdir coverage_report
lcov -c -d . -o coverage_report/new_coverage.info && lcov --remove coverage_report/new_coverage.info 'port/*' '/usr/include/*' 'api/unittest/*' -o coverage_report/main_coverage.info

genhtml coverage_report/main_coverage.info --output-directory coverage_report/


