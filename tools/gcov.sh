#!/bin/sh

# Gcov Html generation
#Append CCFLAGS = ['-ftest-coverage' , '-fprofile-arcs']
#Append LIBS = ['gcov']

NUMFILES=$(find . -type f -name *.gcda | wc -l)

echo -n "generating report for: $NUMFILES files.."

#verbose
verbose=false

#gcovr filter
filter=" -f.*security.* "

#exclude
exclude=" -e.*deps.* -e.*port.* -e.*\.cpp "

#out dir
result_dir="gcov/$(date '+%Y%m%d_%H%M%S')"
result_index="$result_dir/index.html"

mkdir -p $result_dir

RUN="gcovr -r . --html --html-details"

#if [ $filter ]; then
RUN="$RUN $filter $exclude"
#fi

if [ $verbose = true ]; then
RUN=$RUN" -v"
fi

RUN=$RUN" -o $result_index"

eval $RUN

echo "Done"
echo "Out dir: $result_dir"

#ls -l $result_dir

if [ -e "$result_index" ]; then
#	chromium $result_index
	firefox $result_index
fi

