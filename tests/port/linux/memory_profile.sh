#!/bin/sh

#required tool
#sudo apt-get install valgrind
#sudo apt-get install massif-visualizer
#
#usages
#./memory_profile.sh <sampleapp>
#it will generate memory profile file on memory_profile/massif.out.*
#download and open with massif-visualizer to view memory usage.

echo $1

iotivity="$PWD"
echo $iotivity

root_dir="${iotivity}/../../.."
linux_dir="${root_dir}/port/linux/"
#main_dir=  ${root_dir}/${linux_dir}
cd $linux_dir

rm -rf memory_profile
rm -rf massif.out.*

mkdir memory_profile

valgrind --tool=massif --time-unit=B --stacks=yes --heap=yes ./$1
ms_print massif.out.* >> memory_profile/memory_log.txt
awk '/KB/{getline;gsub("[:^]","");print $1}' memory_profile/memory_log.txt >> memory_profile/memory_usage.txt

mv massif.out.* memory_profile/

# make with memtrace to get unreachable memory with the address function

make cleanall
make MEMTRACE=1
make test MEMTRACE=1
./$1 >> memory_profile/unreachable_memory_log.txt



