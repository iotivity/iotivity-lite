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

rm -rf memory_profile
rm -rf massif.out.*

mkdir memory_profile

valgrind --tool=massif ./$1

mv massif.out.* memory_profile/

#run and view profile graph 
#massif-visualizer memory_profile/massif.out.*
