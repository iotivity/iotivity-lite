#!/bin/bash
#Iotivity-constrained build procedure on TizenRT

init=false
copy=false

os_dir="$(pwd)"

external=$os_dir/../external
apps=$os_dir/../apps
current_dir=../

echo "$os_dir"

cd ../external

directory_name="iotivity-constrained"

if [ -d $directory_name  ]
then
	echo "Directory already exists"
else
	mkdir $directory_name
fi

cd iotivity-constrained/

pwd

if [ -d $directory_name ]
then
	pwd
	cd iotivity-constrained
else
	if [ ! $init ]
	then
		git clone --recursive https://gerrit.iotivity.org/gerrit/iotivity-constrained && (cd iotivity-constrained && curl -kLo `git rev-parse --git-dir`/hooks/commit-msg https://gerrit.iotivity.org/gerrit/tools/hooks/commit-msg; chmod +x `git rev-parse --git-dir`/hooks/commit-msg)
		init=ture
	else
		echo "iotivity-constrained code was cloned"
	fi
fi

constrained_dir="$(pwd)"

echo "$constrained_dir"

git branch -a

git checkout remotes/origin/samsung

pwd

if [ ! $copy ]
then
cp -r port/tizenrt/iotlite_apps/ $apps

cp -r apps/st_app $apps/iotlite_apps/

cp -r apps/st_app/tizenrt/Make* $apps/iotlite_apps/st_app/

cp port/tizenrt/scripts/Makefile $current_dir

cp port/tizenrt/scripts/Make.defs $current_dir

cp -r apps/tizenrt/configs/artik053/iotlite/ $os_dir/../build/configs/artik053/

else
	echo "copied all the directories onto TizenRT"
fi

cd $os_dir

cd tools; ./configure.sh artik053/iotlite; cd ..; make

