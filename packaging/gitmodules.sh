#! /bin/sh
# @author: Philippe Coval <mailto:philippe.coval@osg.samsung.com>
# @description: manage git submodules with git-build-package-rpm

set -x
set -e

cat .gitmodules || return 1

mkdir -p "./tmp/"

git submodule status | awk '{ print $2 }' | while read dir ; do
    name=$(basename "$dir" )
    echo "name="
    echo "dir=$dir"
    git submodule init
    git submodule update
    mv $dir ./tmp/
    git commit -sm "$name: Remove submodule (to use patch)" "$dir"
    mv ./tmp/$name $dir
    rm -rf $dir/.git
    git add -f "$dir"  &&  git commit -sm "$name: Import as patch" "$dir"
done
