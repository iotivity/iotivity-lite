#! /bin/bash
if doxygen doxygen.ini ;
then
  [ ! -s Doxygen.log ]
  if [ $? -eq 0 ]
  then
    exit 0
  else
    cat Doxygen.log
    exit 1
  fi
else
  exit 1
fi

