#!/bin/bash
if [ `uname -m` = "x86_64" ]; then
  USE_64=1
fi

cd sphere-probe

if test "$1" = "clean-only"
then
	make -s clean
	exit
fi

if test "$1" = "clean"
then
	make -s clean
fi
make
cd ..
