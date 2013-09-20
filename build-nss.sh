#!/bin/bash
if [ `uname -m` = "x86_64" ]; then
  USE_64=1
fi

cd nss

if test "$1" = "clean-only"
then
	make -s nss_clean_all
	exit
fi

if test "$1" = "clean"
then
	make -s nss_clean_all
fi
make nss_build_all
cd ..
