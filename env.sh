#!/bin/sh
if [ `uname -m` = "x86_64" ]; then
  export USE_64=1
fi

pushd nss/tests/common
OBJ=`make objdir_name`
popd

export LD_LIBRARY_PATH=`pwd`/dist/$OBJ/lib/:`pwd`/iniparser:$LD_LIBRARY_PATH
export PATH=`pwd`/dist/$OBJ/bin/:$PATH
export PYTHONPATH=`pwd`/stem:$PYTHONPATH
