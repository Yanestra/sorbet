#! /bin/sh
if [ $(echo -n I |od -to2 |awk 'FNR==1{ print substr($2,6,1)}') -gt 0 ]
then
    echo BYTEORDER=L >byteorder.mak
else
    echo BYTEORDER=B >byteorder.mak
fi
