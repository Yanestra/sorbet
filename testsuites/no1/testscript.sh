#! /bin/sh

INFILE=testfile
PWFILE="pwfile.txt"
PWFILE2="pwfile_2.txt"
#V=valgrind
#VOPT="--track-origins=yes --leak-check=full"

set -e -v

#export SORBET_USE_TRAILER=0

rm -fv tmp_*

cat $INFILE |$V $VOPT ./sorbet -e $PWFILE >tmp_1_$$
./sorbet -d $PWFILE <tmp_1_$$ >tmp_2_$$
./sorbet -d ${PWFILE2} <tmp_1_$$ >tmp_3_$$
