#! /bin/sh

INFILE=testfile
PWFILE="pwfile.txt"
PWFILE2="pwfile_2.txt"
# V=valgrind

set -x

#export SORBET_USE_TRAILER=0

rm -fv tmp_*

time ./sorbet -e $PWFILE $INFILE tmp_1_$$ 2>/dev/null
echo is: $? should be: 0
time ./sorbet -d $PWFILE tmp_1_$$ tmp_2_$$ 2>/dev/null
echo is: $? should be: 0
time ./sorbet -d ${PWFILE2} tmp_1_$$ tmp_3_$$ 2>/dev/null
echo is: $? should be: 2
