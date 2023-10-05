#! /bin/sh

INFILE=testfile
PWFILE="pwfile.txt"
PWFILE2="pwfile_2.txt"
#V=valgrind
#VOPT="--track-origins=yes --leak-check=full"

# this is a prime
COUNT=37199

#set -v -x

#export SORBET_CPUS=2
#export SORBET_NUMBLOCKS=2
#export SORBET_BLOCKSIZE=4096
#export SORBET_USE_TRAILER=1

LOG=log

i=16300
m=20000

while [[ $i -lt $m ]]
do

  rm -fv tmp_*

  X="$(expr $COUNT \* $i)"

  date >>$LOG
  echo bs=$i count=$COUNT total=$X >>$LOG

  dd if=$INFILE bs=$i count=$COUNT |$V $VOPT ./sorbet -e $PWFILE >tmp_1_$$
  if ./sorbet -d $PWFILE <tmp_1_$$ >tmp_2_$$
  then
    echo PASSED >>$LOG
    echo >>$LOG
  else
    echo '*****' FAILED '*****' >>$LOG
    echo '***********************************' >>$LOG
    echo >>$LOG
    exit 10
  fi

  i=$(($i + 1))

done
