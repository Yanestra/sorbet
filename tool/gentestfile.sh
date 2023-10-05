#! /bin/sh

if [ -z "$2" ]
then
    echo usage: $0 filename number_of_1k_blocks
    exit 1
fi

dd if=/dev/urandom bs=1024 count="$2" of="$1"
dd if=/dev/urandom bs=1 count="$RANDOM" >>"$1"
