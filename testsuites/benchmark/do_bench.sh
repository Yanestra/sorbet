#! /bin/sh

rm -f testfile.gpg testfile.cpt

set -x

rm -f testfile*
../../tool/gentestfile.sh testfile 20M
time gpg -c --cipher-algo=camellia256 --compression-algo=Uncompressed \
  --passphrase="xxx" --batch testfile
time ccrypt -e -b -K "xxx" testfile
time ../../sorbet -e do_bench.sh testfile.cpt testfile.xxx
