include ver.mak
include byteorder.mak

CFLAGS=-Wall -O2 -pipe -march=znver3 -msse4.1 -msse4.2 -mavx2 -maes -mvaes -Icamellia-BSD -Icompat -Iwhirlpool -I. -pthread -DBSD=0 -DSOTPET_VERSION="\"$(VERSION)\"" -DBYTEORDER="'$(BYTEORDER)'"
#CFLAGS=-Wall -O0 -g -pipe -march=x86-64 -Icamellia-BSD -Icompat -Iwhirlpool -I. -fstack-protector-all -mshstk -pthread -DDEBUG=0 -DBSD=0 -DSOTPET_VERSION="\"$(VERSION)\"" -DBYTEORDER="'$(BYTEORDER)'"
#CFLAGS_NDEB=-Wall -O2 -pipe -march=x86-64 -Icamellia-BSD -Icompat -Iwhirlpool -I. -fstack-protector-all -pthread -DNDEBUG=1 -DDEBUG=0 -DBSD=0 -DSOTPET_VERSION="\"$(VERSION)\"" -DBYTEORDER="'$(BYTEORDER)'"
CXXFLAGS=$(CFLAGS)
CXXFLAGS_NDEB=$(CFLAGS)
LDFLAGS=-g -pthread
LDLIBS=-lpthread

OBJS = whirlpool.o camellia.o buftools.o octword.o sotpet_trailer.o sotpet_main.o sotpet.o sotpet_level2.o fifo.o linuxfun.o shm.o

MAIN = sorbet

#.c.o:

all: $(MAIN) sotpet_master.zip

$(MAIN): $(OBJS)
	$(CXX) $(LDFLAGS) $(LDLIBS) -o $(MAIN) $(OBJS)

# whirlpool gets broken when compiled with -Og and with NDEBUG set, -O2 is ok.

whirlpool.o: whirlpool/whirlpool.c whirlpool/whirlpool.h
	$(CXX) $(CXXFLAGS) -c -o $@ $<

camellia.o: camellia-BSD/camellia.c camellia-BSD/camellia.h
	$(CXX) $(CXXFLAGS) -c -o $@ $<

octword.o: octword.cpp octword.hpp
	$(CXX) $(CXXFLAGS) -c -o $@ $<

fifo.o: fifo.cpp fifo.hpp
	$(CXX) $(CXXFLAGS) -c -o $@ $<

buftools.o: compat/buftools.c compat/buftools.h
	$(CXX) $(CXXFLAGS) -c -o $@ $<

sotpet_trailer.o: sotpet_trailer.c sotpet_trailer.h
	$(CXX) $(CXXFLAGS) -c -o $@ $<

sotpet_main.o: sotpet_main.c
	$(CXX) $(CXXFLAGS) -c -o $@ $<

sotpet_level2.o: sotpet_level2.cpp sotpet_level2.hpp compat/endianess.h
	$(CXX) $(CXXFLAGS) -c -o $@ $<

linuxfun.o: compat/linuxfun.c compat/linuxfun.h
	$(CXX) $(CXXFLAGS) -c -o $@ $<

shm.o: compat/shm.cpp compat/shm.hpp
	$(CXX) $(CXXFLAGS) -c -o $@ $<

sotpet_master.zip:
	zip -9 $@ *.[ch] *.sh *.[ch]pp */*.[ch] */*.[ch]pp Makefile.* testsuites/*/*.sh testsuites/*/*.txt *.md *.txt ver.mak */*.sh */*.py

.c.o:
	$(CXX) $(CXXFLAGS) -c -o $@ $<

ci:
	git add *.[ch] */*.sh *.[ch]pp */*.[ch] */*.[ch]pp Makefile* testsuites/*/*.sh testsuites/*/*.txt *.md *.txt *.mak


clean:
	rm -f *.o $(MAIN) tmp_* core sotpet_master.zip


