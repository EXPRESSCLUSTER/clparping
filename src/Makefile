.PHONY: all
all: clparping clean

clparping: clparping.o
	cc -o clparping clparping.o
clparping.o: clparping.c
	cc -c clparping.c
clparping.o: clparping.h

.PHONY: debug
debug: clparping_d clean

clparping_d: clparping_d.o
	cc -o clparping clparping.o
clparping_d.o: clparping.c
	cc -g3 -c clparping.c -DDEBUG
clparping_d.o: clparping.h

.PHONY: clean
clean:
	rm -f clparping.o

.PHONY: test
test:
	-sudo ./clparping
	echo
	-sudo ./clparping ip -x
	echo
	-sudo ./clparping ip -q
	echo
	-sudo ./clparping ip -q -w
	echo
	-sudo ./clparping ip -w time
	echo
	-sudo ./clparping ip -w 1
	echo
	-sudo ./clparping ip -q -w time
	echo
	-sudo ./clparping ip -w -q 1
	echo
	-sudo ./clparping ip -q -w 1
	echo
	-sudo ./clparping ip -q -w 1 aaa
	echo
	-sudo ./clparping 192.168.137.800
	echo
	-sudo ./clparping 192.168.137.80 -q
	echo
	-sudo ./clparping 192.168.137.80 -q -w 1
	echo
	-sudo ./clparping -q 192.168.137.80 -w 1
	echo
	-sudo ./clparping 1.1.1.1
	echo
	-sudo ./clparping 192.168.145.1