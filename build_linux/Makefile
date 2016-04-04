all: libespio.so espio

libespio.so:
	g++ -fPIC -shared -g -O2 -Wall -Werror -Wno-unused-function ../src/espio.cpp -o libespio.so

espio:
	gcc -I../src -g -O2 -Wall -Werror -Wno-unused-function ../examples/espio_test.c -ldl -o espio

install: libespio.so espio
	install -D libespio.so /usr/lib/libespio.so
	install -D espio /usr/bin/espio

cleanup:
	if test -e libespio.so; then unlink libespio.so; fi
	if test -e espio; then unlink espio; fi
	if test -e /usr/lib/libespio.so; then unlink /usr/lib/libespio.so; fi
	if test -e /usr/bin/espio; then unlink /usr/bin/espio; fi
