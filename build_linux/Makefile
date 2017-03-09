esall: libespio.so espio_test

libespio.so:
	g++ -Wall -Wl,--no-as-needed -pthread -std=c++11 -fPIC -shared -g -O2 -Werror -Wno-unused-function ../src/espio.cpp -o libespio.so

espio_test:
	gcc -I../src -g -O2 -Wall -Werror -Wno-unused-function ../examples/espio_test.c -ldl -o espio_test

espio_with_soque_test:
	gcc -I../src -g -O2 -Wall -Werror -Wno-unused-function -DWITH_SOQUE -I../../soque/src ../examples/espio_test.c -ldl -o espio_with_soque_test
	install -D espio_with_soque_test /usr/bin/espio_with_soque_test

install: libespio.so espio_test
	install -D libespio.so /usr/lib/libespio.so
	install -D espio_test /usr/bin/espio_test
	if test -e espio_with_soque_test; then install -D espio_with_soque_test /usr/bin/espio_with_soque_test; fi

cleanup:
	if test -e libespio.so; then unlink libespio.so; fi
	if test -e espio_test; then unlink espio_test; fi
	if test -e espio_with_soque_test; then unlink espio_with_soque_test; fi
	if test -e /usr/lib/libespio.so; then unlink /usr/lib/libespio.so; fi
	if test -e /usr/bin/espio_test; then unlink /usr/bin/espio_test; fi
	if test -e /usr/bin/espio_with_soque_test; then unlink /usr/bin/espio_with_soque_test; fi
