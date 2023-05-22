SHELL := /bin/bash

all: lib/libfastcircuit8.so lib/libfastcircuit16.so lib/libfastcircuit32.so lib/libfastcircuit64.so

# bin/runcircuit: bin/runcircuit.c lib/fastcircuit.c lib/fastcircuit.h
# 	gcc -Wall -O3 -Iwhitebox/ lib/fastcircuit.c bin/runcircuit.c -o bin/runcircuit

lib/libfastcircuit8.so: src/wboxkit/fastcircuit.c src/wboxkit/fastcircuit.h
	gcc -Wall -O3 -DCIRCUIT_RAM_BITS=8 -Isrc/wboxkit/ src/wboxkit/fastcircuit.c -fPIC -shared -o lib/libfastcircuit8.so

lib/libfastcircuit16.so: src/wboxkit/fastcircuit.c src/wboxkit/fastcircuit.h
	gcc -Wall -O3 -DCIRCUIT_RAM_BITS=16 -Isrc/wboxkit/ src/wboxkit/fastcircuit.c -fPIC -shared -o lib/libfastcircuit16.so

lib/libfastcircuit32.so: src/wboxkit/fastcircuit.c src/wboxkit/fastcircuit.h
	gcc -Wall -O3 -DCIRCUIT_RAM_BITS=32 -Isrc/wboxkit/ src/wboxkit/fastcircuit.c -fPIC -shared -o lib/libfastcircuit32.so

lib/libfastcircuit64.so: src/wboxkit/fastcircuit.c src/wboxkit/fastcircuit.h
	gcc -Wall -O3 -DCIRCUIT_RAM_BITS=64 -Isrc/wboxkit/ src/wboxkit/fastcircuit.c -fPIC -shared -o lib/libfastcircuit64.so

clean:
	rm -f lib/libfastcircuit*.so

submit:
	gcc -O3 build/submit.c build/main.c -o build/submit
	diff <(./build/submit <build/plain | xxd) <(xxd build/cipher)
