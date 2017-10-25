#cd ..
#emcc -s ASSERTIONS=1 -s ASYNCIFY=1 -s TOTAL_MEMORY=134217728 --preload-file coins.json -DFROM_JS -O2 -I../includes -I../crypto777 -s PTHREAD_POOL_SIZE=8 -s USE_PTHREADS=1 -o /var/www/html/index.html exchanges/mm.c ../crypto777/*.c ../crypto777/jpeg/*.c ../crypto777/jpeg/unix/*.c mini-gmp.c secp256k1/src/secp256k1.c -lm ../OSlibs/js/libnanomsg.a -lc -lpthread

include ../crypto777/crypto777.sources

all:
	echo building... $(CRYPTO777_SRCS)
	emcc -s ASSERTIONS=1 -s ASYNCIFY=1 -s TOTAL_MEMORY=134217728 --preload-file coins.json -D__PNACL -DFROM_JS -O2 -I../includes -I../crypto777 -s PTHREAD_POOL_SIZE=8 -s USE_PTHREADS=1 -o /var/www/html/index.html exchanges/mm.c $(CRYPTO777_SRCS) mini-gmp.c secp256k1/src/secp256k1.c -lm 

