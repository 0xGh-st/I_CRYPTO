all : ../lib/libICrypto.so

../lib/libICrypto.so : i_crypto.o
	gcc -shared -o ../lib/libICrypto.so i_crypto.o -lssl -lcrypto
i_crypto.o : i_crypto.c
	gcc -fPIC -c -o i_crypto.o i_crypto.c -I../include

clean :
	rm -f *.o
