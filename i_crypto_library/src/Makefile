all : ../lib/libOTP.so

../lib/libOTP.so : otp.o
	gcc -shared -o ../lib/libOTP.so otp.o -lm
otp.o : otp.c
	gcc -fPIC -c -o otp.o otp.c -I../include/

clean :
	rm -f *.o
