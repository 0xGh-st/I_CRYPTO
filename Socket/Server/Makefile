TARGET = server

CC = gcc
LD = gcc
CFLAGS = -c -g 

INC = -I../i_crypto_library/include
LIB = -L../i_crypto_library/lib -lICrypto
DEFS = -D_LINUX
LD_CFLAGS = -Wl,-rpath,'$$ORIGIN/../i_crypto_library/lib'

SRCS = server.c
OBJS = server.o
.c.o : 
	$(CC) $(CFLAGS) $(INC) $(DEFS) $<

all : $(TARGET)
$(TARGET):	$(OBJS)
	$(CC) $(LD_CFLAGS) -o $@ $(OBJS) $(LIB) -lpthread

#test:
#	@./$(TARGET) 

clean:
	rm -f *.o $(TARGET)
