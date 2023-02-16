TARGET = client

CC = gcc
LD = gcc
CFLAGS = -c -g 

INC = -I../i_crypto_library/include
LIB = -L../i_crypto_library/lib -lICrypto -lssl -lcrypto
DEFS = -D_LINUX
LD_CFLAGS = -Wl,-rpath,'$$ORIGIN/../i_crypto_library/lib'

SRCS = client.c
OBJS = client.o
.c.o : 
	$(CC) $(CFLAGS) $(INC) $(DEFS) $<

all : $(TARGET)
$(TARGET):	$(OBJS)
	$(CC) $(LD_CFLAGS) -o $@ $(OBJS) $(LIB) -lpthread

#test:
#	@./$(TARGET) 

clean:
	rm -f *.o $(TARGET)
