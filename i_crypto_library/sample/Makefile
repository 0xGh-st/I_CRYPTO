TARGET = i_crypto_sample

CC = gcc
LD = gcc
CFLAGS = -c -g 

INC = -I../include
LIB = -L../lib -lICrypto -lssl -lcrypto
DEFS = -D_LINUX
LD_CFLAGS = -Wl,-rpath,'$$ORIGIN/../lib'

SRCS = i_crypto_sample.c
OBJS = i_crypto_sample.o
.c.o : 
	$(CC) $(CFLAGS) $(INC) $(DEFS) $<

all : $(TARGET)
$(TARGET):	$(OBJS)
	$(CC) $(LD_CFLAGS) -o $@ $(OBJS) $(LIB)

test:
	@./$(TARGET) 

clean:
	rm -f *.o $(TARGET)
