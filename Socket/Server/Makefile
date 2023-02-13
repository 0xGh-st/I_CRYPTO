TARGET = server

CC = gcc
LD = gcc
CFLAGS = -c -g 

INC = -I../lib
LIB = -L../lib -lEdgeCrypto -lISymmetric
DEFS = -D_LINUX
LD_CFLAGS = -Wl,-rpath,'$$ORIGIN/../lib'

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
