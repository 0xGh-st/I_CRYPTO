TARGET = otpVerify

CC = gcc
LD = gcc
CFLAGS = -c -g 

INC = -I../otp_library/include
LIB = -L../otp_library/lib -lOTP
DEFS = -D_LINUX
LD_CFLAGS = -Wl,-rpath,'$$ORIGIN/../otp_library/lib'

SRCS = otpVerify.c
OBJS = otpVerify.o
.c.o : 
	$(CC) $(CFLAGS) $(INC) $(DEFS) $<

all : $(TARGET)
$(TARGET):	$(OBJS)
	$(CC) $(LD_CFLAGS) -o $@ $(OBJS) $(LIB)

test:
	@./$(TARGET) 

clean:
	rm -f *.o $(TARGET)
