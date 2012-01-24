CFLAGS = 
LDFLAGS = -lpjf -lpcre -lpthread

ME=tracedump
C_OBJECTS=pid.o ptrace.o inject.o tracedump.o pcap.o
TARGETS=tracedump

include rules.mk

tracedump: $(C_OBJECTS)
	$(CC) $(C_OBJECTS) $(LDFLAGS) -o tracedump

clean: clean-std
install: install-std
