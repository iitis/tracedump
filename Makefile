CFLAGS = 
LDFLAGS = -lpjf -lpcre

ME=tracedump
C_OBJECTS=ptrace.o inject.o tracedump.o
TARGETS=tracedump

include rules.mk

tracedump: $(C_OBJECTS)
	$(CC) $(C_OBJECTS) $(LDFLAGS) -o tracedump

clean: clean-std
install: install-std
