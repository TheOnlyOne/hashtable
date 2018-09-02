
CC=gcc-4.9
CFLGAGS= = -lpthread -03
DEFS = -DHASHTEST -DHASHTHREADED
DEPS = hashtable.h
OBJ = test.o hashtable.o

%.o: %.c %(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS) $(DEFS)

test: %(OBJ)
	$(CC) -o $@ $^ (CFLAGS)

.PHONY:
	clean

clean:
	rm *.o test *.s
