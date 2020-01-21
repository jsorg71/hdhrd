
OBJS=test_client.o

CFLAGS=-Wall -O2 -I../..

LDFLAGS=

LIBS=

test_client: $(OBJS)
	$(CC) -o test_client $(OBJS) $(LDFLAGS) $(LIBS)

clean:
	rm -f test_client $(OBJS)
