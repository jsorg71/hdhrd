
OBJS=hdhrd.o

CFLAGS=-O2 -Wall -I/usr/include/libhdhomerun

LDFLAGS=

LIBS=-lhdhomerun

hdhrd: $(OBJS)
	$(CC) -o hdhrd $(OBJS) $(LDFLAGS) $(LIBS)

clean:
	rm -f $(OBJS) hdhrd
