
OBJS=hdhrd.o mpeg_ts.o

CFLAGS=-O2 -g -Wall -Wextra -I/usr/include/libhdhomerun

LDFLAGS=

LIBS=-lhdhomerun

hdhrd: $(OBJS)
	$(CC) -o hdhrd $(OBJS) $(LDFLAGS) $(LIBS)

clean:
	rm -f $(OBJS) hdhrd
