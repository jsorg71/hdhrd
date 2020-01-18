
OBJS=hdhrd.o mpeg_ts.o hdhrd_ac3.o

CFLAGS=-O2 -g -Wall -Wextra -I/usr/include/libhdhomerun
# older distro use this
#CFLAGS=-O2 -g -Wall -Wextra -I/usr/lib/libhdhomerun

LDFLAGS=

LIBS=-lhdhomerun -la52

hdhrd: $(OBJS)
	$(CC) -o hdhrd $(OBJS) $(LDFLAGS) $(LIBS)

clean:
	rm -f $(OBJS) hdhrd
