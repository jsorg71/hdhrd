
OBJS=hdhrd.o mpeg_ts.o hdhrd_ac3.o hdhrd_peer.o

CFLAGS=-O2 -g -Wall -Wextra -I/usr/include/libhdhomerun -I/opt/yami/include
# older distro use this
#CFLAGS=-O2 -g -Wall -Wextra -I/usr/lib/libhdhomerun

LDFLAGS=-L/opt/yami/lib -Wl,-rpath=/opt/yami/lib

LIBS=-lhdhomerun -la52 -lyami_inf

hdhrd: $(OBJS)
	$(CC) -o hdhrd $(OBJS) $(LDFLAGS) $(LIBS)

clean:
	rm -f $(OBJS) hdhrd
