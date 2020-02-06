
OBJS=hdhrd.o mpeg_ts.o hdhrd_ac3.o hdhrd_peer.o hdhrd_mpeg2.o hdhrd_log.o hdhrd_utils.o

CFLAGS=-O2 -g -Wall -Wextra -I/usr/include/libhdhomerun -I/opt/yami/include
#CFLAGS=-O2 -g -Wall -Wextra -I/usr/include/libhdhomerun -I/opt/intel/include
# older distro use this
#CFLAGS=-O2 -g -Wall -Wextra -I/usr/lib/libhdhomerun

LDFLAGS=-L/opt/yami/lib -Wl,-rpath=/opt/yami/lib
#LDFLAGS=-L/opt/intel/lib -Wl,-rpath=/opt/intel/lib

LIBS=-lhdhomerun -la52 -lyami_inf

hdhrd: $(OBJS)
	$(CC) -o hdhrd $(OBJS) $(LDFLAGS) $(LIBS)

clean:
	rm -f $(OBJS) hdhrd
