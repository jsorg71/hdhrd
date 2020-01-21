
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "arch.h"
#include "parse.h"

/*****************************************************************************/
int
main(int argc, char** argv)
{
    struct sockaddr_un s;
    int sck;
    struct stream* out_s;

    sck = socket(PF_LOCAL, SOCK_STREAM, 0);
    if (sck == -1)
    {
        return 1;
    }

    out_s = (struct stream*)calloc(1, sizeof(struct stream));
    out_s->data = (char*)malloc(1024);
    out_s->p = out_s->data;
    out_uint32_le(out_s, 1);
    out_uint32_le(out_s, 9);
    memset(&s, 0, sizeof(struct sockaddr_un));
    s.sun_family = AF_UNIX;
    strncpy(s.sun_path, "/tmp/wtv_hdhrd3138", sizeof(s.sun_path));
    s.sun_path[sizeof(s.sun_path) - 1] = 0;
    connect(sck, (struct sockaddr*)&s, sizeof(struct sockaddr_un));
    send(sck, out_s->data, 9, 0);
    usleep(10 * 1024 * 1024);
    close(sck);
    return 0;
}
