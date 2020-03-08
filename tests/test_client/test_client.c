
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "arch.h"
#include "parse.h"

/*****************************************************************************/
const char *
get_filename(char* filename, int bytes)
{
    DIR * ldir;
    struct dirent * entry;
    int count;

    count = 0;
    ldir = opendir("/tmp");
    if (ldir != NULL)
    {
        entry = readdir(ldir);
        while (entry != NULL)
        {
            if (strncmp(entry->d_name, "wtv_", 3) == 0)
            {
                if (entry->d_type == DT_SOCK)
                {
                    snprintf(filename, bytes, "/tmp/%s", entry->d_name);
                    count++;
                }
            }
            entry = readdir(ldir);
        }
        closedir(ldir);
    }
    if (count == 1)
    {
        return filename;
    }
    return NULL;
}

/*****************************************************************************/
int
main(int argc, char** argv)
{
    struct sockaddr_un s;
    int sck;
    int ran;
    struct stream* out_s;
    unsigned int stime;
    char filename[256];
    const char* lfilename;

    sck = socket(PF_LOCAL, SOCK_STREAM, 0);
    ran = open("/dev/urandom", O_RDONLY);
    read(ran, &stime, 4);
    out_s = (struct stream*)calloc(1, sizeof(struct stream));
    out_s->data = (char*)malloc(1024);
    out_s->p = out_s->data;
    out_uint32_le(out_s, 1); /* msg_subscribe_audio */
    out_uint32_le(out_s, 9);
    out_uint8(out_s, 1);
    memset(&s, 0, sizeof(struct sockaddr_un));
    s.sun_family = AF_UNIX;
    lfilename = get_filename(filename, 256);
    printf("connecting filename %s\n", lfilename);
    strncpy(s.sun_path, lfilename, sizeof(s.sun_path));
    s.sun_path[sizeof(s.sun_path) - 1] = 0;
    connect(sck, (struct sockaddr*)&s, sizeof(struct sockaddr_un));
    send(sck, out_s->data, 9, 0);
    printf("stime %d\n", stime % 10);
    usleep((stime % 10) * 1024 * 1024);
    close(sck);
    return 0;
}
