/**
 * hdhome_run daemon
 *
 * Copyright 2020 Jay Sorg <jay.sorg@gmail.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/un.h>

#include <hdhomerun.h>

#include "arch.h"
#include "parse.h"
#include "mpeg_ts.h"
#include "hdhrd_ac3.h"

static volatile int g_term = 0;

struct pid0_info
{
    int pad0;
    int pad1;
};

struct hdhrd_info
{
    struct tmpegts_cb cb;
    struct pid0_info pid0;
    int listener;
    int pad0;
    void* ac3;
};

#define HDHRD_UDS "/tmp/hdhrd"

/*****************************************************************************/
int
hex_dump(const void* data, int bytes)
{
    const unsigned char *line;
    int i;
    int thisline;
    int offset;

    line = (const unsigned char *)data;
    offset = 0;
    while (offset < bytes)
    {
        printf("%04x ", offset);
        thisline = bytes - offset;
        if (thisline > 16)
        {
            thisline = 16;
        }
        for (i = 0; i < thisline; i++)
        {
            printf("%02x ", line[i]);
        }
        for (; i < 16; i++)
        {
            printf("   ");
        }
        for (i = 0; i < thisline; i++)
        {
            printf("%c", (line[i] >= 0x20 && line[i] < 0x7f) ? line[i] : '.');
        }
        printf("\n");
        offset += thisline;
        line += thisline;
    }
    return 0;
}

/*****************************************************************************/
static int
read_time(const void* ptr, int* time)
{
    const unsigned char* pui8;
    unsigned int t1;

    pui8 = (const unsigned char*) ptr;
    /* 11100000 00000000 00000000 00000000 3 bits */
    /* 00011111 11100000 00000000 00000000 8 bits */
    /* 00000000 00011111 11000000 00000000 7 bits */
    /* 00000000 00000000 00111111 11000000 8 bits */
    /* 00000000 00000000 00000000 00111111 6 bits */
    t1 = ((pui8[0] & 0x0E) << 28) | ((pui8[1] & 0xFF) << 21) |
         ((pui8[2] & 0xFE) << 13) | ((pui8[3] & 0xFF) <<  6) |
         ((pui8[4] & 0xFE) >>  2);
    t1 = t1 / 45;
    *time = t1;
    return 0;
}

/*****************************************************************************/
/* https://en.wikipedia.org/wiki/Packetized_elementary_stream */
static int
read_pes(struct stream* s, int* pts, int* dts)
{
    unsigned char code;
    unsigned char remaining;
    char* holdp;

    if (!s_check_rem(s, 9))
    {
        return 1;
    }
    in_uint8s(s, 7);
    in_uint8(s, code);
    in_uint8(s, remaining);
    holdp = s->p;
    if (!s_check_rem(s, remaining))
    {
        return 2;
    }
    if ((code & 0xC0) == 0xC0)
    {
        if (!s_check_rem(s, 10))
        {
            return 3;
        }
        read_time(s->p, pts);
        in_uint8s(s, 5);
        read_time(s->p, dts);
        in_uint8s(s, 5);
    }
    else if ((code & 0x80) == 0x80)
    {
        if (!s_check_rem(s, 5))
        {
            return 4;
        }
        read_time(s->p, pts);
        in_uint8s(s, 5);
        *dts = *pts;
    }
    else
    {
        return 5;
    }
    s->p = holdp + remaining;
    return 0;
}

/*****************************************************************************/
static int
tmpegts_video_cb(struct pid_info* pi, void* udata)
{
    int error;
    int pts;
    int dts;
    struct stream* s;

    (void)udata;

    //printf("tmpegts_video_cb: bytes %10.10d flags0 0x%8.8x\n", (int)(pi->s->end - pi->s->data), pi->flags0);
    //if (pi->flags0 & 1)
    //{
    //    printf("tmpegts_video_cb: pcr %10.10u\n", pi->pcr);
    //}
    s = pi->s;
    pts = 0;
    dts = 0;
    error = read_pes(s, &pts, &dts);
    if (error != 0)
    {
        return 0;
    }
    //printf("tmpegts_video_cb: error %d pts %10.10u dts %10.10u\n", error, pts, dts);
    //hex_dump(pi->s->p, 32);
    return 0;
}

/*****************************************************************************/
static int
tmpegts_audio_cb(struct pid_info* pi, void* udata)
{
    int error;
    int pts;
    int dts;
    int cdata_bytes;
    int cdata_bytes_processed;
    int decoded;
    int channels;
    int bytes;
    struct stream* s;
    struct hdhrd_info* hdhrd;

    hdhrd = (struct hdhrd_info*)udata;

    printf("tmpegts_audio_cb: bytes %10.10d flags0 0x%8.8x\n", (int)(pi->s->end - pi->s->data), pi->flags0);
    //if (pi->flags0 & 1)
    //{
    //    printf("tmpegts_audio_cb: pcr 0x%10.10u\n", pi->pcr);
    //}
    s = pi->s;
    pts = 0;
    dts = 0;
    error = read_pes(s, &pts, &dts);
    if (error != 0)
    {
        return 0;
    }
    //printf("tmpegts_audio_cb: error %d pts %10.10u dts %10.10u\n", error, pts, dts);
    //hex_dump(pi->s->p, 32);

    while (s->p < s->end)
    {
        cdata_bytes = (int)(s->end - s->p);
        error = hdhrd_ac3_decode(hdhrd->ac3, s->p, cdata_bytes,
                                 &cdata_bytes_processed, &decoded);
        printf("  tmpegts_audio_cb: error %d cdata_bytes %d "
               "cdata_bytes_processed %d decoded %d\n",
               error, cdata_bytes, cdata_bytes_processed, decoded);
        if (error != 0)
        {
            printf("tmpegts_audio_cb: hdhrd_ac3_decode failed\n");
            break;
        }
        s->p += cdata_bytes_processed;
        if (decoded)
        {
            hdhrd_ac3_get_frame_info(hdhrd->ac3, &channels, &bytes);
            printf("    tmpegts_audio_cb: channels %d bytes %d\n", channels, bytes);
        }
    }
    return 0;
}

/*****************************************************************************/
static int
tmpegts_program_cb(struct pid_info* pi, void* udata)
{
    int pointer_field;
    int table_id;
    int packed_bits;
    int section_length;
    int program_info_length;
    int stream_type;
    int elementary_pid;
    int es_info_length;
    int video_pid;
    int audio_pid;
    struct hdhrd_info* hdhrd;
    struct stream* s;

    //printf("tmpegts_program_cb: bytes %d\n", (int)(pi->s->end - pi->s->data));
    //hex_dump(pi->s->data, pi->s->end - pi->s->data);
    hdhrd = (struct hdhrd_info*)udata;
    s = pi->s;
    if (!s_check_rem(s, 1))
    {
        return 1;
    }
    in_uint8(s, pointer_field);
    if (pointer_field < 0)
    {
        return 2;
    }
    if (!s_check_rem(s, pointer_field + 3))
    {
        return 3;
    }
    in_uint8s(s, pointer_field);
    in_uint8(s, table_id);
    //printf("tmpegts_program_cb: table_id %d\n", table_id);
    if (table_id != 2)
    {
        return 4;
    }
    in_uint16_be(s, packed_bits);
    section_length = packed_bits & 0x03FF;
    if (!s_check_rem(s, section_length))
    {
        return 5;
    }
    //printf("tmpegts_program_cb: section_length %d\n", section_length);
    if (hdhrd->cb.num_pids != 2)
    {
        return 0;
    }

    s->end = s->p + section_length;
    if (packed_bits & 0x8000) /* section_syntax_indicator */
    {
        if (!s_check_rem(s, 9))
        {
            return 6;
        }
        in_uint8s(s, 7);
        in_uint16_be(s, packed_bits);
        program_info_length = packed_bits & 0x03FF;
        if (!s_check_rem(s, program_info_length))
        {
            return 7;
        }
        in_uint8s(s, program_info_length);
        video_pid = 0;
        audio_pid = 0;
        while (s_check_rem(s, 9)) /* last 4 bytes is crc */
        {
            in_uint8(s, stream_type);
            in_uint16_be(s, packed_bits);
            elementary_pid = packed_bits & 0x1FFF;
            in_uint16_be(s, packed_bits);
            es_info_length = packed_bits & 0x03FF;
            printf("tmpegts_program_cb: found stream_type 0x%4.4x "
                   "elementary_pid 0x%4.4x es_info_length %d\n",
                   stream_type, elementary_pid, es_info_length);
            //hex_dump(pi->s->p, es_info_length); 
            in_uint8s(s, es_info_length);
            if ((stream_type == 0x02) && (video_pid == 0)) /* mpeg2 */
            {
                video_pid = elementary_pid;
            }
            if ((stream_type == 0x81) && (audio_pid == 0)) /* ac3 */
            {
                audio_pid = elementary_pid;
            }
        }
        if ((video_pid != 0) && (audio_pid != 0))
        {
            printf("tmpegts_program_cb: adding video pid 0x%4.4x\n", video_pid);
            hdhrd->cb.pids[2] = video_pid;
            hdhrd->cb.procs[2] = tmpegts_video_cb;
            printf("tmpegts_program_cb: adding audio pid 0x%4.4x\n", audio_pid);
            hdhrd->cb.pids[3] = audio_pid;
            hdhrd->cb.procs[3] = tmpegts_audio_cb;
            hdhrd->cb.num_pids = 4;
        }
    }
    return 0;
}

/*****************************************************************************/
/* https://en.wikipedia.org/wiki/Program-specific_information */
static int
tmpegts_pid0_cb(struct pid_info* pi, void* udata)
{
    int pointer_field;
    int table_id;
    int packed_bits;
    int section_length;
    struct hdhrd_info* hdhrd;
    int program_num;
    int program_map_pid;
    int pmt_pid;
    struct stream* s;

    //printf("tmpegts_pid0_cb: bytes %d\n", (int)(pi->s->end - pi->s->data));
    //hex_dump(pi->s->data, pi->s->end - pi->s->data);
    hdhrd = (struct hdhrd_info*)udata;
    s = pi->s;
    if (!s_check_rem(s, 1))
    {
        return 1;
    }
    in_uint8(s, pointer_field);
    if (pointer_field < 0)
    {
        return 2;
    }
    if (!s_check_rem(s, pointer_field + 3))
    {
        return 3;
    }
    in_uint8s(s, pointer_field);
    in_uint8(s, table_id);
    //printf("tmpegts_pid0_cb: table_id %d\n", table_id);
    if (table_id != 0)
    {
        return 4;
    }
    in_uint16_be(s, packed_bits);
    section_length = packed_bits & 0x03FF;
    if (!s_check_rem(s, section_length))
    {
        return 5;
    }
    //printf("tmpegts_pid0_cb: section_length %d\n", section_length);
    //hex_dump(s->p, section_length);
    if (hdhrd->cb.num_pids != 1)
    {
        return 0;
    }
    s->end = s->p + section_length;
    if (packed_bits & 0x8000) /* section_syntax_indicator */
    {
        if (!s_check_rem(s, 5))
        {
            return 6;
        }
        in_uint8s(s, 5);
        pmt_pid = 0;
        while (s_check_rem(s, 8)) /* last 4 bytes is crc */
        {
            in_uint16_be(s, program_num);
            in_uint16_be(s, program_map_pid);
            program_map_pid &= 0x1FFF;
            if ((program_map_pid != 0) && (pmt_pid == 0))
            {
                pmt_pid = program_map_pid;
            }
            printf("tmpegts_pid0_cb: found program_num 0x%4.4x "
                   "program_map_pid 0x%4.4x\n",
                   program_num, program_map_pid);
        }
        if (pmt_pid != 0)
        {
            printf("tmpegts_pid0_cb: adding program pid 0x%4.4x\n", pmt_pid);
            hdhrd->cb.pids[1] = pmt_pid;
            hdhrd->cb.procs[1] = tmpegts_program_cb;
            hdhrd->cb.num_pids = 2;
        }
    }
    return 0;
}

/*****************************************************************************/
static void
sig_int(int sig)
{
    (void)sig;
    g_term = 1;
}

/*****************************************************************************/
int
main(int argc, char** argv)
{
    struct hdhomerun_device_t* hdhr;
    struct hdhrd_info* hdhrd;
    const char* dev_name;
    uint8_t* data;
    size_t bytes;
    int error;
    int lbytes;
    int millis;
    struct sockaddr_un s;
    fd_set rfds;
    struct timeval time;

    (void)argc;
    (void)argv;

    hdhrd = (struct hdhrd_info*)calloc(1, sizeof(struct hdhrd_info));
    if (hdhrd == NULL)
    {
        printf("main: calloc failed\n");
        return 1;
    }
    signal(SIGINT, sig_int);
    unlink(HDHRD_UDS);
    hdhrd->listener = socket(PF_LOCAL, SOCK_STREAM, 0);
    if (hdhrd->listener == -1)
    {
        printf("main: socket failed\n");
        return 1;
    }
    memset(&s, 0, sizeof(struct sockaddr_un));
    s.sun_family = AF_UNIX;
    strncpy(s.sun_path, HDHRD_UDS, sizeof(s.sun_path));
    s.sun_path[sizeof(s.sun_path) - 1] = 0;
    bytes = sizeof(struct sockaddr_un);
    error = bind(hdhrd->listener, (struct sockaddr*)&s, bytes);
    if (error != 0)
    {
        printf("main: bind error\n");
        return 1;
    }
    error = listen(hdhrd->listener, 2);
    if (error != 0)
    {
        printf("main: listen error\n");
        return 1;
    }
    hdhr = hdhomerun_device_create_from_str("1020B660-0", 0);
    if (hdhr == NULL)
    {
        printf("main: hdhomerun_device_create_from_str failed\n");
        return 1;
    }
    dev_name = hdhomerun_device_get_name(hdhr);
    printf("main: hdhomerun_device_get_name returns %s\n", dev_name);
    error = hdhomerun_device_stream_start(hdhr);
    printf("main: hdhomerun_device_stream_start returns %d\n", error);
    if (error == 1)
    {
        printf("main: adding main pid 0x%4.4x\n", 0);
        hdhrd->cb.pids[0] = 0;
        hdhrd->cb.procs[0] = tmpegts_pid0_cb;
        hdhrd->cb.num_pids = 1;
        if (hdhrd_ac3_create(&(hdhrd->ac3)) != 0)
        {
            printf("main: hdhrd_ac3_create failed\n");
        }
        for (;;)
        {
            if (g_term)
            {
                printf("main: g_term set\n");
                break;
            }
            bytes = 32 * 1024;
            data = hdhomerun_device_stream_recv(hdhr, bytes, &bytes);
            //printf("main: data %p bytes %ld\n", data, bytes);
            error = 0;
            while ((error == 0) && (bytes > 3))
            {
                lbytes = bytes;
                if (lbytes > 188)
                {
                    lbytes = 188;
                }
                error = process_mpeg_ts_packet(data, lbytes, &(hdhrd->cb),
                                               hdhrd);
                data += lbytes;
                bytes -= lbytes;
            }
            if (error != 0)
            {
                printf("main: process_mpeg_ts_packet returned %d\n", error);
            }

            FD_ZERO(&rfds);
            FD_SET(hdhrd->listener, &rfds);
            millis = 15;
            time.tv_sec = millis / 1000;
            time.tv_usec = (millis * 1000) % 1000000;
            error = select(hdhrd->listener + 1, &rfds, 0, 0, &time);
            if (error > 0)
            {
                if (FD_ISSET(hdhrd->listener, &rfds))
                {
                    printf("got connection\n");
                }
            }

        }
    }
    hdhomerun_device_destroy(hdhr);
    mpeg_ts_cleanup(&(hdhrd->cb));
    close(hdhrd->listener);
    hdhrd_ac3_delete(hdhrd->ac3);
    free(hdhrd);
    unlink(HDHRD_UDS);
    return 0;
}
