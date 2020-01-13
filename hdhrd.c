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

#include <hdhomerun.h>

#include "arch.h"
#include "parse.h"
#include "mpeg_ts.h"

static volatile int g_term = 0;

struct pid0_info
{
};

struct hdhrd_info
{
    struct tmpegts_cb cb;
    struct pid0_info pid0;
};

/*****************************************************************************/
static int
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
    struct stream* s;

    //printf("tmpegts_audio_cb: bytes %10.10d flags0 0x%8.8x\n", (int)(pi->s->end - pi->s->data), pi->flags0);
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
    return 0;
}

/*****************************************************************************/
static int
tmpegts_program_cb(struct pid_info* pi, void* udata)
{
    struct hdhrd_info* hdhrd;

    hdhrd = (struct hdhrd_info*)udata;
    //printf("tmpegts_program_cb: bytes %d\n", (int)(pi->s->end - pi->s->data));
    //hex_dump(pi->s->data, pi->s->end - pi->s->data);

    if (hdhrd->cb.num_pids == 2)
    {
        hdhrd->cb.pids[2] = 0x31;
        hdhrd->cb.procs[2] = tmpegts_video_cb;
        hdhrd->cb.pids[3] = 0x34;
        hdhrd->cb.procs[3] = tmpegts_audio_cb;
        hdhrd->cb.num_pids = 4;
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
    int table_id_extension;
    int program_num;
    int program_map_pid;
    struct stream* s;

    hdhrd = (struct hdhrd_info*)udata;
    if (hdhrd->cb.num_pids != 1)
    {
        return 0;
    }
    s = pi->s;
    if (!s_check_rem(s, 1))
    {
        return 1;
    }
    in_uint8(s, pointer_field);
    //printf("tmpegts_pid0_cb: pointer_field %d\n", pointer_field);
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
    in_uint16_be(s, packed_bits);
    section_length = packed_bits & 0x03FF;
    //printf("tmpegts_pid0_cb: section_length %d\n", section_length);
    //hex_dump(s->p, section_length);
    if (!s_check_rem(s, section_length))
    {
        return 4;
    }
    s->end = s->p + section_length;
    if (packed_bits & 0x8000) /* section_syntax_indicator */
    {
        if (!s_check_rem(s, 5))
        {
            return 5;
        }
        in_uint16_be(s, table_id_extension);
        //printf("tmpegts_pid0_cb: table_id_extension 0x%4.4x\n",
        //       table_id_extension);
        in_uint8s(s, 3);
        while (s_check_rem(s, 8)) /* last 4 bytes is crc */
        {
            in_uint16_be(s, program_num);
            in_uint16_be(s, program_map_pid);
            program_map_pid &= 0x1FFF;
            if (program_map_pid == 0x30)
            {
                hdhrd->cb.pids[1] = program_map_pid;
                hdhrd->cb.procs[1] = tmpegts_program_cb;
                hdhrd->cb.num_pids = 2;
            }
            //printf("tmpegts_pid0_cb: program_num 0x%4.4x "
            //       "program_map_pid 0x%4.4x\n",
            //       program_num, program_map_pid);
        }
    }
    return 0;
}

/*****************************************************************************/
static void
sig_int(int sig)
{
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

    signal(SIGINT, sig_int);

    hdhrd = (struct hdhrd_info*)calloc(1, sizeof(struct hdhrd_info));
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
        hdhrd->cb.pids[0] = 0;
        hdhrd->cb.procs[0] = tmpegts_pid0_cb;
        hdhrd->cb.num_pids = 1;
        while (1)
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
                error = process_mpeg_ts_packet(data, lbytes, &(hdhrd->cb), hdhrd);
                data += lbytes;
                bytes -= lbytes;
            }
            if (error != 0)
            {
                printf("main: exit main loop with error %d\n", error);
            }
            usleep(10 * 1024);
        }
    }
    hdhomerun_device_destroy(hdhr);
    mpeg_ts_cleanup(&(hdhrd->cb));
    free(hdhrd);
    return 0;
}
