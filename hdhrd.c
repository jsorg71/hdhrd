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
tmpegts_pid0_cb(struct stream* s, const struct tmpegts* mpegts, void* udata)
{
    int pointer_field;
    int table_id;
    int packed_bits;
    int section_length;
    //struct hdhrd_info* hdhrd;
    int table_id_extension;
    int program_num;
    int program_map_pid;

    printf("tmpegts_pid0_cb:\n");
    //hdhrd = (struct hdhrd_info*)udata;

    in_uint8(s, pointer_field);
    //printf("tmpegts_pid0_cb: pointer_field %d\n", pointer_field);
    in_uint8s(s, pointer_field);
    in_uint8(s, table_id);
    //printf("tmpegts_pid0_cb: table_id %d\n", table_id);

    in_uint16_be(s, packed_bits);
    section_length = packed_bits & 0x03FF;
    //printf("tmpegts_pid0_cb: section_length %d\n", section_length);
    //hex_dump(s->p, section_length);
    s->end = s->p + section_length;
    if (packed_bits & 0x8000) /* section_syntax_indicator */
    {
        in_uint16_be(s, table_id_extension);
        //printf("tmpegts_pid0_cb: table_id_extension 0x%4.4x\n",
        //       table_id_extension);
        in_uint8s(s, 3);
        while (s_check_rem(s, 8))
        {
            in_uint16_be(s, program_num);
            in_uint16_be(s, program_map_pid);
            program_map_pid &= 0x1FFF;
            printf("tmpegts_pid0_cb: program_num 0x%4.4x "
                   "program_map_pid 0x%4.4x\n",
                   program_num, program_map_pid);
        }
    }

    return 0;
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
    free(hdhrd);
    return 0;
}
