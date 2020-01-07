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

#include "mpeg_ts.h"

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
tmpegts_zero_cb(const void* data, int data_bytes,
                const struct tmpegts* mpegts, void* udata)
{
    const unsigned char* data8;
    int pointer_field;
    int table_id;
    int packed_bits;
    int section_length;

    printf("tmpegts_zero_cb:\n");
    hex_dump(data, data_bytes);

    data8 = (const unsigned char*)data;
    pointer_field = *(data8++);
    printf("tmpegts_zero_cb: pointer_field %d\n", pointer_field);
    data8 += pointer_field;
    table_id = *(data8++);
    printf("tmpegts_zero_cb: table_id %d\n", table_id);

    packed_bits = *(data8++);
    packed_bits <<= 8;
    packed_bits |= *(data8++);

    section_length = packed_bits & 0x03FF;
    printf("tmpegts_zero_cb: section_length %d\n", section_length);

    hex_dump(data8, section_length);
    data8 += section_length;

    return 0;
}

/*****************************************************************************/
int
main(int argc, char** argv)
{
    struct hdhomerun_device_t* hdhr;
    const char* dev_name;
    uint8_t* data;
    size_t bytes;
    int error;
    int lbytes;
    struct tmpegts_cb cb;

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
        cb.pids[0] = 0;
        cb.procs[0] = tmpegts_zero_cb;
        cb.num_pids = 1;
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
                error = process_mpeg_ts_packet(data, lbytes, &cb, 0);
                data += lbytes;
                bytes -= lbytes;
            }
            usleep(10 * 1024);
        }
    }
    hdhomerun_device_destroy(hdhr);
    return 0;
}
