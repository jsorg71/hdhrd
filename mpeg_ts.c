/**
 * mpegts calls
 *
 * Copyright 2015-2020 Jay Sorg <jay.sorg@gmail.com>
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

/* https://en.wikipedia.org/wiki/MPEG_transport_stream */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mpeg_ts.h"

/*****************************************************************************/
static int
read_pcr(const void* ptr, int* pcr)
{
    const unsigned char* pui8;
    unsigned int t1;

    pui8 = (const unsigned char*) ptr;
    t1 = (pui8[0] << 24) | (pui8[1] << 16) | (pui8[2] << 8) | pui8[3];
    t1 = t1 / 45;
    *pcr = t1;
    return 0;
}

/*****************************************************************************/
static int
process_pid(struct tmpegts_cb* cb,
            const unsigned char* data8, int cb_bytes,
            struct tmpegts* mpegts, void* udata,
            const unsigned char* ppcr)
{
    struct pid_info* pi;
    struct stream* s;
    int error;
    int index;
    int count;

    count = cb->num_pids;
    for (index = 0; index < count; index++)
    {
        if (cb->pids[index] == mpegts->pid)
        {
            pi = cb->pis + index;
            s = pi->s;
            if (mpegts->payload_unit_start_indicator)
            {
                if (s == NULL)
                {
                    s = (struct stream*)calloc(1, sizeof(struct stream));
                    s->size = 1024 * 1024;
                    s->data = (char*)malloc(s->size);
                    pi->s = s;
                }
                else if (s->end > s->data)
                {
                    if (cb->procs[index] != NULL)
                    {
                        s->p = s->data;
                        error = (cb->procs[index])(pi, udata);
                        if (error != 0)
                        {
                            printf("process_pid: cb for "
                                   "pid %d returned %d\n", mpegts->pid,
                                   error);
                            return 10;
                        }
                    }
                }
                /* reset pi */
                s->p = s->data;
                s->end = s->data;
                pi->flags0 = 0;
                pi->flags1 = 0;
            }
            if (mpegts->payload_flag)
            {
                if (s != NULL)
                {
                    if (!s_check_rem_out(s, cb_bytes))
                    {
                        /* not enough space for new data */
                        return 11;
                    }
                    else
                    {
                        out_uint8a(s, data8, cb_bytes);
                        s->end = s->p;
                    }
                }
            }
            if (ppcr != NULL)
            {
                pi->flags0 |= FLAGS0_PCR_VALID;
                read_pcr(ppcr + 1, &(pi->pcr));
            }
            if (mpegts->random_access_indicator)
            {
                pi->flags0 |= FLAGS0_RANDOM_ACCESS;
            }
        }
    }
    return 0;
}

/*****************************************************************************/
int
process_mpeg_ts_packet(const void* data, int bytes,
                       struct tmpegts_cb* cb, void* udata)
{
    unsigned int header;
    struct tmpegts mpegts;
    const unsigned char* data8;
    const unsigned char* ppcr;

    memset(&mpegts, 0, sizeof(mpegts));
    data8 = (const unsigned char*) data;
    header = (data8[0] << 24) | (data8[1] << 16) | (data8[2] << 8) | data8[3];
    data8 += 4;
    mpegts.sync_byte                    = (header & 0xff000000) >> 24;
    mpegts.transport_error_indicator    = (header & 0x00800000) >> 23;
    mpegts.payload_unit_start_indicator = (header & 0x00400000) >> 22;
    mpegts.transport_priority           = (header & 0x00200000) >> 21;
    mpegts.pid                          = (header & 0x001fff00) >> 8;
    mpegts.scrambling_control           = (header & 0x000000c0) >> 6;
    mpegts.adaptation_field_flag        = (header & 0x00000020) >> 5;
    mpegts.payload_flag                 = (header & 0x00000010) >> 4;
    mpegts.continuity_counter           = (header & 0x0000000f) >> 0;
    if (mpegts.sync_byte != 0x47)
    {
        /* must be parse error */
        return 1;
    }
    if (mpegts.transport_error_indicator)
    {
        return 2;
    }
    if (mpegts.scrambling_control != 0)
    {
        /* not supported */
        return 3;
    }
    ppcr = NULL;
    if (mpegts.adaptation_field_flag && (data8[0] > 0))
    {
        mpegts.adaptation_field_length = data8[0];
        data8++;
        header = data8[0];
        mpegts.discontinuity_indicator              = (header & 0x80) >> 7;
        mpegts.random_access_indicator              = (header & 0x40) >> 6;
        mpegts.elementary_stream_priority_indicator = (header & 0x20) >> 5;
        mpegts.pcr_flag                             = (header & 0x10) >> 4;
        mpegts.opcr_flag                            = (header & 0x08) >> 3;
        mpegts.splicing_point_flag                  = (header & 0x04) >> 2;
        mpegts.transport_private_data_flag          = (header & 0x02) >> 1;
        mpegts.adaptation_field_extension_flag      = (header & 0x01) >> 0;
        if (mpegts.pcr_flag)
        {
            /* 48 bit */
            ppcr = data8;
        }
        data8 += mpegts.adaptation_field_length;
    }
    return process_pid(cb, data8, bytes, &mpegts, udata, ppcr);
}

/*****************************************************************************/
int
mpeg_ts_cleanup(struct tmpegts_cb* cb)
{
    int index;

    for (index = 0; index < 32; index++)
    {
        if (cb->pis[index].s != NULL)
        {
            free(cb->pis[index].s->data);
            free(cb->pis[index].s);
        }
    }
    return 0;
}
