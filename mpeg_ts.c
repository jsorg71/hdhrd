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
#include "hdhrd_log.h"
#include "hdhrd_error.h"

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
    return HDHRD_ERROR_NONE;
}

/*****************************************************************************/
static int
process_pid(struct tmpegts_cb* cb, struct stream* in_s,
            struct tmpegts* mpegts, void* udata)
{
    struct pid_info* pi;
    struct stream* s;
    int error;
    int index;
    int count;
    int cb_bytes;

    cb_bytes = (int) (in_s->end - in_s->p);
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
                    if (s == NULL)
                    {
                        return HDHRD_ERROR_MEMORY;
                    }
                    s->size = 1024 * 1024;
                    s->data = (char*)malloc(s->size);
                    if (s->data == NULL)
                    {
                        free(s);
                        return HDHRD_ERROR_MEMORY;
                    }
                    pi->s = s;
                }
                else if (s->end > s->data)
                {
                    if (cb->procs[index] != NULL)
                    {
                        s->p = s->data;
                        error = (cb->procs[index])(pi, udata);
                        if (error != HDHRD_ERROR_NONE)
                        {
                            LOGLN0((LOG_ERROR, LOGS "cb for pid %d "
                                    "returned %d", LOGP, mpegts->pid,
                                    error));
                            return error;
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
                    if ((s->end > s->data) &&
                         (mpegts->continuity_counter !=
                          ((pi->continuity_counter + 1) & 0xF)))
                    {
                        LOGLN0((LOG_ERROR, LOGS "continuity_counter mismatch "
                                "expected 0x%2.2x got 0x%2.2x "
                                "pid 0x%4.4x", LOGP,
                                pi->continuity_counter + 1,
                                mpegts->continuity_counter, mpegts->pid));
                        /* maybe lost one */
                        free(s->data);
                        free(s);
                        pi->s = NULL;
                    }
                    else if (!s_check_rem_out(s, cb_bytes))
                    {
                        /* not enough space for new data */
                        return HDHRD_ERROR_RANGE;
                    }
                    else
                    {
                        out_uint8a(s, in_s->p, cb_bytes);
                        s->end = s->p;
                    }
                }
                pi->continuity_counter = mpegts->continuity_counter;
            }
            if (mpegts->ppcr != NULL)
            {
                pi->flags0 |= FLAGS0_PCR_VALID;
                read_pcr(mpegts->ppcr, &(pi->pcr));
                LOGLN10((LOG_INFO, LOGS "pcr %10.10u pid 0x%x", LOGP, pi->pcr,
                         mpegts->pid));
            }
            if (mpegts->random_access_indicator)
            {
                pi->flags0 |= FLAGS0_RANDOM_ACCESS;
            }
        }
    }
    return HDHRD_ERROR_NONE;
}

/*****************************************************************************/
int
process_mpeg_ts_packet(const void* data, int bytes,
                       struct tmpegts_cb* cb, void* udata)
{
    unsigned int header;
    struct tmpegts mpegts;
    struct stream ls;
    char* holdp;

    memset(&ls, 0, sizeof(ls));
    ls.data = (char*)data;
    ls.p = ls.data;
    ls.end = ls.p + bytes;
    in_uint32_be(&ls, header);
    memset(&mpegts, 0, sizeof(mpegts));
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
        return HDHRD_ERROR_TS;
    }
    if (mpegts.transport_error_indicator)
    {
        LOGLN0((LOG_ERROR, LOGS "transport_error_indicator set, pid %d",
                LOGP, mpegts.pid));
        return HDHRD_ERROR_TS;
    }
    if (mpegts.scrambling_control != 0)
    {
        /* not supported */
        return HDHRD_ERROR_NOT_SUPPORTED;
    }
    if (mpegts.adaptation_field_flag)
    {
        if (!s_check_rem(&ls, 1))
        {
            return HDHRD_ERROR_RANGE;
        }
        in_uint8(&ls, mpegts.adaptation_field_length);
        if (mpegts.adaptation_field_length > 0)
        {
            if (!s_check_rem(&ls, mpegts.adaptation_field_length))
            {
                return HDHRD_ERROR_RANGE;
            }
            holdp = ls.p;
            in_uint8(&ls, header);
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
                if (!s_check_rem(&ls, 6))
                {
                    return HDHRD_ERROR_RANGE;
                }
                in_uint8p(&ls, mpegts.ppcr, 6);
            }
            ls.p = holdp + mpegts.adaptation_field_length;
        }
    }
    return process_pid(cb, &ls, &mpegts, udata);
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
            cb->pis[index].s = NULL;
        }
    }
    return HDHRD_ERROR_NONE;
}
