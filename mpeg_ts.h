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

#ifndef _MPEG_TS_H_
#define _MPEG_TS_H_

#include "arch.h"
#include "parse.h"

struct tmpegts
{
    int sync_byte;
    int transport_error_indicator; /* boolean */
    int payload_unit_start_indicator; /* boolean */
    int transport_priority; /* boolean */
    int pid;
    int scrambling_control;
    int adaptation_field_flag; /* boolean */
    int payload_flag; /* boolean */
    int continuity_counter;

    int adaptation_field_length;
    int discontinuity_indicator;
    int random_access_indicator;
    int elementary_stream_priority_indicator;
    int pcr_flag;
    int opcr_flag;
    int splicing_point_flag;
    int transport_private_data_flag;
    int adaptation_field_extension_flag;

    const char* ppcr;
};

#define FLAGS0_PCR_VALID        (1 << 0)
#define FLAGS0_RANDOM_ACCESS    (1 << 1)

struct pid_info
{
    struct stream* s;
    int flags0;
    int flags1;
    int pcr;
    int continuity_counter;
};

typedef int (*tmpegts_cb_proc)(struct pid_info* pi, void* udata);

struct tmpegts_cb
{
    int num_pids;
    int pad0;
    int pids[32];
    tmpegts_cb_proc procs[32];
    struct pid_info pis[32];
};

int
process_mpeg_ts_packet(const void* data, int bytes,
                       struct tmpegts_cb* cb, void* udata);
int
mpeg_ts_cleanup(struct tmpegts_cb* cb);

#endif
