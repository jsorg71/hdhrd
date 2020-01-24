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

#ifndef _HDHRD_H_
#define _HDHRD_H_

#define HDHRD_BUFFER_SIZE (32 * 1024)
#define HDHRD_SELECT_MSTIME 15
#define HDHRD_UDS "/tmp/wtv_hdhrd%d"

struct hdhrd_info
{
    struct tmpegts_cb cb;
    int listener;
    int yami_fd;
    void* ac3;
    void* yami;
    struct peer_info* peer_head;
    struct peer_info* peer_tail;
};

#endif

