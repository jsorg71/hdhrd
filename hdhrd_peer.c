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
#include <time.h>
#include <sys/un.h>

#include <hdhomerun.h>

#include "arch.h"
#include "parse.h"
#include "mpeg_ts.h"
#include "hdhrd.h"
#include "hdhrd_peer.h"

struct peer_info
{
    int sck;
    int pad0;
    struct stream* out_s;
    struct peer_info* next;
};

/*****************************************************************************/
int
hdhrd_peer_get_fds(struct hdhrd_info* hdhrd, int* max_fd,
                   fd_set* rfds, fd_set* wfds)
{
    struct peer_info* peer;
    int lmax_fd;

    lmax_fd = *max_fd;
    peer = hdhrd->peer_head;
    while (peer != NULL)
    {
        if (peer->sck > lmax_fd)
        {
            lmax_fd = peer->sck;
        }
        FD_SET(peer->sck, rfds);
        if (peer->out_s != NULL)
        {
            FD_SET(peer->sck, wfds);
        }
        peer = peer->next;
    }
    *max_fd = lmax_fd;
    return 0;
}

/*****************************************************************************/
int
hdhrd_peer_check_fds(struct hdhrd_info* hdhrd, fd_set* rfds, fd_set* wfds)
{
    struct peer_info* peer;

    peer = hdhrd->peer_head;
    while (peer != NULL)
    {
        if (FD_ISSET(peer->sck, rfds))
        {
        }
        if (FD_ISSET(peer->sck, wfds))
        {
            if (peer->out_s != NULL)
            {
            }
        }
        peer = peer->next;
    }
    return 0;
}

/*****************************************************************************/
int
hdhrd_peer_add_fd(struct hdhrd_info* hdhrd, int sck)
{
    struct peer_info* peer;

    peer = (struct peer_info*)calloc(1, sizeof(struct peer_info));
    if (peer == NULL)
    {
        return 1;
    }
    peer->sck = sck;
    if (hdhrd->peer_head == NULL)
    {
        hdhrd->peer_head = peer;
        hdhrd->peer_tail = peer;
    }
    else
    {
        hdhrd->peer_head->next = peer;
        hdhrd->peer_tail = peer;
    }
    return 0;
}

/*****************************************************************************/
int
hdhrd_peer_cleanup(struct hdhrd_info* hdhrd)
{
    (void)hdhrd;
    return 0;
}

