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
    struct stream* out_s_head;
    struct stream* out_s_tail;
    struct stream* in_s;
    struct peer_info* next;
};

/*****************************************************************************/
static int
hdhrd_peer_delete_one(struct peer_info* peer)
{
    struct stream* out_s;
    struct stream* lout_s;

    close(peer->sck);
    out_s = peer->out_s_head;
    while (out_s != NULL)
    {
        lout_s = out_s;
        out_s = out_s->next;
        free(lout_s->data);
        free(lout_s);
    }
    if (peer->in_s != NULL)
    {
        free(peer->in_s->data);
        free(peer->in_s);
    }
    free(peer);
    return 0;
}

/*****************************************************************************/
static int
hdhrd_peer_remove_one(struct hdhrd_info* hdhrd, struct peer_info** apeer,
                      struct peer_info** alast_peer)
{
    struct peer_info* peer;
    struct peer_info* last_peer;

    peer = *apeer;
    last_peer = *alast_peer;
    if ((hdhrd->peer_head == peer) && (hdhrd->peer_tail == peer))
    {
        /* remove only item */
        hdhrd->peer_head = NULL;
        hdhrd->peer_tail = NULL;
        hdhrd_peer_delete_one(peer);
        last_peer = NULL;
        peer = NULL;
    }
    else if (hdhrd->peer_head == peer)
    {
        /* remove first item */
        hdhrd->peer_head = peer->next;
        hdhrd_peer_delete_one(peer);
        last_peer = NULL;
        peer = hdhrd->peer_head;
    }
    else if (hdhrd->peer_tail == peer)
    {
        /* remove last item */
        hdhrd->peer_tail = last_peer;
        last_peer->next = peer->next;
        hdhrd_peer_delete_one(peer);
        last_peer = NULL;
        peer = NULL;
    }
    else
    {
        /* remome middle item */
        last_peer->next = peer->next;
        hdhrd_peer_delete_one(peer);
        last_peer = peer;
        peer = peer->next;
    }
    *apeer = peer;
    *alast_peer = last_peer;
    return 0;
}

/*****************************************************************************/
static int
hdhrd_peer_process_msg(struct hdhrd_info* hdhrd, struct peer_info* peer)
{
    int pdu_code;
    int pdu_bytes;
    struct stream* in_s;

    (void)hdhrd;

    in_s = peer->in_s;
    in_uint32_le(in_s, pdu_code);
    in_uint32_le(in_s, pdu_bytes);
    printf("hdhrd_peer_process_msg: sck %d pdu_code %d pdu_bytes %d\n",
           peer->sck, pdu_code, pdu_bytes);
    return 0;
}

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
        if (peer->out_s_head != NULL)
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
    struct peer_info* last_peer;
    struct stream* out_s;
    struct stream* in_s;
    int out_bytes;
    int in_bytes;
    int sent;
    int reed;
    int pdu_bytes;

    last_peer = NULL;
    peer = hdhrd->peer_head;
    while (peer != NULL)
    {
        if (FD_ISSET(peer->sck, rfds))
        {
            in_s = peer->in_s;
            if (in_s == NULL)
            {
                in_s = (struct stream*)calloc(1, sizeof(struct stream));
                if (in_s == NULL)
                {
                    return 1;
                }
                in_s->size = 1024 * 1024;
                in_s->data = (char*)malloc(in_s->size);
                if (in_s->data == NULL)
                {
                    free(in_s);
                    return 2;
                }
                in_s->p = in_s->data;
                in_s->end = in_s->data;
                peer->in_s = in_s;
            }
            if (in_s->p == in_s->data)
            {
                in_s->end = in_s->data + 8;
            }
            in_bytes = (int)(in_s->end - in_s->p);
            reed = recv(peer->sck, in_s->p, in_bytes, 0);
            if (reed < 1)
            {
                /* error */
                printf("hdhrd_peer_check_fds: recv failed sck %d reed %d\n",
                       peer->sck, reed);
                hdhrd_peer_remove_one(hdhrd, &peer, &last_peer);
                continue;
            }
            else
            {
                in_s->p += reed;
                if (in_s->p >= in_s->end)
                {
                    if (in_s->p == in_s->data + 8)
                    {
                        /* finished reading in header */
                        in_s->p = in_s->data;
                        in_uint8s(in_s, 4); /* pdu_code */
                        in_uint32_le(in_s, pdu_bytes);
                        if ((pdu_bytes < 8) || (pdu_bytes > in_s->size))
                        {
                            printf("hdhrd_peer_check_fds: bad pdu_bytes %d\n",
                                   pdu_bytes);
                            hdhrd_peer_remove_one(hdhrd, &peer, &last_peer);
                            continue;
                        }
                        in_s->end = in_s->data + pdu_bytes;
                    }
                    if (in_s->p >= in_s->end)
                    {
                        /* finished reading in header and payload */
                        in_s->p = in_s->data;
                        if (hdhrd_peer_process_msg(hdhrd, peer) != 0)
                        {
                            printf("hdhrd_peer_check_fds: "
                                   "hdhrd_peer_process_msg failed\n");
                            hdhrd_peer_remove_one(hdhrd, &peer, &last_peer);
                            continue;
                        }
                        in_s->p = in_s->data;
                    }
                }
            }
        }
        if (FD_ISSET(peer->sck, wfds))
        {
            out_s = peer->out_s_head;
            if (out_s != NULL)
            {
                out_bytes = (int)(out_s->end - out_s->p);
                sent = send(peer->sck, out_s->p, out_bytes, 0);
                if (sent < 1)
                {
                    /* error */
                    printf("hdhrd_peer_check_fds: send failed\n");
                    hdhrd_peer_remove_one(hdhrd, &peer, &last_peer);
                    continue;
                }
                else
                {
                    out_s->p += sent;
                    if (out_s->p >= out_s->end)
                    {
                        if (out_s->next == NULL)
                        {
                            peer->out_s_head = NULL;
                            peer->out_s_tail = NULL;
                        }
                        else
                        {
                            peer->out_s_head = out_s->next;
                        }
                        free(out_s->data);
                        free(out_s);
                    }
                }
            }
        }
        last_peer = peer;
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
        hdhrd->peer_tail->next = peer;
        hdhrd->peer_tail = peer;
    }
    return 0;
}

/*****************************************************************************/
int
hdhrd_peer_cleanup(struct hdhrd_info* hdhrd)
{
    struct peer_info* peer;
    struct peer_info* lpeer;

    peer = hdhrd->peer_head;
    while (peer != NULL)
    {
        lpeer = peer;
        peer = peer->next;
        hdhrd_peer_delete_one(lpeer);
    }
    hdhrd->peer_head = NULL;
    hdhrd->peer_tail = NULL;
    return 0;
}

