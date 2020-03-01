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
#include "hdhrd_log.h"
#include "hdhrd_utils.h"
#include "hdhrd_error.h"

struct peer_info
{
    int sck;
    int flags;
    int video_frame_count;
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
        if (lout_s->data == NULL)
        {
            if (lout_s->fd > 0)
            {
                close(lout_s->fd);
            }
        }
        else
        {
            free(lout_s->data);
        }
        free(lout_s);
    }
    if (peer->in_s != NULL)
    {
        free(peer->in_s->data);
        free(peer->in_s);
    }
    free(peer);
    return HDHRD_ERROR_NONE;
}

/*****************************************************************************/
static int
hdhrd_peer_remove_one(struct hdhrd_info* hdhrd, struct peer_info** apeer,
                      struct peer_info** alast_peer)
{
    struct peer_info* peer;
    struct peer_info* lpeer;
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
        /* remove middle item */
        last_peer->next = peer->next;
        lpeer = peer;
        peer = peer->next;
        hdhrd_peer_delete_one(lpeer);
    }
    *apeer = peer;
    *alast_peer = last_peer;
    return HDHRD_ERROR_NONE;
}

/*****************************************************************************/
static int
mdhrd_peer_queue_frame(struct hdhrd_info* hdhrd, struct peer_info* peer)
{
    struct stream* out_s;
    int rv;

    if (hdhrd->fd < 1)
    {
        return HDHRD_ERROR_FD;
    }
    out_s = (struct stream*)calloc(1, sizeof(struct stream));
    if (out_s == NULL)
    {
        return HDHRD_ERROR_MEMORY;
    }
    out_s->size = 1024 * 1024;
    out_s->data = (char*)malloc(out_s->size);
    if (out_s->data == NULL)
    {
        free(out_s);
        return HDHRD_ERROR_MEMORY;
    }
    if (peer->video_frame_count == hdhrd->video_frame_count)
    {
        LOGLN0((LOG_INFO, LOGS "peer->video_frame_count %d "
                "hdhrd->video_frame_count %d",
                LOGP, peer->video_frame_count,
                hdhrd->video_frame_count));
    }
    peer->video_frame_count = hdhrd->video_frame_count;
    out_s->p = out_s->data;
    out_uint32_le(out_s, 4);
    out_uint32_le(out_s, 40);
    out_uint32_le(out_s, hdhrd->fd_time);
    out_uint8s(out_s, 4);
    out_uint32_le(out_s, hdhrd->fd);
    out_uint32_le(out_s, hdhrd->fd_width);
    out_uint32_le(out_s, hdhrd->fd_height);
    out_uint32_le(out_s, hdhrd->fd_stride);
    out_uint32_le(out_s, hdhrd->fd_size);
    out_uint32_le(out_s, hdhrd->fd_bpp);
    out_s->end = out_s->p;
    rv = hdhrd_peer_queue(peer, out_s);
    free(out_s->data);
    if (rv == HDHRD_ERROR_NONE)
    {
        memset(out_s, 0, sizeof(struct stream));
        out_s->fd = hdhrd->fd;
        rv = hdhrd_peer_queue(peer, out_s);
    }
    free(out_s);
    return rv;
}

/*****************************************************************************/
static int
mdhrd_peer_process_msg_request_video_frame(struct hdhrd_info* hdhrd,
                                           struct peer_info* peer,
                                           struct stream* in_s)
{
    int rv;

    (void)in_s;

    if (peer->flags & HDHRD_PEER_REQUEST_VIDEO)
    {
        LOGLN10((LOG_INFO, LOGS "already requested", LOGP));
        return HDHRD_ERROR_NONE;
    }
    if ((hdhrd->fd < 1) ||
        (peer->video_frame_count == hdhrd->video_frame_count))
    {
        LOGLN10((LOG_INFO, LOGS "set to get next frame", LOGP));
        peer->flags |= HDHRD_PEER_REQUEST_VIDEO;
        return HDHRD_ERROR_NONE;
    }
    LOGLN10((LOG_INFO, LOGS "sending frame now", LOGP));
    rv = mdhrd_peer_queue_frame(hdhrd, peer);
    return rv;
}

/*****************************************************************************/
static int
mdhrd_peer_process_msg_subscribe_audio(struct hdhrd_info* hdhrd,
                                      struct peer_info* peer,
                                      struct stream* in_s)
{
    unsigned char val8;

    (void)hdhrd;

    in_uint8(in_s, val8);
    if (val8)
    {
        peer->flags |= HDHRD_PEER_SUBSCRIBE_AUDIO;
    }
    else
    {
        peer->flags &= ~HDHRD_PEER_SUBSCRIBE_AUDIO;
    }
    return HDHRD_ERROR_NONE;
}

/*****************************************************************************/
static int
hdhrd_peer_process_msg(struct hdhrd_info* hdhrd, struct peer_info* peer)
{
    int pdu_code;
    int pdu_bytes;
    int rv;
    struct stream* in_s;

    (void)hdhrd;

    rv = HDHRD_ERROR_NONE;
    in_s = peer->in_s;
    in_uint32_le(in_s, pdu_code);
    in_uint32_le(in_s, pdu_bytes);
    LOGLN10((LOG_INFO, LOGS "sck %d pdu_code %d pdu_bytes %d",
             LOGP, peer->sck, pdu_code, pdu_bytes));
    if ((pdu_bytes < 8) || !s_check_rem(in_s, pdu_bytes - 8))
    {
        LOGLN0((LOG_INFO, LOGS "bad pdu_bytes, sck %d pdu_code %d "
                "pdu_bytes %d", LOGP, peer->sck, pdu_code, pdu_bytes));
        return HDHRD_ERROR_RANGE;
    }
    switch (pdu_code)
    {
        case 1:
            rv = mdhrd_peer_process_msg_subscribe_audio(hdhrd, peer, in_s);
            break;
        case 3:
            rv = mdhrd_peer_process_msg_request_video_frame(hdhrd, peer, in_s);
            break;
    }
    return rv;
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
    return HDHRD_ERROR_NONE;
}

/******************************************************************************/
static int
hdhrd_peer_send_fd(int sck, int fd)
{
    ssize_t size;
    struct msghdr msg;
    struct iovec iov;
    union _cmsgu
    {
        struct cmsghdr cmsghdr;
        char control[CMSG_SPACE(sizeof(int))];
    } cmsgu;
    struct cmsghdr *cmsg;
    int *fds;
    char text[4] = "int";

    iov.iov_base = text;
    iov.iov_len = 4;
    msg.msg_name = NULL;
    msg.msg_namelen = 0;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsgu.control;
    msg.msg_controllen = sizeof(cmsgu.control);
    cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    fds = (int *) CMSG_DATA(cmsg);
    *fds = fd;
    size = sendmsg(sck, &msg, 0);
    LOGLN10((LOG_INFO, LOGS "size %d", LOGP, size));
    if (size != 4)
    {
        return HDHRD_ERROR_FD;
    }
    return HDHRD_ERROR_NONE;
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
    int rv;
    int error;

    rv = HDHRD_ERROR_NONE;
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
                    return HDHRD_ERROR_MEMORY;
                }
                in_s->size = 1024 * 1024;
                in_s->data = (char*)malloc(in_s->size);
                if (in_s->data == NULL)
                {
                    free(in_s);
                    return HDHRD_ERROR_MEMORY;
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
                LOGLN0((LOG_ERROR, LOGS "recv failed sck %d reed %d",
                        LOGP, peer->sck, reed));
                error = hdhrd_peer_remove_one(hdhrd, &peer, &last_peer);
                if (error != HDHRD_ERROR_NONE)
                {
                    return error;
                }
                rv = HDHRD_ERROR_PEER_REMOVED;
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
                            LOGLN0((LOG_ERROR, LOGS "bad pdu_bytes %d",
                                    LOGP, pdu_bytes));
                            error = hdhrd_peer_remove_one(hdhrd, &peer, &last_peer);
                            if (error != HDHRD_ERROR_NONE)
                            {
                                return error;
                            }
                            rv = HDHRD_ERROR_PEER_REMOVED;
                            continue;
                        }
                        in_s->end = in_s->data + pdu_bytes;
                    }
                    if (in_s->p >= in_s->end)
                    {
                        /* finished reading in header and payload */
                        in_s->p = in_s->data;
                        rv = hdhrd_peer_process_msg(hdhrd, peer);
                        if (rv != HDHRD_ERROR_NONE)
                        {
                            LOGLN0((LOG_ERROR, LOGS "hdhrd_peer_process_msg "
                                   "failed", LOGP));
                            error = hdhrd_peer_remove_one(hdhrd, &peer, &last_peer);
                            if (error != HDHRD_ERROR_NONE)
                            {
                                return error;
                            }
                            rv = HDHRD_ERROR_PEER_REMOVED;
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
                if (out_s->data == NULL)
                {
                    rv = hdhrd_peer_send_fd(peer->sck, out_s->fd);
                    if (rv != HDHRD_ERROR_NONE)
                    {
                        /* error */
                        LOGLN0((LOG_ERROR, LOGS "hdhrd_peer_send_fd failed "
                                "fd %d", LOGP, out_s->fd));
                        error = hdhrd_peer_remove_one(hdhrd, &peer, &last_peer);
                        if (error != HDHRD_ERROR_NONE)
                        {
                            return error;
                        }
                        rv = HDHRD_ERROR_PEER_REMOVED;
                        continue;
                    }
                    LOGLN10((LOG_DEBUG, LOGS "hdhrd_peer_send_fd ok", LOGP));
                    if (out_s->next == NULL)
                    {
                        peer->out_s_head = NULL;
                        peer->out_s_tail = NULL;
                    }
                    else
                    {
                        peer->out_s_head = out_s->next;
                    }
                    close(out_s->fd);
                    free(out_s);
                }
                else
                {
                    out_bytes = (int)(out_s->end - out_s->p);
                    sent = send(peer->sck, out_s->p, out_bytes, 0);
                    if (sent < 1)
                    {
                        /* error */
                        LOGLN0((LOG_ERROR, LOGS "send failed", LOGP));
                        error = hdhrd_peer_remove_one(hdhrd, &peer, &last_peer);
                        if (error != HDHRD_ERROR_NONE)
                        {
                            return error;
                        }
                        rv = HDHRD_ERROR_PEER_REMOVED;
                        continue;
                    }
                    LOGLN10((LOG_DEBUG, LOGS "send ok, sent %d", LOGP, sent));
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
    return rv;
}

/*****************************************************************************/
int
hdhrd_peer_add_fd(struct hdhrd_info* hdhrd, int sck)
{
    struct peer_info* peer;

    peer = (struct peer_info*)calloc(1, sizeof(struct peer_info));
    if (peer == NULL)
    {
        return HDHRD_ERROR_MEMORY;
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
    return HDHRD_ERROR_NONE;
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
    return HDHRD_ERROR_NONE;
}

/*****************************************************************************/
int
hdhrd_peer_queue_all_video(struct hdhrd_info* hdhrd)
{
    struct peer_info* peer;

    peer = hdhrd->peer_head;
    while (peer != NULL)
    {
        if (peer->flags & HDHRD_PEER_REQUEST_VIDEO)
        {
            mdhrd_peer_queue_frame(hdhrd, peer);
            peer->flags &= ~HDHRD_PEER_REQUEST_VIDEO;
        }
        peer = peer->next;
    }
    return HDHRD_ERROR_NONE;
}

/*****************************************************************************/
int
hdhrd_peer_queue_all_audio(struct hdhrd_info* hdhrd, struct stream* out_s)
{
    int rv;
    struct peer_info* peer;

    peer = hdhrd->peer_head;
    while (peer != NULL)
    {
        if (peer->flags & HDHRD_PEER_SUBSCRIBE_AUDIO)
        {
            rv = hdhrd_peer_queue(peer, out_s);
            if (rv != HDHRD_ERROR_NONE)
            {
                return rv;
            }
        }
        peer = peer->next;
    }
    return HDHRD_ERROR_NONE;
}

/*****************************************************************************/
int
hdhrd_peer_queue(struct peer_info* peer, struct stream* out_s)
{
    struct stream* lout_s;
    int bytes;

    lout_s = (struct stream*)calloc(1, sizeof(struct stream));
    if (lout_s == NULL)
    {
        return HDHRD_ERROR_MEMORY;
    }
    if (out_s->data == NULL)
    {
        lout_s->fd = dup(out_s->fd);
        if (lout_s->fd == -1)
        {
            free(lout_s);
            return HDHRD_ERROR_DUP;
        }
        LOGLN10((LOG_INFO, LOGS "fd %d", LOGP, lout_s->fd));
    }
    else
    {
        bytes = (int)(out_s->end - out_s->data);
        if ((bytes < 1) || (bytes > 1024 * 1024))
        {
            free(lout_s);
            return HDHRD_ERROR_PARAM;
        }
        lout_s->size = bytes;
        lout_s->data = (char*)malloc(lout_s->size);
        if (lout_s->data == NULL)
        {
            free(lout_s);
            return HDHRD_ERROR_MEMORY;
        }
        lout_s->p = lout_s->data;
        out_uint8p(lout_s, out_s->data, bytes);
        lout_s->end = lout_s->p;
        lout_s->p = lout_s->data;
    }
    if (peer->out_s_tail == NULL)
    {
        peer->out_s_head = lout_s;
        peer->out_s_tail = lout_s;
    }
    else
    {
        peer->out_s_tail->next = lout_s;
        peer->out_s_tail = lout_s;
    }
    return HDHRD_ERROR_NONE;
}

