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
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>

#include <hdhomerun.h>

#include <yami_inf.h>

#include "arch.h"
#include "parse.h"
#include "mpeg_ts.h"
#include "hdhrd.h"
#include "hdhrd_ac3.h"
#include "hdhrd_peer.h"
#include "hdhrd_log.h"
#include "hdhrd_utils.h"

static int g_term_pipe[2];

struct video_info
{
    int dts;
    int pts;
    int flags0;
    int flags1;
    struct stream* s;
    struct video_info* next;
};

struct audio_info
{
    int dts;
    int pts;
    int flags0;
    int flags1;
    struct stream* s;
    struct audio_info* next;
};

struct settings_info
{
    char hdhrd_uds[256];
    char hdhrd_device_name[256];
    char hdhrd_channel_name[256];
    char hdhrd_program_name[256];
};

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
read_pes(struct stream* s, int* bytes, int* pts, int* dts)
{
    unsigned char code;
    unsigned char remaining;
    char* holdp;

    if (!s_check_rem(s, 9))
    {
        return 1;
    }
    in_uint8s(s, 4);
    in_uint16_be(s, *bytes);
    in_uint8s(s, 1);
    in_uint8(s, code);
    LOGLN10((LOG_DEBUG, LOGS "code 0x%2.2x", LOGP, code));
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
hdhrd_process_vi(struct hdhrd_info* hdhrd)
{
    int error;
    int cdata_bytes;
    int now;
    struct stream* s;
    struct video_info* vi;

    LOGLN10((LOG_INFO, LOGS, LOGP));
    vi = hdhrd->video_head;
    if (vi != NULL)
    {
        if (get_mstime(&now) == 0)
        {
            LOGLN10((LOG_INFO, LOGS "vi %p pts %10.10u dts %10.10u "
                     "now %10.10d vi->pts - hdhrd->video_dif %10.10d",
                     LOGP, vi, vi->pts, vi->dts, now,
                     vi->pts - hdhrd->video_diff));
            if (now < (vi->pts - hdhrd->video_diff))
            {
                LOGLN10((LOG_INFO, LOGS "not yet", LOGP));
                return 0;
            }
        }
        s = vi->s;
        if ((hdhrd->yami == NULL) && (vi->flags0 & FLAGS0_RANDOM_ACCESS))
        {
            yami_decoder_delete(hdhrd->yami);
            error = yami_decoder_create(&(hdhrd->yami), 0, 0,
                                        YI_TYPE_MPEG2, 0);
            LOGLN0((LOG_INFO, LOGS "yami_decoder_create rv %d", LOGP, error));
            hdhrd->video_frame_count = 0;
        }
        if (hdhrd->yami != NULL)
        {
            cdata_bytes = (int)(s->end - s->p);
            error = yami_decoder_decode(hdhrd->yami, s->p, cdata_bytes);
            LOGLN10((LOG_DEBUG, LOGS "cdata_bytes %d yami_decoder_decode "
                   "rv %d", LOGP, cdata_bytes, error));
            if (error == 0)
            {
                if (hdhrd->fd > 0)
                {
                    close(hdhrd->fd);
                    hdhrd->fd = 0;
                }
                error = yami_decoder_get_fd_dst(hdhrd->yami, &hdhrd->fd,
                                                &hdhrd->fd_width,
                                                &hdhrd->fd_height,
                                                &hdhrd->fd_stride,
                                                &hdhrd->fd_size,
                                                &hdhrd->fd_bpp);
                LOGLN10((LOG_DEBUG, LOGS "yami_decoder_get_fd_dst rv %d fd %d "
                         "fd_width %d fd_height %d fd_stride %d fd_size %d "
                         "fd_bpp %d", LOGP, error, hdhrd->fd,
                         hdhrd->fd_width, hdhrd->fd_height,
                         hdhrd->fd_stride, hdhrd->fd_size, hdhrd->fd_bpp));
                if (error == 0)
                {
#if 0
                    int now;
                    get_mstime(&now);
                    LOGLN0((LOG_INFO, LOGS "last frame %d", LOGP, now - hdhrd->last_decode_mstime));
#endif
                    hdhrd->last_decode_mstime = now;
                    hdhrd->fd_pts = vi->pts;
                    hdhrd->fd_dts = vi->dts;
                    hdhrd->video_frame_count++;
                    hdhrd_peer_queue_all_video(hdhrd);
                }
                else
                {
                    LOGLN0((LOG_ERROR, LOGS "yami_decoder_get_fd_dst failed "
                            "rv %d", LOGP, error));
                }
            }
            else
            {
                LOGLN0((LOG_ERROR, LOGS "yami_decoder_decode failed rv %d",
                        LOGP, error));
            }
        }
        if (vi->next == NULL)
        {
            hdhrd->video_head = NULL;
            hdhrd->video_tail = NULL;
        }
        else
        {
            hdhrd->video_head = hdhrd->video_head->next;
        }
        LOGLN10((LOG_DEBUG, LOGS "video_head %p video_tail %p", LOGP,
                 hdhrd->video_head, hdhrd->video_tail));
        free(vi->s->data);
        free(vi->s);
        free(vi);
        return 1;
    }
    return 0;
}

/*****************************************************************************/
static int
hdhrd_process_ai(struct hdhrd_info* hdhrd)
{
    int error;
    int cdata_bytes;
    int now;
    int decoded;
    int cdata_bytes_processed;
    int channels;
    int bytes;
    struct stream* s;
    struct stream* out_s;
    struct audio_info* ai;

    LOGLN10((LOG_INFO, LOGS, LOGP));
    ai = hdhrd->audio_head;
    if (ai != NULL)
    {
        if (get_mstime(&now) == 0)
        {
            LOGLN10((LOG_INFO, LOGS "vi %p pts %10.10u dts %10.10u "
                     "now %10.10u", LOGP, vi, vi->pts, vi->dts, now));
            if (now < (ai->pts - hdhrd->audio_diff))
            {
                LOGLN10((LOG_INFO, LOGS "not yet", LOGP));
                return 0;
            }
        }
        s = ai->s;
        if (hdhrd->ac3 == NULL)
        {
            error = hdhrd_ac3_create(&(hdhrd->ac3));
            LOGLN0((LOG_INFO, LOGS "hdhrd_ac3_create rv %d", LOGP, error));
        }
        if (hdhrd->ac3 != NULL)
        {
            while (s_check_rem(s, 8))
            {
                cdata_bytes = (int)(s->end - s->p);
                decoded = 0;
                error = hdhrd_ac3_decode(hdhrd->ac3, s->p, cdata_bytes,
                                         &cdata_bytes_processed, &decoded);
                LOGLN10((LOG_DEBUG, LOGS "error %d cdata_bytes %d "
                         "cdata_bytes_processed %d decoded %d",
                         LOGP, error, cdata_bytes, cdata_bytes_processed,
                         decoded));
                if (error != 0)
                {
                    LOGLN0((LOG_ERROR, LOGS "hdhrd_ac3_decode "
                            "failed %d", LOGP, error));
                    break;
                }
                s->p += cdata_bytes_processed;
                if (decoded)
                {
                    error = hdhrd_ac3_get_frame_info(hdhrd->ac3, &channels,
                                                     &bytes);
                    if (error != 0)
                    {
                        LOGLN0((LOG_ERROR, LOGS "hdhrd_ac3_get_frame_info "
                                "failed %d", LOGP, error));
                    }
                    LOGLN10((LOG_DEBUG, LOGS "channels %d bytes %d",
                             LOGP, channels, bytes));
                    out_s = (struct stream*)calloc(1, sizeof(struct stream));
                    if (out_s != NULL)
                    {
                        out_s->size = bytes + 1024;
                        out_s->data = (char*)malloc(out_s->size);
                        if (out_s->data != NULL)
                        {
                            out_s->p = out_s->data;
                            out_uint32_le(out_s, 2);
                            out_uint32_le(out_s, 24 + bytes);
                            out_uint32_le(out_s, ai->pts);
                            out_uint32_le(out_s, ai->dts);
                            out_uint32_le(out_s, channels);
                            out_uint32_le(out_s, bytes);
                            error = hdhrd_ac3_get_frame_data(hdhrd->ac3,
                                                             out_s->p,
                                                             bytes);
                            if (error != 0)
                            {
                                LOGLN0((LOG_ERROR, LOGS
                                        "hdhrd_ac3_get_frame_data "
                                        "failed %d", LOGP, error));
                                free(out_s->data);
                                free(out_s);
                                break;
                            }
                            out_s->p += bytes;
                            out_s->end = out_s->p;
                            out_s->p = out_s->data;
                            hdhrd_peer_queue_all_audio(hdhrd, out_s);
                            free(out_s->data);
                        }
                        free(out_s);
                    }
                }
            }
        }
        if (ai->next == NULL)
        {
            hdhrd->audio_head = NULL;
            hdhrd->audio_tail = NULL;
        }
        else
        {
            hdhrd->audio_head = hdhrd->audio_head->next;
        }
        LOGLN10((LOG_DEBUG, LOGS "audio_head %p audio_tail %p", LOGP,
                 hdhrd->audio_head, hdhrd->audio_tail));
        free(ai->s->data);
        free(ai->s);
        free(ai);
        return 1;
    }
    return 0;
}

/*****************************************************************************/
static int
tmpegts_video_cb(struct pid_info* pi, void* udata)
{
    int error;
    int pts;
    int dts;
    int cdata_bytes;
    int pdu_bytes;
    int now;
    struct stream* s;
    struct hdhrd_info* hdhrd;
    struct video_info* vi;

    hdhrd = (struct hdhrd_info*)udata;
    LOGLN10((LOG_DEBUG, LOGS "bytes %10.10d flags0 0x%8.8x", LOGP,
             (int)(pi->s->end - pi->s->data), pi->flags0));
    s = pi->s;
    pts = 0;
    dts = 0;
    error = read_pes(s, &pdu_bytes, &pts, &dts);
    if (error != 0)
    {
        return 0;
    }
    if ((hdhrd->video_diff == 0) ||
        (pts > hdhrd->video_update_pts + HDHRD_SYNC_MSTIME))
    {
        if (get_mstime(&now) == 0)
        {
            hdhrd->video_update_pts = pts;
            hdhrd->video_diff = (pts - now) - HDHRD_VIDEO_DELAY_MSTIME;
            LOGLN10((LOG_INFO, LOGS "video_diff %10.10d", LOGP,
                     hdhrd->video_diff));
        }
    }
#if 0
    get_mstime(&now);
    LOGLN0((LOG_DEBUG, LOGS "pts diff  %10.10d", LOGP,
            (pts - hdhrd->video_diff) - now));
#endif
    LOGLN10((LOG_DEBUG, LOGS "error %d pts %10.10u dts %10.10u "
             "pdu_bytes %d", LOGP, error, pts, dts, pdu_bytes));
    vi = (struct video_info*)calloc(1, sizeof(struct video_info));
    if (vi == NULL)
    {
        return 1;
    }
    vi->s = (struct stream*)calloc(1, sizeof(struct stream));
    if (vi->s == NULL)
    {
        free(vi);
        return 2;
    }
    cdata_bytes = (int)(s->end - s->p);
    vi->s->size = cdata_bytes;
    vi->s->data = (char*)malloc(vi->s->size);
    if (vi->s->data == NULL)
    {
        free(vi->s);
        free(vi);
        return 3;
    }
#if 0
    LOGLN0((LOG_DEBUG, LOGS "cdata_bytes %d", LOGP, cdata_bytes));
    //hex_dump(s->p, 64);
    int index;
    for (index = 0; index < cdata_bytes - 4; index++)
    {
        if (s->p[index] == 0 && s->p[index + 1] == 0 && s->p[index + 2] == 0 && s->p[index + 3] == 1)
        {
            LOGLN0((LOG_DEBUG, LOGS "found index %d", LOGP, index));
        }
    }
#endif
    vi->s->size = cdata_bytes;
    vi->pts = pts;
    vi->dts = dts;
    vi->flags0 = pi->flags0;
    vi->flags1 = pi->flags1;
    vi->s->p = vi->s->data;
    out_uint8p(vi->s, s->p, cdata_bytes);
    vi->s->end = vi->s->p;
    vi->s->p = vi->s->data;
    if (hdhrd->video_tail == NULL)
    {
        hdhrd->video_head = vi;
        hdhrd->video_tail = vi;
    }
    else
    {
        hdhrd->video_tail->next = vi;
        hdhrd->video_tail = vi;
    }
    LOGLN10((LOG_DEBUG, LOGS "video_head %p video_tail %p", LOGP,
             hdhrd->video_head, hdhrd->video_tail));
    return 0;
}

/*****************************************************************************/
static int
tmpegts_audio_cb(struct pid_info* pi, void* udata)
{
    int error;
    int pts;
    int dts;
    int cdata_bytes;
    int pdu_bytes;
    int now;
    struct stream* s;
    struct hdhrd_info* hdhrd;
    struct audio_info* ai;

    hdhrd = (struct hdhrd_info*)udata;

    LOGLN10((LOG_DEBUG, LOGS "bytes %10.10d flags0 0x%8.8x",
             LOGP, (int)(pi->s->end - pi->s->data), pi->flags0));
    s = pi->s;
    pts = 0;
    dts = 0;
    error = read_pes(s, &pdu_bytes, &pts, &dts);
    if (error != 0)
    {
        return 0;
    }
    if ((hdhrd->audio_diff == 0) ||
        (pts > hdhrd->audio_update_pts + HDHRD_SYNC_MSTIME))
    {
        if (get_mstime(&now) == 0)
        {
            hdhrd->audio_update_pts = pts;
            hdhrd->audio_diff = (pts - now) - HDHRD_AUDIO_DELAY_MSTIME;
            LOGLN10((LOG_INFO, LOGS "audio_diff %10.10d", LOGP,
                     hdhrd->audio_diff));
        }
    }
#if 0
    get_mstime(&now);
    LOGLN0((LOG_DEBUG, LOGS "pts diff  %10.10d", LOGP,
            (pts - hdhrd->video_diff) - now));
#endif
    LOGLN10((LOG_DEBUG, LOGS "error %d pts %10.10u dts %10.10u "
             "pdu_bytes %d", LOGP, error, pts, dts, pdu_bytes));
    ai = (struct audio_info*)calloc(1, sizeof(struct audio_info));
    if (ai == NULL)
    {
        return 1;
    }
    ai->s = (struct stream*)calloc(1, sizeof(struct stream));
    if (ai->s == NULL)
    {
        free(ai);
        return 2;
    }
    cdata_bytes = (int)(s->end - s->p);
    ai->s->size = cdata_bytes;
    ai->s->data = (char*)malloc(ai->s->size);
    if (ai->s->data == NULL)
    {
        free(ai->s);
        free(ai);
        return 3;
    }
    ai->s->size = cdata_bytes;
    ai->pts = pts;
    ai->dts = dts;
    ai->flags0 = pi->flags0;
    ai->flags1 = pi->flags1;
    ai->s->p = ai->s->data;
    out_uint8p(ai->s, s->p, cdata_bytes);
    ai->s->end = ai->s->p;
    ai->s->p = ai->s->data;
    if (hdhrd->audio_tail == NULL)
    {
        hdhrd->audio_head = ai;
        hdhrd->audio_tail = ai;
    }
    else
    {
        hdhrd->audio_tail->next = ai;
        hdhrd->audio_tail = ai;
    }
    LOGLN10((LOG_DEBUG, LOGS "audio_head %p audio_tail %p", LOGP,
             hdhrd->audio_head, hdhrd->audio_tail));
    return 0;
}

/*****************************************************************************/
static int
tmpegts_program_cb(struct pid_info* pi, void* udata)
{
    int pointer_field;
    int table_id;
    int packed_bits;
    int section_length;
    int program_info_length;
    int stream_type;
    int elementary_pid;
    int es_info_length;
    int video_pid;
    int audio_pid;
    struct hdhrd_info* hdhrd;
    struct stream* s;

    LOGLN10((LOG_INFO, LOGS "bytes %d", LOGP,
             (int)(pi->s->end - pi->s->data)));
    hdhrd = (struct hdhrd_info*)udata;
    s = pi->s;
    if (!s_check_rem(s, 1))
    {
        return 1;
    }
    in_uint8(s, pointer_field);
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
    LOGLN10((LOG_INFO, LOGS "table_id %d", LOGP, table_id));
    if (table_id != 2)
    {
        return 4;
    }
    in_uint16_be(s, packed_bits);
    section_length = packed_bits & 0x03FF;
    if (!s_check_rem(s, section_length))
    {
        return 5;
    }
    LOGLN10((LOG_INFO, LOGS "section_length %d", LOGP, section_length));
    if (hdhrd->cb.num_pids != 2)
    {
        return 0;
    }
    s->end = s->p + section_length;
    if (packed_bits & 0x8000) /* section_syntax_indicator */
    {
        if (!s_check_rem(s, 9))
        {
            return 6;
        }
        in_uint8s(s, 7);
        in_uint16_be(s, packed_bits);
        program_info_length = packed_bits & 0x03FF;
        if (!s_check_rem(s, program_info_length))
        {
            return 7;
        }
        in_uint8s(s, program_info_length);
        video_pid = 0;
        audio_pid = 0;
        while (s_check_rem(s, 9)) /* last 4 bytes is crc */
        {
            in_uint8(s, stream_type);
            in_uint16_be(s, packed_bits);
            elementary_pid = packed_bits & 0x1FFF;
            in_uint16_be(s, packed_bits);
            es_info_length = packed_bits & 0x03FF;
            LOGLN0((LOG_INFO, LOGS "found stream_type 0x%4.4x "
                    "elementary_pid 0x%4.4x es_info_length %d",
                    LOGP, stream_type, elementary_pid, es_info_length));
            //hex_dump(s->p, es_info_length);
            in_uint8s(s, es_info_length);
            if ((stream_type == 0x02) && (video_pid == 0)) /* mpeg2 */
            {
                video_pid = elementary_pid;
            }
            if ((stream_type == 0x81) && (audio_pid == 0)) /* ac3 */
            {
                audio_pid = elementary_pid;
            }
        }
        if ((video_pid != 0) && (audio_pid != 0))
        {
            LOGLN0((LOG_INFO, LOGS "adding video pid 0x%4.4x", LOGP, video_pid));
            hdhrd->cb.pids[2] = video_pid;
            hdhrd->cb.procs[2] = tmpegts_video_cb;
            LOGLN0((LOG_INFO, LOGS "adding audio pid 0x%4.4x", LOGP, audio_pid));
            hdhrd->cb.pids[3] = audio_pid;
            hdhrd->cb.procs[3] = tmpegts_audio_cb;
            hdhrd->cb.num_pids = 4;
        }
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
    int program_num;
    int program_map_pid;
    int pmt_pid;
    struct stream* s;

    LOGLN10((LOG_INFO, LOGS "bytes %d", LOGP,
             (int)(pi->s->end - pi->s->data)));
    hdhrd = (struct hdhrd_info*)udata;
    s = pi->s;
    if (!s_check_rem(s, 1))
    {
        return 1;
    }
    in_uint8(s, pointer_field);
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
    LOGLN10((LOG_INFO, LOGS "table_id %d", LOGP, table_id));
    if (table_id != 0)
    {
        return 4;
    }
    in_uint16_be(s, packed_bits);
    section_length = packed_bits & 0x03FF;
    if (!s_check_rem(s, section_length))
    {
        return 5;
    }
    LOGLN10((LOG_INFO, LOGS "ection_length %d", LOGP, section_length));
    if (hdhrd->cb.num_pids != 1)
    {
        return 0;
    }
    s->end = s->p + section_length;
    if (packed_bits & 0x8000) /* section_syntax_indicator */
    {
        if (!s_check_rem(s, 5))
        {
            return 6;
        }
        in_uint8s(s, 5);
        pmt_pid = 0;
        while (s_check_rem(s, 8)) /* last 4 bytes is crc */
        {
            in_uint16_be(s, program_num);
            in_uint16_be(s, program_map_pid);
            program_map_pid &= 0x1FFF;
            if ((program_map_pid != 0) && (pmt_pid == 0))
            {
                pmt_pid = program_map_pid;
            }
            LOGLN0((LOG_INFO, LOGS "found program_num 0x%4.4x "
                    "program_map_pid 0x%4.4x", LOGP,
                    program_num, program_map_pid));
        }
        if (pmt_pid != 0)
        {
            LOGLN0((LOG_INFO, LOGS "adding program pid 0x%4.4x",
                    LOGP, pmt_pid));
            hdhrd->cb.pids[1] = pmt_pid;
            hdhrd->cb.procs[1] = tmpegts_program_cb;
            hdhrd->cb.num_pids = 2;
        }
    }
    return 0;
}

/*****************************************************************************/
static void
sig_int(int sig)
{
    (void)sig;
    if (write(g_term_pipe[1], "sig", 4) != 4)
    {
    }
}

/*****************************************************************************/
static void
sig_pipe(int sig)
{
    (void)sig;
}

/*****************************************************************************/
static int
process_args(int argc, char** argv, struct settings_info* setting)
{
    int index;

    for (index = 1; index < argc; index++)
    {
        if (strcmp("-c", argv[index]) == 0)
        {
            index++;
            strncpy(setting->hdhrd_channel_name, argv[index], 255);
        }
        else if (strcmp("-d", argv[index]) == 0)
        {
            index++;
            strncpy(setting->hdhrd_device_name, argv[index], 255);
        }
        else if (strcmp("-p", argv[index]) == 0)
        {
            index++;
            strncpy(setting->hdhrd_program_name, argv[index], 255);
        }
        else
        {
            return 1;
        }
    }
    return 0;
}

/*****************************************************************************/
static int
printf_help(int argc, char** argv)
{
    (void)argc;
    (void)argv;
    return 0;
}

/*****************************************************************************/
static int
hdhrd_process_stream_recv(struct hdhrd_info* hdhrd)
{
    uint8_t* data;
    size_t bytes;
    int lbytes;
    int error;

    bytes = HDHRD_BUFFER_SIZE;
    data = hdhomerun_device_stream_recv(hdhrd->hdhr, bytes, &bytes);
    LOGLN10((LOG_INFO, LOGS "data %p HDHRD_BUFFER_SIZE %d, bytes %ld",
             LOGP, data, HDHRD_BUFFER_SIZE, bytes));
    if (data == NULL)
    {
        LOGLN10((LOG_INFO, LOGS "hdhomerun_device_stream_recv "
                 "return nil", LOGP));
    }
    else
    {
        if (HDHRD_BUFFER_SIZE - bytes < 2 * 1024)
        {
            LOGLN10((LOG_INFO, LOGS "hdhomerun_device_stream_recv might "
                     "have missed data HDHRD_BUFFER_SIZE %d bytes %d",
                     LOGP, HDHRD_BUFFER_SIZE, bytes));
        }
        error = 0;
        while ((error == 0) && (bytes > 3))
        {
            lbytes = bytes;
            if (lbytes > TS_PACKET_SIZE) /* 188 */
            {
                lbytes = TS_PACKET_SIZE;
            }
            error = process_mpeg_ts_packet(data, lbytes, &(hdhrd->cb),
                                           hdhrd);
            data += lbytes;
            bytes -= lbytes;
        }
        if (error != 0)
        {
            LOGLN0((LOG_ERROR, LOGS "process_mpeg_ts_packet "
                    "returned %d", LOGP, error));
        }
    }
    return 0;
}

/*****************************************************************************/
static int
hdhrd_get_viai_mstime(struct hdhrd_info* hdhrd, int* mstime)
{
    int lmstime;
    int lmstime1;

    if (hdhrd->video_head == NULL)
    {
        if (hdhrd->audio_head == NULL)
        {
            return 1;
        }
        else
        {
            lmstime = hdhrd->audio_head->pts - hdhrd->audio_diff;
        }
    }
    else
    {
        if (hdhrd->audio_head == NULL)
        {
            lmstime = hdhrd->video_head->pts - hdhrd->video_diff;
        }
        else
        {
            lmstime = hdhrd->audio_head->pts - hdhrd->audio_diff;
            lmstime1 = hdhrd->video_head->pts - hdhrd->video_diff;
            if (lmstime1 < lmstime)
            {
                lmstime = lmstime1;
            }
        }
    }
    *mstime = lmstime;
    return 0;
}

/*****************************************************************************/
static int
hdhrd_process_vi_ai(struct hdhrd_info* hdhrd)
{
#if 0
    int index;

    index = 0;
    while (hdhrd_process_vi(hdhrd) > 0)
    {
        LOGLN0((LOG_INFO, LOGS "processed video index %d", LOGP, index));
        index++;
    }
    index = 0;
    while (hdhrd_process_ai(hdhrd) > 0)
    {
        LOGLN0((LOG_INFO, LOGS "processed audio index %d", LOGP, index));
        index++;
    }
#else
    hdhrd_process_vi(hdhrd);
    hdhrd_process_ai(hdhrd);
#endif
    return 0;
}

/*****************************************************************************/
static int
hdhrd_cleanup(struct hdhrd_info* hdhrd)
{
    struct video_info* vi;
    struct audio_info* ai;

    while (hdhrd->video_head != NULL)
    {
        vi = hdhrd->video_head;
        hdhrd->video_head = hdhrd->video_head->next;
        free(vi->s->data);
        free(vi->s);
        free(vi);
    }
    hdhrd->video_head = NULL;
    hdhrd->video_tail = NULL;
    while (hdhrd->audio_head != NULL)
    {
        ai = hdhrd->audio_head;
        hdhrd->audio_head = hdhrd->audio_head->next;
        free(ai->s->data);
        free(ai->s);
        free(ai);
    }
    hdhrd->audio_head = NULL;
    hdhrd->audio_tail = NULL;
    if (hdhrd->ac3 != NULL)
    {
        hdhrd_ac3_delete(hdhrd->ac3);
        hdhrd->ac3 = NULL;
    }
    if (hdhrd->yami != NULL)
    {
        yami_decoder_delete(hdhrd->yami);
        hdhrd->yami = NULL;
    }
    if (hdhrd->hdhr != NULL)
    {
        hdhomerun_device_destroy(hdhrd->hdhr);
        hdhrd->hdhr = NULL;
    }
    if (hdhrd->fd > 0)
    {
        close(hdhrd->fd);
        hdhrd->fd = 0;
    }
    hdhrd->video_diff = 0;
    hdhrd->audio_diff = 0;
    return 0;
}

/*****************************************************************************/
static int
hdhrd_start(struct hdhrd_info* hdhrd, struct settings_info* settings)
{
    int error;
    const char* device_name = "1020B660-0";
    const char* channel_name;
    const char* program_name;

    if (settings->hdhrd_device_name[0] != 0)
    {
        device_name = settings->hdhrd_device_name;
    }
    hdhrd->hdhr = hdhomerun_device_create_from_str(device_name, 0);
    if (hdhrd->hdhr == NULL)
    {
        return 1;
    }
    channel_name = settings->hdhrd_channel_name;
    if (channel_name[0] != 0)
    {
        hdhomerun_device_set_tuner_channel(hdhrd->hdhr, channel_name);
    }
    program_name = settings->hdhrd_program_name;
    if (program_name[0] != 0)
    {
        hdhomerun_device_set_tuner_program(hdhrd->hdhr, program_name);
    }
    LOGLN0((LOG_INFO, LOGS "adding main pid 0x%4.4x", LOGP, 0));
    hdhrd->cb.pids[0] = 0;
    hdhrd->cb.procs[0] = tmpegts_pid0_cb;
    hdhrd->cb.num_pids = 1;
    error = hdhomerun_device_stream_start(hdhrd->hdhr);
    LOGLN0((LOG_INFO, LOGS
            "hdhomerun_device_stream_start returns %d",
            LOGP, error));
    if (error != 1)
    {
        return 2;
    }
    return 0;
}

/*****************************************************************************/
static int
hdhrd_stop(struct hdhrd_info* hdhrd)
{
    hdhrd_cleanup(hdhrd);
    LOGLN0((LOG_INFO, LOGS "hdhrd_cleanup called", LOGP));
    return 0;
}

/*****************************************************************************/
static int
hdhrd_proces_fds(struct hdhrd_info* hdhrd, struct settings_info* settings,
                 int mstime)
{
    int max_fd;
    int now;
    int rv;
    int millis;
    int error;
    int sck;
    fd_set rfds;
    fd_set wfds;
    struct timeval time;
    struct timeval* ptime;
    socklen_t sock_len;
    struct sockaddr_un s;

    rv = 0;
    for (;;)
    {
        max_fd = hdhrd->listener;
        if (g_term_pipe[0] > max_fd)
        {
            max_fd = g_term_pipe[0];
        }
        FD_ZERO(&rfds);
        FD_ZERO(&wfds);
        FD_SET(hdhrd->listener, &rfds);
        FD_SET(g_term_pipe[0], &rfds);
        if (hdhrd_peer_get_fds(hdhrd, &max_fd, &rfds, &wfds) != 0)
        {
            LOGLN0((LOG_ERROR, LOGS "hdhrd_peer_get_fds failed", LOGP));
        }
        if (mstime == -1)
        {
            ptime = NULL;
        }
        else
        {
            if (get_mstime(&now) != 0)
            {
                LOGLN0((LOG_ERROR, LOGS "get_mstime failed", LOGP));
                break;
            }
            millis = mstime - now;
            if (millis < 0)
            {
                millis = 0;
            }
            time.tv_sec = millis / 1000;
            time.tv_usec = (millis * 1000) % 1000000;
            LOGLN10((LOG_INFO, LOGS "millis %d", LOGP, millis));
            ptime = &time;
        }
        error = select(max_fd + 1, &rfds, &wfds, 0, ptime);
        if (error > 0)
        {
            if (FD_ISSET(g_term_pipe[0], &rfds))
            {
                LOGLN0((LOG_INFO, LOGS "g_term_pipe set", LOGP));
                rv = 1;
                break;
            }
            if (FD_ISSET(hdhrd->listener, &rfds))
            {
                sock_len = sizeof(struct sockaddr_un);
                sck = accept(hdhrd->listener, (struct sockaddr*)&s, &sock_len);
                LOGLN0((LOG_INFO, LOGS "got connection sck %d", LOGP, sck));
                if (sck != -1)
                {
                    if (hdhrd_peer_add_fd(hdhrd, sck) != 0)
                    {
                        LOGLN0((LOG_ERROR, LOGS "hdhrd_peer_add_fd failed",
                                LOGP));
                        close(sck);
                    }
                    else
                    {
                        if (hdhrd->is_running == 0)
                        {
                            if (hdhrd_start(hdhrd, settings) == 0)
                            {
                                hdhrd->is_running = 1;
                                break;
                            }
                            else
                            {
                                hdhrd_stop(hdhrd);
                            }
                        }
                    }
                }
            }
            error = hdhrd_peer_check_fds(hdhrd, &rfds, &wfds);
            if (error != 0)
            {
                LOGLN0((LOG_ERROR, LOGS "hdhrd_peer_check_fds rv %d",
                        LOGP, error));
                if (hdhrd->peer_head == NULL)
                {
                    if (hdhrd->is_running)
                    {
                        if (hdhrd_stop(hdhrd) == 0)
                        {
                            hdhrd->is_running = 0;
                            break;
                        }
                    }
                }
            }
        }
        if (get_mstime(&now) != 0)
        {
            LOGLN0((LOG_ERROR, LOGS "get_mstime failed", LOGP));
            break;
        }
        if (now >= mstime)
        {
            break;
        }
    }
    return rv;
}

/*****************************************************************************/
/* FD_SETSIZE */
int
main(int argc, char** argv)
{
    struct hdhrd_info* hdhrd;
    int error;
    int now;
    int hdhrd_viai_mstime;
    int hdhrd_recv_mstime;
    int hdhrd_mstime;
    struct sockaddr_un s;
    socklen_t sock_len;
    struct settings_info* settings;

    settings = (struct settings_info*)calloc(1, sizeof(struct settings_info));
    if (settings == NULL)
    {
        LOGLN0((LOG_ERROR, LOGS "calloc failed", LOGP));
        return 1;
    }
    if (process_args(argc, argv, settings) != 0)
    {
        printf_help(argc, argv);
        free(settings);
        return 0;
    }
    hdhrd = (struct hdhrd_info*)calloc(1, sizeof(struct hdhrd_info));
    if (hdhrd == NULL)
    {
        LOGLN0((LOG_ERROR, LOGS "calloc failed", LOGP));
        free(settings);
        return 1;
    }
    signal(SIGINT, sig_int);
    signal(SIGPIPE, sig_pipe);
    hdhrd->yami_fd = open("/dev/dri/renderD128", O_RDWR);
    if (hdhrd->yami_fd == -1)
    {
        LOGLN0((LOG_ERROR, LOGS "open /dev/dri/renderD128 failed", LOGP));
        free(settings);
        free(hdhrd);
        return 1;
    }
    error = yami_init(YI_TYPE_DRM, (void*)(long)(hdhrd->yami_fd));
    LOGLN0((LOG_INFO, LOGS "yami_init rv %d", LOGP, error));
    if (error != 0)
    {
        LOGLN0((LOG_ERROR, LOGS "yami_init failed %d", LOGP, error));
    }

    //snprintf(settings->hdhrd_uds, 255, HDHRD_UDS, getpid());
    snprintf(settings->hdhrd_uds, 255, HDHRD_UDS, 0);
    unlink(settings->hdhrd_uds);
    hdhrd->listener = socket(PF_LOCAL, SOCK_STREAM, 0);
    if (hdhrd->listener == -1)
    {
        LOGLN0((LOG_ERROR, LOGS "socket failed", LOGP));
        free(settings);
        free(hdhrd);
        return 1;
    }
    memset(&s, 0, sizeof(struct sockaddr_un));
    s.sun_family = AF_UNIX;
    strncpy(s.sun_path, settings->hdhrd_uds, sizeof(s.sun_path));
    s.sun_path[sizeof(s.sun_path) - 1] = 0;
    sock_len = sizeof(struct sockaddr_un);
    error = bind(hdhrd->listener, (struct sockaddr*)&s, sock_len);
    if (error != 0)
    {
        LOGLN0((LOG_ERROR, LOGS "bind failed", LOGP));
        close(hdhrd->listener);
        free(settings);
        free(hdhrd);
        return 1;
    }
    error = listen(hdhrd->listener, 2);
    if (error != 0)
    {
        LOGLN0((LOG_ERROR, LOGS "listen failed", LOGP));
        close(hdhrd->listener);
        free(settings);
        free(hdhrd);
        return 1;
    }
    error = chmod(settings->hdhrd_uds, 0777);
    if (error != 0)
    {
        LOGLN0((LOG_ERROR, LOGS "chmod failed for %s",
                LOGP, settings->hdhrd_uds));
        close(hdhrd->listener);
        free(settings);
        free(hdhrd);
        return 1;
    }
    LOGLN0((LOG_INFO, LOGS "listen ok socket %d uds %s",
            LOGP, hdhrd->listener, settings->hdhrd_uds));
    error = pipe(g_term_pipe);
    if (error != 0)
    {
        LOGLN0((LOG_ERROR, LOGS "pipe failed", LOGP));
        close(hdhrd->listener);
        free(settings);
        free(hdhrd);
        return 1;
    }
    for (;;)
    {
        if (hdhrd->is_running)
        {
            if (get_mstime(&now) != 0)
            {
                LOGLN0((LOG_ERROR, LOGS "get_mstime failed", LOGP));
                break;
            }
            hdhrd_process_vi_ai(hdhrd);
            hdhrd_process_stream_recv(hdhrd);
            hdhrd_recv_mstime = now + HDHRD_SELECT_MSTIME;
            hdhrd_mstime = hdhrd_recv_mstime;
            if (hdhrd_get_viai_mstime(hdhrd, &hdhrd_viai_mstime) == 0)
            {
                if (hdhrd_viai_mstime < hdhrd_recv_mstime)
                {
                    hdhrd_mstime = hdhrd_viai_mstime;
                }
            }
            LOGLN10((LOG_INFO, LOGS "hdhrd_mstime %d", LOGP, hdhrd_mstime));
            if (hdhrd_proces_fds(hdhrd, settings, hdhrd_mstime) != 0)
            {
                break;
            }
        }
        else
        {
            if (hdhrd_proces_fds(hdhrd, settings, -1) != 0)
            {
                break;
            }
        }
    }
    close(hdhrd->listener);
    unlink(settings->hdhrd_uds);
    mpeg_ts_cleanup(&(hdhrd->cb));
    hdhrd_peer_cleanup(hdhrd);
    hdhrd_cleanup(hdhrd);
    yami_deinit();
    close(hdhrd->yami_fd);
    free(hdhrd);
    free(settings);
    close(g_term_pipe[0]);
    close(g_term_pipe[1]);
    return 0;
}
