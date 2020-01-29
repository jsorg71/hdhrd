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

static volatile int g_term = 0;

struct settings_info
{
    char hdhrd_uds[256];
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
tmpegts_video_cb(struct pid_info* pi, void* udata)
{
    int error;
    int pts;
    int dts;
    int cdata_bytes;
    int pdu_bytes;
    struct stream* s;
    struct hdhrd_info* hdhrd;

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
    LOGLN10((LOG_DEBUG, LOGS "error %d pts %10.10u dts %10.10u "
             "pdu_bytes %d", LOGP, error, pts, dts, pdu_bytes));
    if ((hdhrd->yami == NULL) && (pi->flags0 & FLAGS0_RANDOM_ACCESS))
    {
        yami_decoder_delete(hdhrd->yami);
        error = yami_decoder_create(&(hdhrd->yami), 0, 0, YI_TYPE_MPEG2, 0);
        LOGLN0((LOG_INFO, LOGS "yami_decoder_create rv %d", LOGP, error));
    }
    if (hdhrd->yami != NULL)
    {
        cdata_bytes = (int)(s->end - s->p);
        error = yami_decoder_decode(hdhrd->yami, s->p, cdata_bytes);
        LOGLN10((LOG_DEBUG, LOGS "cdata_bytes %d yami_decoder_decode "
               "rv %d", LOGP, cdata_bytes, error));
        if (error == 0)
        {
            error = yami_decoder_get_fd_dst(hdhrd->yami, 0, 0, 0, 0, 0, 0);
            LOGLN10((LOG_DEBUG, LOGS "yami_decoder_get_fd_dst rv %d",
                     LOGP, error));
            if (error == 0)
            {
            }
            else
            {
                LOGLN0((LOG_ERROR, LOGS "yami_decoder_get_fd_dst failed rv %d",
                        LOGP, error));
            }
        }
        else
        {
            LOGLN0((LOG_ERROR, LOGS "yami_decoder_decode failed rv %d",
                    LOGP, error));
        }
    }
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
    int cdata_bytes_processed;
    int decoded;
    int channels;
    int bytes;
    int pdu_bytes;
    struct stream* s;
    struct stream* out_s;
    struct hdhrd_info* hdhrd;

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
    LOGLN10((LOG_DEBUG, LOGS "error %d pts %10.10u dts %10.10u "
             "pdu_bytes %d", LOGP, error, pts, dts, pdu_bytes));
    while (s_check_rem(s, 5))
    {
        cdata_bytes = (int)(s->end - s->p);
        decoded = 0;
        error = hdhrd_ac3_decode(hdhrd->ac3, s->p, cdata_bytes,
                                 &cdata_bytes_processed, &decoded);
        LOGLN10((LOG_DEBUG, LOGS "error %d cdata_bytes %d "
                 "cdata_bytes_processed %d decoded %d",
                 LOGP, error, cdata_bytes, cdata_bytes_processed, decoded));
        if (error != 0)
        {
            LOGLN0((LOG_ERROR, LOGS "hdhrd_ac3_decode "
                    "failed %d", LOGP, error));
            break;
        }
        s->p += cdata_bytes_processed;
        if (decoded)
        {
            error = hdhrd_ac3_get_frame_info(hdhrd->ac3, &channels, &bytes);
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
                out_s->data = (char*)malloc(bytes + 1024);
                if (out_s->data != NULL)
                {
                    out_s->p = out_s->data;
                    out_uint32_le(out_s, 2);
                    out_uint32_le(out_s, 24 + bytes);
                    out_uint32_le(out_s, pts);
                    out_uint32_le(out_s, dts);
                    out_uint32_le(out_s, channels);
                    out_uint32_le(out_s, bytes);
                    error = hdhrd_ac3_get_frame_data(hdhrd->ac3, out_s->p,
                                                     bytes);
                    if (error != 0)
                    {
                        LOGLN0((LOG_ERROR, LOGS "hdhrd_ac3_get_frame_data "
                                "failed %d", LOGP, error));
                    }
                    out_s->p += bytes;
                    out_s->end = out_s->p;
                    out_s->p = out_s->data;
                    hdhrd_peer_send_all(hdhrd, out_s);
                    free(out_s->data);
                }
                free(out_s);
            }
        }
    }
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
    g_term = 1;
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
/* FD_SETSIZE */
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
    int millis;
    int max_fd;
    unsigned int start_time;
    unsigned int now;
    int diff_time;
    struct sockaddr_un s;
    socklen_t sock_len;
    fd_set rfds;
    fd_set wfds;
    struct timeval time;
    int sck;
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

    //snprintf(hdhrd_uds, 255, HDHRD_UDS, getpid());
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
    LOGLN0((LOG_INFO, LOGS "listen ok socket %d uds %s",
            LOGP, hdhrd->listener, settings->hdhrd_uds));
    hdhr = hdhomerun_device_create_from_str("1020B660-0", 0);
    if (hdhr == NULL)
    {
        LOGLN0((LOG_ERROR, LOGS "hdhomerun_device_create_from_str failed",
                LOGP));
        close(hdhrd->listener);
        free(settings);
        free(hdhrd);
        return 1;
    }
    dev_name = hdhomerun_device_get_name(hdhr);
    LOGLN0((LOG_INFO, LOGS "hdhomerun_device_get_name returns %s",
            LOGP, dev_name));
    if (settings->hdhrd_channel_name[0] != 0)
    {
        hdhomerun_device_set_tuner_channel(hdhr, settings->hdhrd_channel_name);
    }
    if (settings->hdhrd_program_name[0] != 0)
    {
        hdhomerun_device_set_tuner_program(hdhr, settings->hdhrd_program_name);
    }
    error = hdhomerun_device_stream_start(hdhr);
    LOGLN0((LOG_INFO, LOGS "hdhomerun_device_stream_start returns %d",
            LOGP, error));
    if (error == 1)
    {
        LOGLN0((LOG_INFO, LOGS "adding main pid 0x%4.4x", LOGP, 0));
        hdhrd->cb.pids[0] = 0;
        hdhrd->cb.procs[0] = tmpegts_pid0_cb;
        hdhrd->cb.num_pids = 1;
        if (hdhrd_ac3_create(&(hdhrd->ac3)) != 0)
        {
            LOGLN0((LOG_ERROR, LOGS "hdhrd_ac3_create failed", LOGP));
        }
        for (;;)
        {
            if (g_term)
            {
                LOGLN0((LOG_INFO, LOGS "g_term set", LOGP));
                break;
            }
            if (get_mstime(&start_time) != 0)
            {
                LOGLN0((LOG_ERROR, LOGS "get_mstime failed", LOGP));
                break;
            }
            bytes = HDHRD_BUFFER_SIZE;
            data = hdhomerun_device_stream_recv(hdhr, bytes, &bytes);
            LOGLN10((LOG_ERROR, LOGS "data %p HDHRD_BUFFER_SIZE %d, bytes %ld",
                     LOGP, data, HDHRD_BUFFER_SIZE, bytes));
            error = 0;
            while ((error == 0) && (bytes > 3))
            {
                if (g_term)
                {
                    LOGLN0((LOG_INFO, LOGS "g_term set", LOGP));
                    break;
                }
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
                LOGLN0((LOG_ERROR, LOGS "process_mpeg_ts_packet returned %d",
                        LOGP, error));
            }
            for (;;)
            {
                if (g_term)
                {
                    break;
                }
                if (get_mstime(&now) != 0)
                {
                    LOGLN0((LOG_ERROR, LOGS "get_mstime failed", LOGP));
                    break;
                }
                diff_time = now - start_time;
                if (diff_time >= HDHRD_SELECT_MSTIME)
                {
                    break;
                }
                max_fd = hdhrd->listener;
                FD_ZERO(&rfds);
                FD_ZERO(&wfds);
                FD_SET(hdhrd->listener, &rfds);
                if (hdhrd_peer_get_fds(hdhrd, &max_fd, &rfds, &wfds) != 0)
                {
                    LOGLN0((LOG_ERROR, LOGS "hdhrd_peer_get_fds "
                            "failed", LOGP));
                }
                millis = HDHRD_SELECT_MSTIME - diff_time;
                if (millis < 1)
                {
                    millis = 1;
                }
                LOGLN10((LOG_INFO, LOGS "millis %d", LOGP, millis));
                time.tv_sec = millis / 1000;
                time.tv_usec = (millis * 1000) % 1000000;
                error = select(max_fd + 1, &rfds, &wfds, 0, &time);
                if (error > 0)
                {
                    if (FD_ISSET(hdhrd->listener, &rfds))
                    {
                        sock_len = sizeof(struct sockaddr_un);
                        sck = accept(hdhrd->listener, (struct sockaddr*)&s,
                                     &sock_len);
                        LOGLN0((LOG_INFO, LOGS "got connection sck %d",
                                LOGP, sck));
                        if (sck != -1)
                        {
                            if (hdhrd_peer_add_fd(hdhrd, sck) != 0)
                            {
                                LOGLN0((LOG_ERROR, LOGS "hdhrd_peer_add_fd "
                                        "failed", LOGP));
                                close(sck);
                            }
                        }
                    }
                    if (hdhrd_peer_check_fds(hdhrd, &rfds, &wfds) != 0)
                    {
                        LOGLN0((LOG_ERROR, LOGS "hdhrd_peer_check_fds "
                                "failed", LOGP));
                    }
                }
            }
        }
    }
    hdhomerun_device_destroy(hdhr);
    mpeg_ts_cleanup(&(hdhrd->cb));
    close(hdhrd->listener);
    hdhrd_ac3_delete(hdhrd->ac3);
    hdhrd_peer_cleanup(hdhrd);
    free(hdhrd);
    unlink(settings->hdhrd_uds);
    free(settings);
    return 0;
}
