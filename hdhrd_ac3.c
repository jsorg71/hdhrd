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
#include <stdint.h>
#include <a52dec/a52.h>

#include "hdhrd_ac3.h"
#include "hdhrd_error.h"

static const int g_ac3_channels[8] = { 2, 1, 2, 3, 3, 4, 4, 5 };

struct mycodec_audio
{
    a52_state_t* state;
    sample_t* samples;
    int frame_size;
    int flags;
    int sample_rate;
    int channels;
    int bit_rate;
    int cdata_bytes;;
    uint8_t* cdata;
};

/*****************************************************************************/
int
hdhrd_ac3_create(void** obj)
{
    struct mycodec_audio* self;

    if (obj == NULL)
    {
        return HDHRD_ERROR_PARAM;
    }
    self = (struct mycodec_audio*)calloc(sizeof(struct mycodec_audio), 1);
    if (self == NULL)
    {
        return HDHRD_ERROR_MEMORY;
    }
    self->state = a52_init(0);
    if (self->state == NULL)
    {
        free(self);
        return HDHRD_ERROR_START;
    }
    self->samples = a52_samples(self->state);
    if (self->samples == NULL)
    {
        a52_free(self->state);
        free(self);
        return HDHRD_ERROR_START;
    }
    *obj = self;
    return HDHRD_ERROR_NONE;
}

/*****************************************************************************/
int
hdhrd_ac3_delete(void* obj)
{
    struct mycodec_audio* self;

    if (obj == NULL)
    {
        return HDHRD_ERROR_NONE;
    }
    self = (struct mycodec_audio*)obj;
    a52_free(self->state);
    free(self->cdata);
    free(self);
    return HDHRD_ERROR_NONE;
}

/**** the following two functions comes from a52dec */
/*****************************************************************************/
static int
blah(int32_t i)
{
    if (i > 0x43c07fff)
    {
        return 32767;
    }
    else if (i < 0x43bf8000)
    {
        return -32768;
    }
    return i - 0x43c00000;
}

/*****************************************************************************/
static void
float_to_short(float* in_float, int16_t* out_i16, int nchannels)
{
    int i;
    int j;
    int c;
    int32_t* f;

    f = (int32_t*)in_float;     /* XXX assumes IEEE float format */
    j = 0;
    nchannels *= 256;
    for (i = 0; i < 256; i++)
    {
        for (c = 0; c < nchannels; c += 256)
        {
            out_i16[j++] = blah(f[i + c]);
        }
    }
}

/*****************************************************************************/
int
hdhrd_ac3_decode(void* obj, void* cdata, int cdata_bytes,
                 int* cdata_bytes_processed, int* decoded)
{
    struct mycodec_audio* self;
    int flags;
    int sample_rate;
    int bit_rate;
    int len;
    float level;

    *decoded = 0;
    *cdata_bytes_processed = 0;
    self = (struct mycodec_audio*)obj;
    if (self->frame_size == 0)
    {
        if (cdata_bytes >= 7)
        {
            /* lookign for header */
            flags = 0;
            sample_rate = 0;
            bit_rate = 0;
            len = a52_syncinfo((uint8_t*)cdata, &flags,
                               &sample_rate, &bit_rate);
            if (len == 0)
            {
                return HDHRD_ERROR_START;
            }
            else
            {
                self->flags = flags;
                self->frame_size = len;
                self->sample_rate = sample_rate;
                self->channels = g_ac3_channels[self->flags & 7];
                if (self->flags & A52_LFE)
                {
                    self->channels++;
                }
                self->bit_rate = bit_rate;
                self->cdata = (uint8_t*)malloc(1024 * 1024);
                if (self->cdata == NULL)
                {
                    return HDHRD_ERROR_MEMORY;
                }
                self->cdata_bytes = 0;
                return HDHRD_ERROR_NONE;
            }
        }
        return 3;
    }
    len = self->frame_size - self->cdata_bytes;
    if (len > cdata_bytes)
    {
        len = cdata_bytes;
    }
    if (len < 1)
    {
        return HDHRD_ERROR_PARAM;
    }
    memcpy(self->cdata + self->cdata_bytes, cdata, len);
    self->cdata_bytes += len;
    *cdata_bytes_processed = len;
    if (self->cdata_bytes >= self->frame_size)
    {
        self->cdata_bytes = 0;
        flags = self->flags;
        if (self->channels == 1)
        {
            flags = A52_MONO;
        }
        else if (self->channels == 2)
        {
            flags = A52_STEREO;
        }
        else
        {
            flags |= A52_ADJUST_LEVEL;
        }
        level = 1;
        if (a52_frame(self->state, self->cdata, &flags, &level, 384))
        {
            return HDHRD_ERROR_DECODE;
        }
        *decoded = 1;
    }
    return HDHRD_ERROR_NONE;
}

/*****************************************************************************/
int
hdhrd_ac3_get_frame_info(void* obj, int* channels, int* bytes)
{
    struct mycodec_audio* self;

    self = (struct mycodec_audio*)obj;
    *channels = self->channels;
    *bytes = 6 * 256 * self->channels * 2;
    return HDHRD_ERROR_NONE;
}

/*****************************************************************************/
int
hdhrd_ac3_get_frame_data(void* obj, void* data, int data_bytes)
{
    struct mycodec_audio* self;
    int index;
    short* out_samples;

    self = (struct mycodec_audio*)obj;
    if (data_bytes < 6 * 256 * self->channels * 2)
    {
        return HDHRD_ERROR_PARAM;
    }
    out_samples = (short*)data;
    for (index = 0; index < 6; index++)
    {
        if (a52_block(self->state) != 0)
        {
            return HDHRD_ERROR_DECODE;
        }
        float_to_short(self->samples,
                       out_samples + index * 256 * self->channels,
                       self->channels);
    }
    return HDHRD_ERROR_NONE;
}

