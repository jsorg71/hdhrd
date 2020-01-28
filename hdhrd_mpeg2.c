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

#include <mpeg2dec/mpeg2.h>

/*****************************************************************************/
int
hdhrd_mpeg2_create(void** obj)
{

}

/*****************************************************************************/
int
hdhrd_mpeg2_delete(void* obj)
{
}

/*****************************************************************************/
int
hdhrd_mpeg2_decode(void* obj, void* cdata, int cdata_bytes,
                   int* cdata_bytes_processed, int* decoded)
{
}

/*****************************************************************************/
int
hdhrd_mpeg2_get_frame_info(void* obj, int* width, int* height,
                           int* format, int* bytes)
{
}

/*****************************************************************************/
int
hdhrd_mpeg2_get_frame_data(void* obj, void* data, int data_bytes)
{
}

