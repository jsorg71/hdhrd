/**
 * xrdp: A Remote Desktop Protocol server.
 *
 * Copyright (C) Jay Sorg 2004-2014
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
 *
 * Parsing structs and macros
 *
 * based on parse.h from rdesktop
 * this is a super fast stream method, you bet
 * needed functions g_malloc, g_free, g_memset, g_memcpy
 */

#if !defined(PARSE_H)
#define PARSE_H

#include "arch.h"

#if defined(L_ENDIAN)
#elif defined(B_ENDIAN)
#else
#error Unknown endianness.
#endif

/* parser state */
struct stream
{
    char *p;
    char *data;
    char *end;
    int size;
    int fd;
    struct stream* next;
};

/******************************************************************************/
#define s_check_rem(s, n) ((s)->p + (n) <= (s)->end)

/******************************************************************************/
#define s_check_rem_out(s, n) ((s)->p + (n) <= (s)->data + (s)->size)

/******************************************************************************/
#define in_uint8(s, v) do \
{ \
    (v) = *((unsigned char*)((s)->p)); \
    (s)->p++; \
} while (0)

/******************************************************************************/
#if defined(B_ENDIAN) || defined(NEED_ALIGN)
#define in_sint16_le(s, v) do \
{ \
    (v) = (signed short) \
        ( \
            (*((unsigned char*)((s)->p + 0)) << 0) | \
            (*((unsigned char*)((s)->p + 1)) << 8) \
        ); \
    (s)->p += 2; \
} while (0)
#else
#define in_sint16_le(s, v) do \
{ \
    (v) = *((signed short*)((s)->p)); \
    (s)->p += 2; \
} while (0)
#endif

/******************************************************************************/
#if defined(B_ENDIAN) || defined(NEED_ALIGN)
#define in_uint16_le(s, v) do \
{ \
    (v) = (unsigned short) \
        ( \
            (*((unsigned char*)((s)->p + 0)) << 0) | \
            (*((unsigned char*)((s)->p + 1)) << 8) \
        ); \
    (s)->p += 2; \
} while (0)
#else
#define in_uint16_le(s, v) do \
{ \
    (v) = *((unsigned short*)((s)->p)); \
    (s)->p += 2; \
} while (0)
#endif

/******************************************************************************/
#define in_uint16_be(s, v) do \
{ \
    (v) = *((unsigned char*)((s)->p)); \
    (s)->p++; \
    (v) <<= 8; \
    (v) |= *((unsigned char*)((s)->p)); \
    (s)->p++; \
} while (0)

/******************************************************************************/
#if defined(B_ENDIAN) || defined(NEED_ALIGN)
#define in_uint32_le(s, v) do \
{ \
    (v) = (unsigned int) \
        ( \
            (*((unsigned char*)((s)->p + 0)) << 0) | \
            (*((unsigned char*)((s)->p + 1)) << 8) | \
            (*((unsigned char*)((s)->p + 2)) << 16) | \
            (*((unsigned char*)((s)->p + 3)) << 24) \
        ); \
    (s)->p += 4; \
} while (0)
#else
#define in_uint32_le(s, v) do \
{ \
    (v) = *((unsigned int*)((s)->p)); \
    (s)->p += 4; \
} while (0)
#endif

/******************************************************************************/
#if defined(B_ENDIAN) || defined(NEED_ALIGN)
#define in_uint64_le(s, v) do \
{ \
    (v) = (long long) \
        ( \
            (((long long)(*((unsigned char*)((s)->p + 0)))) << 0) | \
            (((long long)(*((unsigned char*)((s)->p + 1)))) << 8) | \
            (((long long)(*((unsigned char*)((s)->p + 2)))) << 16) | \
            (((long long)(*((unsigned char*)((s)->p + 3)))) << 24) | \
            (((long long)(*((unsigned char*)((s)->p + 4)))) << 32) | \
            (((long long)(*((unsigned char*)((s)->p + 5)))) << 40) | \
            (((long long)(*((unsigned char*)((s)->p + 6)))) << 48) | \
            (((long long)(*((unsigned char*)((s)->p + 7)))) << 56) \
        ); \
    (s)->p += 8; \
} while (0)
#else
#define in_uint64_le(s, v) do \
{ \
    (v) = *((long long*)((s)->p)); \
    (s)->p += 8; \
} while (0)
#endif

/******************************************************************************/
#define in_uint32_be(s, v) do \
{ \
    (v) = *((unsigned char*)((s)->p)); \
    (s)->p++; \
    (v) <<= 8; \
    (v) |= *((unsigned char*)((s)->p)); \
    (s)->p++; \
    (v) <<= 8; \
    (v) |= *((unsigned char*)((s)->p)); \
    (s)->p++; \
    (v) <<= 8; \
    (v) |= *((unsigned char*)((s)->p)); \
    (s)->p++; \
} while (0)

/******************************************************************************/
#define out_uint8(s, v) do \
{ \
  *((s)->p) = (unsigned char)(v); \
  (s)->p++; \
} while (0)

/******************************************************************************/
#if defined(B_ENDIAN) || defined(NEED_ALIGN)
#define out_uint16_le(s, v) do \
{ \
    *((s)->p) = (unsigned char)((v) >> 0); \
    (s)->p++; \
    *((s)->p) = (unsigned char)((v) >> 8); \
    (s)->p++; \
} while (0)
#else
#define out_uint16_le(s, v) do \
{ \
    *((unsigned short*)((s)->p)) = (unsigned short)(v); \
    (s)->p += 2; \
} while (0)
#endif

/******************************************************************************/
#define out_uint16_be(s, v) do \
{ \
    *((s)->p) = (unsigned char)((v) >> 8); \
    (s)->p++; \
    *((s)->p) = (unsigned char)((v) >> 0); \
    (s)->p++; \
} while (0)

/******************************************************************************/
#if defined(B_ENDIAN) || defined(NEED_ALIGN)
#define out_uint32_le(s, v) do \
{ \
    *((s)->p) = (unsigned char)((v) >> 0); \
    (s)->p++; \
    *((s)->p) = (unsigned char)((v) >> 8); \
    (s)->p++; \
    *((s)->p) = (unsigned char)((v) >> 16); \
    (s)->p++; \
    *((s)->p) = (unsigned char)((v) >> 24); \
    (s)->p++; \
} while (0)
#else
#define out_uint32_le(s, v) do \
{ \
    *((unsigned int*)((s)->p)) = (v); \
    (s)->p += 4; \
} while (0)
#endif

/******************************************************************************/
#if defined(B_ENDIAN) || defined(NEED_ALIGN)
#define out_uint64_le(s, v) do \
{ \
    *((s)->p) = (unsigned char)((v) >> 0); \
    (s)->p++; \
    *((s)->p) = (unsigned char)((v) >> 8); \
    (s)->p++; \
    *((s)->p) = (unsigned char)((v) >> 16); \
    (s)->p++; \
    *((s)->p) = (unsigned char)((v) >> 24); \
    (s)->p++; \
    *((s)->p) = (unsigned char)((v) >> 32); \
    (s)->p++; \
    *((s)->p) = (unsigned char)((v) >> 40); \
    (s)->p++; \
    *((s)->p) = (unsigned char)((v) >> 48); \
    (s)->p++; \
    *((s)->p) = (unsigned char)((v) >> 56); \
    (s)->p++; \
} while (0)
#else
#define out_uint64_le(s, v) do \
{ \
    *((long long*)((s)->p)) = (v); \
    (s)->p += 8; \
} while (0)
#endif

/******************************************************************************/
#define out_uint32_be(s, v) do \
{ \
    *((s)->p) = (unsigned char)((v) >> 24); \
    s->p++; \
    *((s)->p) = (unsigned char)((v) >> 16); \
    s->p++; \
    *((s)->p) = (unsigned char)((v) >> 8); \
    s->p++; \
    *((s)->p) = (unsigned char)(v); \
    (s)->p++; \
} while (0)

/******************************************************************************/
#define in_uint8p(s, v, n) do \
{ \
    (v) = (s)->p; \
    (s)->p += (n); \
} while (0)

/******************************************************************************/
#define in_uint8a(s, v, n) do \
{ \
    memcpy((v), (s)->p, (n)); \
    (s)->p += (n); \
} while (0)

/******************************************************************************/
#define in_uint8s(s, n) \
    (s)->p += (n)

/******************************************************************************/
#define out_uint8p(s, v, n) do \
{ \
    memcpy((s)->p, (v), (n)); \
    (s)->p += (n); \
} while (0)

/******************************************************************************/
#define out_uint8a(s, v, n) \
    out_uint8p((s), (v), (n))

/******************************************************************************/
#define out_uint8s(s, n) do \
{ \
    memset((s)->p, 0, (n)); \
    (s)->p += (n); \
} while (0)

#endif
