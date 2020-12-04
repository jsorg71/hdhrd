/**
 * xrdp: A Remote Desktop Protocol server.
 *
 * Copyright (C) Jay Sorg 2004-2020
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

#if !defined(ARCH_H)
#define ARCH_H

/* you can define L_ENDIAN or B_ENDIAN and NEED_ALIGN or NO_NEED_ALIGN
   in the makefile to override */

/* check endianness */
#if !(defined(L_ENDIAN) || defined(B_ENDIAN))
#if !defined(__BYTE_ORDER) && defined(__linux__)
#include <endian.h>
#endif

#if defined(BYTE_ORDER)
#if BYTE_ORDER == BIG_ENDIAN
#define B_ENDIAN
#else
#define L_ENDIAN
#endif
#endif

#if !(defined(L_ENDIAN) || defined(B_ENDIAN))
#if defined(__sparc__) || defined(__PPC__) || defined(__ppc__) || \
    defined(__hppa__)
#define B_ENDIAN
#else
#define L_ENDIAN
#endif
#endif
#endif

/* check if we need to align data */
#if !(defined(NEED_ALIGN) || defined(NO_NEED_ALIGN))
#if defined(__sparc__) || defined(__alpha__) || defined(__hppa__) || \
    defined(__AIX__) || defined(__PPC__) || defined(__mips__) || \
    defined(__ia64__) || defined(__ppc__) || defined(__arm__)
#define NEED_ALIGN
#elif defined(__x86__) || defined(__x86_64__) || \
      defined(__AMD64__) || defined(_M_IX86) || defined (_M_AMD64) || \
      defined(__i386__) || defined(__aarch64__)
#define NO_NEED_ALIGN
#else
#warning unknown arch
#endif
#endif
#endif
