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

#ifndef _HDHRD_ERROR_H_
#define _HDHRD_ERROR_H_

#define HDHRD_ERROR_NONE            0
#define HDHRD_ERROR_MEMORY          1
#define HDHRD_ERROR_DUP             2
#define HDHRD_ERROR_PARAM           3
#define HDHRD_ERROR_RANGE           4
#define HDHRD_ERROR_NOPTSDTS        5
#define HDHRD_ERROR_CREATE          6
#define HDHRD_ERROR_START           7
#define HDHRD_ERROR_GETTIME         8
#define HDHRD_ERROR_NOTREADY        9
#define HDHRD_ERROR_FD              10
#define HDHRD_ERROR_DECODE          11
#define HDHRD_ERROR_PEER_REMOVED    12
#define HDHRD_ERROR_LOG             13
#define HDHRD_ERROR_TERM            14
#define HDHRD_ERROR_NOT_SUPPORTED   15
#define HDHRD_ERROR_TS              16

#endif

