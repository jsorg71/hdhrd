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
#include <stdarg.h>

#include "hdhrd_utils.h"
#include "hdhrd_error.h"

static int g_log_level = 4;
static const char g_log_pre[][8] =
{
    "ERROR",
    "WARN",
    "INFO",
    "DEBUG"
};

/*****************************************************************************/
int
logln(int log_level, const char* format, ...)
{
    va_list ap;
    char* log_line;
    int mstime;

    if (log_level < g_log_level)
    {
        log_line = (char*)malloc(2048);
        if (log_line == NULL)
        {
            return HDHRD_ERROR_MEMORY;
        }
        va_start(ap, format);
        vsnprintf(log_line, 1024, format, ap);
        va_end(ap);
        get_mstime(&mstime);
        snprintf(log_line + 1024, 1024, "[%10.10u][%s]%s",
                 mstime, g_log_pre[log_level % 4], log_line);
        printf("%s\n", log_line + 1024);
        free(log_line);
    }
    return HDHRD_ERROR_NONE;
}
