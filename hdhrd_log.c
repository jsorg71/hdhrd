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
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "hdhrd_utils.h"
#include "hdhrd_error.h"
#include "hdhrd_log.h"

static int g_log_level = 4;
static const char g_log_pre[][8] =
{
    "ERROR",
    "WARN",
    "INFO",
    "DEBUG"
};
static int g_log_fd = -1;
static int g_log_flags = LOG_FLAG_STDOUT;
static char g_log_filename[256];

/*****************************************************************************/
int
log_init(int flags, int log_level, const char* filename)
{
    g_log_flags = flags;
    g_log_level = log_level;
    if (flags & LOG_FLAG_FILE)
    {
        g_log_fd = open(filename,
                        O_WRONLY | O_CREAT | O_TRUNC,
                        S_IRUSR | S_IWUSR);
        if (g_log_fd == -1)
        {
            return HDHRD_ERROR_LOG;
        }
        strncpy(g_log_filename, filename, 255);
        g_log_filename[255] = 0;
    }
    return HDHRD_ERROR_NONE;
}

/*****************************************************************************/
int
log_deinit(void)
{
    if (g_log_fd != -1)
    {
        close(g_log_fd);
        unlink(g_log_filename);
    }
    return 0;
}

/*****************************************************************************/
int
logln(int log_level, const char* format, ...)
{
    va_list ap;
    char* log_line;
    int mstime;
    int len;

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
        len = snprintf(log_line + 1024, 1024, "[%10.10u][%s]%s\n",
                       mstime, g_log_pre[log_level % 4], log_line);
        if (g_log_flags & LOG_FLAG_FILE)
        {
            if (g_log_fd == -1)
            {
                return HDHRD_ERROR_LOG;
            }
            if (len != write(g_log_fd, log_line + 1024, len))
            {
                return HDHRD_ERROR_LOG;
            }
        }
        if (g_log_flags & LOG_FLAG_STDOUT)
        {
            printf("%s", log_line + 1024);
        }
        free(log_line);
    }
    return HDHRD_ERROR_NONE;
}
