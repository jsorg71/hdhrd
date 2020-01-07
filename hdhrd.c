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

#include <hdhomerun.h>

/*****************************************************************************/
int
main(int argc, char** argv)
{
    struct hdhomerun_device_t* hdhr;

    hdhr = hdhomerun_device_create_from_str("1020B660-0", 0);
    if (hdhr != NULL)
    {
        hdhomerun_device_destroy(hdhr);
    }
    return 0;
}
