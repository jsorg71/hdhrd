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

#ifndef _HDHRD_PEER_H_
#define _HDHRD_PEER_H_

int
hdhrd_peer_get_fds(struct hdhrd_info* hdhrd, int* max_fd,
                   fd_set* rfds, fd_set* wfds);
int
hdhrd_peer_check_fds(struct hdhrd_info* hdhrd, fd_set* rfds, fd_set* wfds);
int
hdhrd_peer_add_fd(struct hdhrd_info* hdhrd, int sck);
int
hdhrd_peer_cleanup(struct hdhrd_info* hdhrd);
int
hdhrd_peer_queue_all_video(struct hdhrd_info* hdhrd);
int
hdhrd_peer_queue_all_audio(struct hdhrd_info* hdhrd, struct stream* out_s);
int
hdhrd_peer_queue(struct peer_info* peer, struct stream* out_s);

#endif

