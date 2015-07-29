/*
 *
 * Copyright 2003-2015 CORE Security Technologies
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Authors:
 *          Andres Blanco (6e726d)
 *          Andres Gazzoli
 *
 */

#ifndef _MONITOR_H_
#define _MONITOR_H_

#define PROG_NAME "workermon"
#define VERSION_MAJOR 0
#define VERSION_MINOR 1

// Prints usage information.
void show_usage(void);

// Handles signals to exit cleanly.
void signal_handler(int);

// Craft and send WIWO DATA frame.
void send_data(const unsigned char*,
               const unsigned char*,
               const unsigned char*,
               unsigned int);

// Craft and send WIWO DATA FRAGMENT frames.
void send_fragmented_data(const unsigned char*,
                          const unsigned char*,
                          const unsigned char*,
                          unsigned int);

// Forward frames to the manager.
void frame_forwarder(u_char*, const struct pcap_pkthdr*, const u_char*);

#endif /* _MONITOR_H_ */
