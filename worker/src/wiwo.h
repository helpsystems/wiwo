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

#ifndef _WIWO_H_
#define _WIWO_H_

#define PROG_NAME "worker"
#define VERSION_MAJOR 0
#define VERSION_MINOR 1

#define MONITOR_PROG_NAME "workermon"

// Prints usage information.
void show_usage(void);

// Handles signals to exit cleanly.
void signal_handler(int);

// Initialize pcap.
int initialize_pcap(const char*);

// Craft and send WiWo ACK frame.
void send_ack(const char*, const unsigned char*);

// Craft and send WiWo INFO RESPONSE frame.
void send_info_response(const char*, const unsigned char*);

// Craft and send WiWo ERROR frame.
void send_error(const char*, const unsigned char*, const char *);

// Process WiWo SET CHANNEL frame.
int process_set_channel(const unsigned char*, const unsigned int);

// Process WiWo START frame.
int process_start(const char*, const char*, 
                  const unsigned char*, const unsigned int);

// Process WiWo DATA INJECT frame.
int process_data_inject(const unsigned char*, const unsigned int);

// Pcap Loop callback function.
void frame_handler(u_char*, const struct pcap_pkthdr*, const u_char*);

#endif /* _WIWO_H_ */
