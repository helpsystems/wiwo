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

#ifndef _WIRELESS_H_
#define _WIRELESS_H_

#define WIRELESS_MTU 7981

#define MODE_AUTO    "Auto"
#define MODE_ADHOC   "Ad-Hoc"
#define MODE_INFRA   "Infrastructure"
#define MODE_MASTER  "Master"
#define MODE_REPEAT  "Repeater"
#define MODE_SECOND  "Secondary"
#define MODE_MONITOR "Monitor"
#define MODE_MESH    "Mesh"

#define FREQUENCY_DELTA 5 // MHz
#define BG_BASE_FREQUENCY 2407
#define BG_LOWER_FREQUENCY 2412 // Channel 1
#define BG_UPPER_FREQUENCY 2472 // Channle 13
#define BG_CH14_FREQUENCY 2484 // Channel 14
#define A_BASE_FREQUENCY 5000
#define A_LOWER_FREQUENCY 5170 // Channel 34
#define A_UPPER_FREQUENCY 5825 // Channel 165

struct lv {
    unsigned char length;
    unsigned char value[255];
} __attribute__((packed));

// Returns wireless interface protocol name.
int get_wireless_iface_protocol(const char*, char*);
// Returns wireless interface mode.
int get_wireless_iface_mode(const char*, char*);
// Returns wireless interface frequency.
int get_wireless_iface_freq(const char*, unsigned short int*);
// Set wireless interface channel.
int set_wireless_iface_channel(const char*, const unsigned char);
// Returns wireless channels.
int get_wireless_iface_supported_channels(const char*,
                                          unsigned char*,
                                          unsigned char*);
// Returns channel from frequency.
unsigned char get_channel_from_frequency(unsigned short int);
// Returns a buffer containing information of the wireless interfaces.
int get_wireless_interfaces_information(unsigned char*,
                                        unsigned short int*);

#endif /* _WIRELESS_H_ */
