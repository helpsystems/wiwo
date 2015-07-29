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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <net/if.h>

#include <pcap/pcap.h>

#include "mac.h"
#include "debug.h"
#include "system.h"
#include "monitor.h"
#include "ethernet.h"
#include "protocol.h"
#include "wireless.h"

pcap_t* src_pd = NULL;
pcap_t* dst_pd = NULL;

typedef struct
{
   char iface_name[IFNAMSIZ];
   unsigned char manager_address[MAC_ADDR_LEN];
} conf;

/*
 * Prints program usage information.
 */
void show_usage(void)
{
    fprintf(stderr, "%s %d.%d\nusage:\n\t%s <manager address> <wired interface>"
                    " <wireless interface> <filter>\n",
                    PROG_NAME, VERSION_MAJOR, VERSION_MINOR, PROG_NAME);
}

/*
 * Handles signal to exit cleanly.
 */
void signal_handler(int signal)
{
    debug_print("\nCaught terminate signal.\n");
    pcap_breakloop(src_pd);
    pcap_breakloop(dst_pd);
}

/*
 * Craft and send WIWO DATA frame.
 */
void send_data(const unsigned char* src_addr,
               const unsigned char* dst_addr,
               const unsigned char* data,
               unsigned int data_length)
{
    unsigned int offset;
    unsigned char frame_type;
    unsigned int frame_length;
    unsigned char* frame_buffer;
    unsigned short int ether_type;

    frame_length = WIWO_ETHERNET_HDR_MIN_SIZE + data_length;

    if(frame_length < ETHERNET_MIN_SIZE)
        frame_length = ETHERNET_MIN_SIZE;

    frame_buffer = (unsigned char*)malloc(frame_length);
    memset(frame_buffer, 0, frame_length);

    ether_type = WIWO_ETHERNET_TYPE;
    frame_type = TYPE_DATA;

    offset = 0;
    memcpy(frame_buffer, dst_addr, MAC_ADDR_LEN);
    offset += ETHERNET_ADDR_LEN;
    memcpy(frame_buffer + offset, src_addr, MAC_ADDR_LEN);
    offset += ETHERNET_ADDR_LEN;
    memcpy(frame_buffer + offset, &ether_type, sizeof(ether_type));
    offset += ETHERNET_TYPE_LEN;
    memcpy(frame_buffer + offset, &frame_type, sizeof(frame_type));
    offset += sizeof(frame_type);
    memcpy(frame_buffer + offset, data, data_length);

    pcap_inject(dst_pd, frame_buffer, frame_length);

    free(frame_buffer);
}

/*
 * Craft and send WIWO DATA FRAGMENT frames.
 */
void send_fragmented_data(const unsigned char* src_addr,
                          const unsigned char* dst_addr,
                          const unsigned char* data,
                          unsigned int data_length)
{
    int remaining_bytes;
    unsigned char seq_ctrl;
    unsigned char frame_type;
    unsigned char seq_number;
    unsigned short int ether_type;

    ether_type = WIWO_ETHERNET_TYPE;
    frame_type = TYPE_DATA_FRAGMENT;

    remaining_bytes = data_length;

    seq_number = 1;

    while(remaining_bytes > 0)
    {
        unsigned int offset;
        unsigned int frame_length;
        unsigned char* frame_buffer;

        seq_ctrl = seq_number & SEQUENCE_NUMBER_MASK;

        if(remaining_bytes < ETHERNET_MTU)
        {
            frame_length = WIWO_ETHERNET_HDR_FRAG_SIZE + remaining_bytes;

            if(frame_length < ETHERNET_MIN_SIZE)
                frame_length = ETHERNET_MIN_SIZE;

            seq_ctrl |= LAST_FRAGMENT_MASK;
        }
        else
        {
            frame_length = ETHERNET_MTU;
        }

        frame_buffer = (unsigned char*)malloc(frame_length);
        memset(frame_buffer, 0, frame_length);

        offset = 0;
        memcpy(frame_buffer, dst_addr, MAC_ADDR_LEN);
        offset += ETHERNET_ADDR_LEN;
        memcpy(frame_buffer + offset, src_addr, MAC_ADDR_LEN);
        offset += ETHERNET_ADDR_LEN;
        memcpy(frame_buffer + offset, &ether_type, sizeof(ether_type));
        offset += ETHERNET_TYPE_LEN;
        memcpy(frame_buffer + offset, &frame_type, sizeof(frame_type));
        offset += sizeof(frame_type);
        memcpy(frame_buffer + offset, &seq_ctrl, sizeof(seq_ctrl));
        offset += sizeof(seq_ctrl);
        memcpy(frame_buffer + offset, data,
               frame_length - WIWO_ETHERNET_HDR_FRAG_SIZE);

        pcap_inject(dst_pd, frame_buffer, frame_length);

        free(frame_buffer);

        data += frame_length - WIWO_ETHERNET_HDR_FRAG_SIZE;

        seq_number += 1;

        remaining_bytes -= frame_length - WIWO_ETHERNET_HDR_FRAG_SIZE;
    }
}

/*
 * Forward wireless frames to the manager ethernet address using the
 * wired interface.
 */
void
frame_forwarder(u_char* u, const struct pcap_pkthdr* h, const u_char* b)
{
    conf *config = (conf*)u;
    unsigned char mac_addr[MAC_ADDR_LEN];

    if(get_mac_address_from_iface(config->iface_name, mac_addr) != 0)
        return;

    if(h->caplen > ETHERNET_MTU)
    {
        send_fragmented_data(mac_addr,
                             config->manager_address,
                             b,
                             h->caplen);
        return;
    }

    send_data(mac_addr, config->manager_address, b, h->caplen);

    return;
}

int main(int argc, char** argv)
{
    conf config;
    char* filter;
    char* src_iface_name;
    char* dst_iface_name;
    char* manager_address;
    struct bpf_program fp;
    char errbuf[PCAP_ERRBUF_SIZE];
    unsigned char maddr[MAC_ADDR_LEN] = {0};

    if(argc != 5)
    {
        show_usage();
        return -1;
    }

    if(geteuid() != 0)
    {
        fprintf(stderr, "Error: do you have root?\n");
        return -1;
    }

    manager_address = argv[1];
    dst_iface_name = argv[2];
    src_iface_name = argv[3];
    filter = argv[4];

    if(is_interface_valid(src_iface_name) == false)
    {
        fprintf(stderr, "Error: %s interface not found.\n", src_iface_name);
        return -1;
    }

    if(is_interface_valid(dst_iface_name) == false)
    {
        fprintf(stderr, "Error: %s interface not found.\n", dst_iface_name);
        return -1;
    }

    memset(&config, 0x0, sizeof(config));

    signal(SIGTERM, signal_handler);
    signal(SIGINT, signal_handler);

    debug_print("Manager Ethernet Address: %s\n", manager_address);
    debug_print("Source Interface: %s\n", src_iface_name);
    debug_print("Destination Interface: %s\n", dst_iface_name);
    debug_print("Filter: '%s'\n", filter);

    dst_pd = pcap_open_live(dst_iface_name,
                            ETHERNET_MTU + ETHERNET_HDR_SIZE,
                            0,
                            100,
                            errbuf);

    src_pd = pcap_open_live(src_iface_name,
                            WIRELESS_MTU,
                            0,
                            100,
                            errbuf);

    if(pcap_compile(src_pd, &fp, filter, false, false) == -1)
    {
        fprintf(stderr, "Error: pcap_compile.");
        pcap_close(src_pd);
        pcap_close(dst_pd);
        return -1;
    }

    if(pcap_setfilter(src_pd, &fp) == -1)
    {
        fprintf(stderr, "Error: pcap_setfilter.");
        pcap_close(src_pd);
        pcap_close(dst_pd);
        return -1;
    }

    memcpy(&config.iface_name, dst_iface_name, strlen(dst_iface_name));
    get_mac_address_from_string(manager_address, maddr);
    memcpy(&config.manager_address, maddr, MAC_ADDR_LEN);

    pcap_loop(src_pd, 0, frame_forwarder, (u_char*)&config);

    debug_print("Exiting...\n");

    pcap_close(src_pd);
    pcap_close(dst_pd);

    return 0;
}
