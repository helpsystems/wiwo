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
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>

#include <net/if.h>
#include <signal.h>
#include <pcap/pcap.h>
#include <netinet/in.h>

#include "mac.h"
#include "wiwo.h"
#include "debug.h"
#include "system.h"
#include "network.h"
#include "ethernet.h"
#include "protocol.h"
#include "wireless.h"

pcap_t* pd = NULL;

/*
 * Prints program usage information.
 */
void show_usage(void)
{
    fprintf(stderr, "%s %d.%d\nusage:\n\t%s <interface>\n",
            PROG_NAME, VERSION_MAJOR, VERSION_MINOR, PROG_NAME);
}

/*
 * Handles signal to exit cleanly.
 */
void signal_handler(int signal)
{
    debug_print("\nCaught terminate signal.\n");
    pcap_breakloop(pd);
}

/*
 * Initialize pcap.
 */
int initialize_pcap(const char* iface_name)
{
    char* filter_exp;
    char* mac_addr_s;
    struct bpf_program fp;
    char errbuf[PCAP_ERRBUF_SIZE];
    
    pd = pcap_open_live(iface_name,
                        ETHERNET_MTU + ETHERNET_HDR_SIZE,
                        1,
                        0,
                        errbuf);
    if(pd == NULL)
        return -1;

    if(pcap_datalink(pd) != LINKTYPE_ETHERNET)
    {
        pcap_close(pd);
        return -1;
    }

    filter_exp = (char*)malloc(BPF_FILTER_SIZE);
    memset(filter_exp, 0, BPF_FILTER_SIZE);

    mac_addr_s = (char*)malloc(ETHERNET_STR_ADDR_LEN);
    memset(mac_addr_s, 0, ETHERNET_STR_ADDR_LEN);

    if(get_string_mac_address_for_iface(iface_name, mac_addr_s) == -1)
        return -1;

    sprintf(filter_exp,
            "(ether dst %s or broadcast) and ether proto 0x%04X",
            mac_addr_s,
            WIWO_ETHERNET_TYPE);

    free(mac_addr_s);

    debug_print("BPF Filter: %s\n", filter_exp);

    if(pcap_compile(pd, &fp, filter_exp, false, false) == -1)
    {
        free(filter_exp);
        pcap_close(pd);
        return -1;
    }

    free(filter_exp);

    if(pcap_setfilter(pd, &fp) == -1)
    {
        pcap_close(pd);
        return -1;
    }

    return 0;
}

/*
 * Craft and send WiWo ACK frame.
 */
void send_ack(const char* iface_name, const unsigned char* dst_addr)
{
    unsigned int offset;
    unsigned char* buffer;
    unsigned char frame_type;
    unsigned short int ether_type;
    unsigned char mac_addr[ETHERNET_ADDR_LEN];

    ether_type = WIWO_ETHERNET_TYPE;
    frame_type = TYPE_ACK;

    buffer = (unsigned char*)malloc(ETHERNET_MIN_SIZE);
    memset(buffer, 0, ETHERNET_MIN_SIZE);

    if(get_mac_address_from_iface(iface_name, mac_addr) != 0)
        return;

    offset = 0;
    memcpy(buffer, dst_addr, ETHERNET_ADDR_LEN);
    offset += ETHERNET_ADDR_LEN;
    memcpy(buffer + offset, mac_addr, ETHERNET_ADDR_LEN);
    offset += ETHERNET_ADDR_LEN;
    memcpy(buffer + offset, &ether_type, sizeof(ether_type));
    offset += ETHERNET_TYPE_LEN;
    memcpy(buffer + offset, &frame_type, sizeof(frame_type));

    pcap_inject(pd, buffer, ETHERNET_MIN_SIZE);

    free(buffer);
}

/*
 * Craft and send WiWo INFO_RESPONSE frame.
 */
void
send_info_response(const char* iface_name,
                   const unsigned char* dst_addr)
{
    unsigned int offset;
    unsigned char* info;
    unsigned char* buffer;
    unsigned char frame_type;
    unsigned int frame_length;
    unsigned short int ether_type;
    unsigned short int info_length;
    unsigned char mac_addr[ETHERNET_ADDR_LEN];

    ether_type = WIWO_ETHERNET_TYPE;
    frame_type = TYPE_INFO_RESPONSE;

    info = (unsigned char*)malloc(ETHERNET_MTU);
    get_wireless_interfaces_information(info, &info_length);

    if(WIWO_ETHERNET_HDR_MIN_SIZE + info_length < ETHERNET_MIN_SIZE)
        frame_length = ETHERNET_MIN_SIZE;
    else
        frame_length = WIWO_ETHERNET_HDR_MIN_SIZE + info_length;

    buffer = (unsigned char*)malloc(frame_length);
    memset(buffer, 0, frame_length);

    if(get_mac_address_from_iface(iface_name, mac_addr) != 0)
        return;

    offset = 0;
    memcpy(buffer, dst_addr, ETHERNET_ADDR_LEN);
    offset += ETHERNET_ADDR_LEN;
    memcpy(buffer + offset, mac_addr, ETHERNET_ADDR_LEN);
    offset += ETHERNET_ADDR_LEN;
    memcpy(buffer + offset, &ether_type, sizeof(ether_type));
    offset += ETHERNET_TYPE_LEN;
    memcpy(buffer + offset, &frame_type, sizeof(frame_type));
    offset += sizeof(frame_type);
    memcpy(buffer + offset, info, info_length);
    free(info);

    pcap_inject(pd, buffer, frame_length);

    free(buffer);
}

/*
 * Craft and send WiWo ERROR frame.
 */
void send_error(const char* iface_name,
                const unsigned char* dst_addr,
                const char* error_msg)
{
    unsigned int offset;
    unsigned char* buffer;
    unsigned int msg_length;
    unsigned char frame_type;
    unsigned int frame_length;
    unsigned short int ether_type;
    unsigned char mac_addr[ETHERNET_ADDR_LEN];

    ether_type = WIWO_ETHERNET_TYPE;
    frame_type = TYPE_ERROR;

    msg_length = strlen(error_msg);
    frame_length = WIWO_ETHERNET_HDR_MIN_SIZE + msg_length;

    buffer = (unsigned char*)malloc(frame_length);
    memset(buffer, 0, frame_length);

    if(get_mac_address_from_iface(iface_name, mac_addr) != 0)
        return;

    offset = 0;
    memcpy(buffer, dst_addr, ETHERNET_ADDR_LEN);
    offset += ETHERNET_ADDR_LEN;
    memcpy(buffer + offset, mac_addr, ETHERNET_ADDR_LEN);
    offset += ETHERNET_ADDR_LEN;
    memcpy(buffer + offset, &ether_type, sizeof(ether_type));
    offset += ETHERNET_TYPE_LEN;
    memcpy(buffer + offset, &frame_type, sizeof(frame_type));
    offset += sizeof(frame_type);
    memcpy(buffer + offset, error_msg, msg_length);

    pcap_inject(pd, buffer, frame_length);

    free(buffer);
}

/*
 * Process SET CHANNEL frame.
 */
int process_set_channel(const unsigned char* buffer,
                        const unsigned int buffer_size)
{
    unsigned int channel;
    unsigned char iface_name_len;
    char iface_name[IFNAMSIZ] = {0};

    if(buffer_size < 2)
        return -1;

    iface_name_len = *buffer;

    if(buffer_size < iface_name_len + 2)
        return -1;

    memcpy(&iface_name, buffer+1, iface_name_len);

    channel = *(buffer+iface_name_len+1);

    return set_wireless_iface_channel(iface_name, channel);
}

/*
 * Process START frame.
 */
int process_start(const char* iface_name,
                  const char* mgr_addr,
                  const unsigned char* buffer,
                  const unsigned int buffer_len)
{
    unsigned short offset = 0;

    char* bpf_filter;
    unsigned short int bpf_filter_len = 0;

    char wiface_name[IFNAMSIZ] = {0};
    unsigned char wiface_name_len = 0;

    pid_t pid;

    if(buffer_len < 2)
        return -1;

    wiface_name_len = *buffer;

    offset += sizeof(wiface_name_len);

    if(buffer_len < wiface_name_len + offset)
        return -1;

    memcpy(&wiface_name, buffer + offset, wiface_name_len);

    offset += wiface_name_len;

    memcpy(&bpf_filter_len, buffer + offset, sizeof(bpf_filter_len));
    bpf_filter_len = ntohs(bpf_filter_len);

    offset += sizeof(bpf_filter_len);

    if(buffer_len < bpf_filter_len + offset)
        return -1;

    bpf_filter = (char*)malloc(bpf_filter_len + 1);
    if(bpf_filter == NULL)
        return -1;

    memset(bpf_filter, 0, bpf_filter_len + 1);

    memcpy(bpf_filter, buffer + offset, bpf_filter_len);

    pid = fork();

    if(pid == 0)
    {
        execl("/bin/workermon", MONITOR_PROG_NAME, mgr_addr,
              iface_name, wiface_name, bpf_filter, NULL);
        fprintf(stderr, "Error: execl failed.\n");
        exit(-1);
    }
    else if(pid != -1)
    {
        fprintf(stderr, " - Started monitor on pid %d.\n", pid);
    }
    else
    {
        fprintf(stderr, "Error: unable to fork.\n");
    }

    free(bpf_filter);

    return 0;
}

/*
 * Process DATA INJECT frame.
 */
int process_data_inject(const unsigned char* buffer,
                        const unsigned int buffer_size)
{
    pcap_t* ipd = NULL;
    unsigned char* frame_buffer;
    unsigned char iface_name_len;
    char errbuf[PCAP_ERRBUF_SIZE];
    char iface_name[IFNAMSIZ] = {0};
    unsigned int frame_buffer_length;

    if(buffer_size < 2)
        return -1;

    iface_name_len = *buffer;

    if(buffer_size < iface_name_len + 2)
        return -1;

    memcpy(&iface_name, buffer+1, iface_name_len);

    if(is_interface_valid(iface_name) == false)
        return -1;

    frame_buffer_length = buffer_size - (iface_name_len + 1);

    frame_buffer = (unsigned char*)malloc(frame_buffer_length);

    memcpy(frame_buffer, buffer+iface_name_len+1, frame_buffer_length);

    ipd = pcap_open_live(iface_name,
                         WIRELESS_MTU,
                         0,
                         0,
                         errbuf);

    pcap_inject(ipd, frame_buffer, frame_buffer_length);

    free(frame_buffer);

    pcap_close(ipd);
    return 0;
}

/*
 * Pcap loop callback function.
 */
void
frame_handler(u_char* u, const struct pcap_pkthdr* h, const u_char* b)
{
    char* mac_addr_s;
    unsigned char frame_type;
    struct ethernet_header *ether_hdr;

    if(h->caplen < WIWO_ETHERNET_HDR_MIN_SIZE)
        return;

    ether_hdr = (struct ethernet_header*)b;

    mac_addr_s = (char*)malloc(ETHERNET_STR_ADDR_LEN);

    if(get_string_mac_address((unsigned char*)ether_hdr->destination,
                               mac_addr_s) != 0)
        return;

    if(get_string_mac_address((unsigned char*)ether_hdr->source,
                               mac_addr_s) != 0)
        return;

    frame_type = (unsigned char)*(b + ETHERNET_HDR_SIZE);

    debug_print("--------------------------------------------------\n");
    debug_print("Frame Received:\n");
    debug_print(" - Frame Length: %u\n", h->len);
    debug_print(" - Capture Length: %u\n", h->caplen);
    debug_print(" - Destination: %s\n", mac_addr_s);
    debug_print(" - Source: %s\n", mac_addr_s);
    debug_print(" - Ether Type: %02X\n", ether_hdr->type);
    debug_print(" - Frame Type: %01X ", (unsigned int)frame_type);

    switch(frame_type)
    {
        case TYPE_ACK:
            debug_print(" [ACK]\n");
            debug_print("  Workers shouldn't recv this message.\n");
            break;
        case TYPE_ANNOUNCE:
            debug_print(" [ANNOUNCE]\n");
            send_ack((char*)u, ether_hdr->source);
            break;
        case TYPE_INFO_REQUEST:
            debug_print(" [INFO_REQUEST]\n");
            send_info_response((char*)u, ether_hdr->source);
            break;
        case TYPE_INFO_RESPONSE:
            debug_print(" [INFO_RESPONSE]\n");
            debug_print("  Workers shouldn't recv this message.\n");
            break;
        case TYPE_SET_CHANNEL:
            debug_print(" [SET_CHANNEL]\n");
            if(process_set_channel(b + WIWO_ETHERNET_HDR_MIN_SIZE,
                    h->caplen - WIWO_ETHERNET_HDR_MIN_SIZE) == -1)
            {
                debug_print("ERROR: Unable to set channel.\n");
                send_error((char*)u,
                           ether_hdr->source,
                           "Unable to set channel.");
            }
            else
                send_ack((char*)u, ether_hdr->source);
            break;
        case TYPE_START:
            debug_print(" [START]\n");
            if(process_start((char*)u,
                    mac_addr_s,
                    b + WIWO_ETHERNET_HDR_MIN_SIZE,
                    h->caplen - WIWO_ETHERNET_HDR_MIN_SIZE) == -1)
            {
                debug_print("ERROR: Unable to start.\n");
                send_error((char*)u,
                           ether_hdr->source,
                           "Unable to start.");
            }
            else
                send_ack((char*)u, ether_hdr->source);
            break;
        case TYPE_STOP:
            debug_print(" [STOP]\n");
            system("killall -9 workermon");
            send_ack((char*)u, ether_hdr->source);
            break;
        case TYPE_DATA_INJECT:
            debug_print(" [DATA_INJECT]\n");
            if(process_data_inject(b + WIWO_ETHERNET_HDR_MIN_SIZE,
                    h->caplen - WIWO_ETHERNET_HDR_MIN_SIZE) == -1)
            {
                debug_print("ERROR: Unable to inject frame.\n");
                send_error((char*)u,
                           ether_hdr->source,
                           "Unable to inject frame.");
            }
            else
                send_ack((char*)u, ether_hdr->source);
            break;
        case TYPE_ERROR:
            debug_print(" [ERROR]\n");
            debug_print("  Workers shouldn't recv this message.\n");
            break;
        default:
            debug_print("\n");
            break;
    }

    free(mac_addr_s);
}

int main(int argc, char** argv)
{
    char* iface_name;
    char* mac_addr_s;

    if(argc < 2)
    {
        show_usage();
        return -1;
    }

    if(geteuid() != 0)
    {
        fprintf(stderr, "Error: do you have root?\n");
        return -1;
    }

    iface_name = argv[1];

    if(is_interface_valid(iface_name) == false)
    {
        fprintf(stderr, "Error: %s interface not found.\n", iface_name);
        return -1;
    }

    signal(SIGTERM, signal_handler);
    signal(SIGINT, signal_handler);

    mac_addr_s = (char*)malloc(ETHERNET_STR_ADDR_LEN);
    if(get_string_mac_address_for_iface(iface_name, mac_addr_s) != 0)
    {
        fprintf(stderr, "Error: unable to get MAC address.\n");
        return -1;
    }

    debug_print("Interface: %s\n", iface_name);
    debug_print("MAC Address: %s\n", mac_addr_s);

    free(mac_addr_s);

    if(initialize_pcap(iface_name) != 0)
    {
        fprintf(stderr, "Error: initializing pcap.\n");
        return -1;
    }

    pcap_loop(pd, 0, frame_handler, (unsigned char*)iface_name);

    debug_print("Exiting...\n");

    pcap_close(pd);

    return 0;
}
