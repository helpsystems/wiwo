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

#include <string.h>
#include <unistd.h>

#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include <pcap/pcap.h>

#include "system.h"

/*
 * Verifies if iface_name is a valid network interface using the
 * pcap_findalldevs function.
 */
bool is_interface_valid(const char* iface_name)
{
    bool result = false;
    struct pcap_if* iface;
    struct pcap_if* ifaces;
    char errbuf[PCAP_ERRBUF_SIZE];

    if(pcap_findalldevs(&ifaces, errbuf) == -1)
    {
        fprintf(stderr, "Error: pcap_findalldevs - %s.\n", errbuf);
        return -1;
    }

    for(iface = ifaces; iface; iface = iface->next)
    {
        if(strcmp(iface->name, iface_name) == 0)
            result = true;
    }

    pcap_freealldevs(ifaces);

    return result;
}

/*
 * Causes the driver for this interface to be shut down.
 */
bool interface_down(const char* iface_name)
{
    int sd;
    struct ifreq req;

    sd = socket(PF_INET, SOCK_DGRAM, 0);
    if(sd < 0)
        return false;

    memset(&req, 0, sizeof(req));

    strncpy(req.ifr_name, iface_name, strlen(iface_name));

    req.ifr_flags = IFF_BROADCAST | IFF_MULTICAST;
    if (ioctl(sd, SIOCSIFFLAGS, (char *)&req) < 0)
    {
        close(sd);
        return false;
    }

    close(sd);
    return true;
}

/*
 * Causes the interface to be activated.
 */
bool interface_up(const char* iface_name)
{
    int sd;
    struct ifreq req;

    sd = socket(PF_INET, SOCK_DGRAM, 0);
    if(sd < 0)
        return false;

    memset(&req, 0, sizeof(req));

    strncpy(req.ifr_name, iface_name, strlen(iface_name));

    req.ifr_flags = IFF_UP | IFF_RUNNING | IFF_BROADCAST | IFF_MULTICAST;
    if (ioctl(sd, SIOCSIFFLAGS, (char *)&req) < 0)
    {
        close(sd);
        return false;
    }

    close(sd);
    return true;
}
