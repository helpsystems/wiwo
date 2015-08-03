#!/usr/bin/env python
#
# -*- coding: iso-8859-15 -*-
#
# Copyright 2003-2015 CORE Security Technologies
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Authors:
#          Andres Blanco (6e726d)
#          Andres Gazzoli
#
# Description:
#              Example of how to send a broadcast message to every worker. In this example we are sending the stop
#              message.
#

import sys
import platform
import os
import time
import pcapy
from wiwo.manager import Manager

if platform.uname()[0].lower() == "windows":
    from wiwo.helpers import windows


def initial_checks():
    """
    It does basic cheks before start the application.
    """
    platform_name = platform.uname()[0].lower()
    if platform_name == 'linux':
        if os.geteuid() != 0:
            print 'Error: do you have root?'
            return False
            
    if len(sys.argv) != 2:
        show_usage()
        return False

    return True
    

def print_windows_network_interfaces():
    """
    It prints available network interfaces on windows systems.
    """
    ifaces = windows.getNetworkInterfacesInfo()
    for iface in ifaces:
        print "\t* \Device\NPF_%s - %s" % (iface, ifaces[iface]['friendly name'])


def print_unix_network_interfaces():
    """
    It prints available network interfaces on unix systems.
    """
    for iface in pcapy.findalldevs():
        print "\t* %s" % iface


def show_usage():
    """
    It prints usage information.
    """
    print "Usage:"
    print " %s <network interface>\n" % sys.argv[0]
    print "Example:"
    print " %s eth0\n" % sys.argv[0]
    print "Available Interfaces:"
    if platform.uname()[0].lower() == "windows":
        print_windows_network_interfaces()
    else:
        print_unix_network_interfaces()


def stop(mgr):
    """
    It stops all the workers and the manager processes.
    """
    mgr.stop_worker_interfaces("\xff\xff\xff\xff\xff\xff")
    time.sleep(40)
    mgr.stop_receiver_processes()
    

def event_handler(event):
    """
    It handles the manager events.
    """
    pass


def data_handler(manager, worker, frame):
    """
    It handles received data frames.
    """
    pass


if __name__ == "__main__":
    # Check root (linux) and command line arguments.
    if not initial_checks():
        sys.exit(-1)
        
    iface_name = sys.argv[1]

    # Check if iface_name is a valid interface name.
    if iface_name not in pcapy.findalldevs():
        show_usage()
        sys.exit(-1)

    mgr = None
    
    try:
        mgr = Manager(iface_name, data_handler, event_handler)
        
        # Stop all the workers.
        print "Stopping all the workers using broadcast..."
        mgr.stop_worker_interfaces("\xff\xff\xff\xff\xff\xff")
        time.sleep(5)
    except KeyboardInterrupt:
        print " Caught CTRL+C."
    finally:
        print "Stopping..."
        if mgr:
            stop(mgr)
