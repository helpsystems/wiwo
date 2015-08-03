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
#              Basic example of how to use the wiwo python module.
#              Below we have an example that shows how to look for workers, set channels and monitor for frames.
#

import sys
import os
import time
import platform

import pcapy

from wiwo.manager import Manager

if platform.uname()[0].lower() == "windows":
    from wiwo.helpers import windows


class BasicExample(object):
    """
    Basic example of how to use Wiwo manager.
    """
    
    def __init__(self, iface):
        self.__iface = iface
        self.__workers_list = None
        # Create a Manager instance.
        self.__mgr = Manager(self.__iface, self._data_handler, self._event_handler)

    def stop(self):
        """
        Method that stops the Manager instance the way it should be done. This object has several python vm instances
        running simultaneous. It also stops all the workers.
        """
        self.__mgr.stop_worker_interfaces("\xff\xff\xff\xff\xff\xff")
        time.sleep(40)
        self.__mgr.stop_receiver_processes()

    def get_workers(self):
        """
        Method that gets available workers.
        """
        self.__mgr.announce_to_worker()
        time.sleep(2)
        self.__workers_list = self.__mgr.get_workers()
        print "Found %d workers." % len(self.__workers_list)

    def show_workers_information(self):
        """
        Method that prints information from the available workers.
        """
        for worker in self.__workers_list:
            print " * %s" % worker.mac_address()
            for interface in worker.interfaces_list():
                print "\t+ %s (%s) - Channel: %d - Supported Channels: %r" % (interface.name(),
                                                                              interface.protocol(),
                                                                              interface.channel(),
                                                                              interface.supported_channels())

    def set_channels(self):
        """
        Method that prints information from the available workers.
        """
        available_channels = self._get_supported_channels_set()
        for worker in self.__workers_list:
            for interface in worker.interfaces_list():
                for channel in interface.supported_channels():
                    if channel in available_channels:
                        print "Setting %s interface of worker %s to channel %d" % (interface.name(),
                                                                                   worker.mac_address(),
                                                                                   channel)
                        available_channels.discard(channel)
                        self.__mgr.set_channel_to_worker_interface(worker.raw_mac_address(),
                                                                   interface.name(),
                                                                   channel)
                        break

    def _get_supported_channels_set(self):
        """
        Method that returns a set with all supported channels for all available workers.
        """
        supported_channels = set()
        for worker in self.__workers_list:
            for interface in worker.interfaces_list():
               supported_channels.update(interface.supported_channels())
        return set(sorted(supported_channels))

    def start_workers(self, bpf_filter):
        """
        Method that starts monitoring with every available worker using a specific bpf filter.
        """
        for worker in self.__workers_list:
            for interface in worker.interfaces_list():
                self.__mgr.start_worker_interface(worker.raw_mac_address(), interface.name(), bpf_filter)

    def _event_handler(self, event):
        """
        Method that handle events from the Manager. This is a callback method.
        """
        pass
        # print "Received Event: %r" % event

    def _data_handler(self, manager, worker, frame_data):
        """
        Method that handle the data frames from the Manager. This is a callback method.
        """
        # print "Received Frame from worker %s" % worker
        # print repr(frame_data)
        print ".",


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
    Print available network interfaces on windows systems.
    """
    ifaces = windows.getNetworkInterfacesInfo()
    for iface in ifaces:
        print "\t* \Device\NPF_%s - %s" % (iface, ifaces[iface]['friendly name'])


def print_unix_network_interfaces():
    """
    Print available network interfaces on unix systems.
    """
    for iface in pcapy.findalldevs():
        print "\t* %s" % iface


def show_usage():
    """
    Print usage information.
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


if __name__ == "__main__":
    # Check root (linux) and command line arguments.
    if not initial_checks():
        sys.exit(-1)

    iface = sys.argv[1]
    
    # Check if iface_name is a valid interface name.
    if iface not in pcapy.findalldevs():
        show_usage()
        sys.exit(-1)

    basic = None
    
    try:
        basic = BasicExample(iface)
        basic.get_workers()
        basic.show_workers_information()
        basic.set_channels()
        basic.start_workers("type mgt subtype beacon")
        time.sleep(30)
    except KeyboardInterrupt:
        print " Caught CTRL+C."
    finally:
        print "Stopping..."
        if basic:
            basic.stop()
