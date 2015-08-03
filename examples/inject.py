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

import os
import sys
import time
import struct
import platform

import pcapy
from impacket import dot11
from impacket.ImpactDecoder import RadioTapDecoder

from wiwo.manager import Manager

if platform.uname()[0].lower() == "windows":
    from wiwo.helpers import windows


class NoWorkersException(Exception):
    pass


class Injector(object):
    """
    Represents a class that process dns queries and send fake dns responses.
    """

    MTU = 7981
    TIMEOUT = 100  # in milliseconds

    def __init__(self, iface_name):
        self.__iface_name = iface_name
        self.__bpf_filter = "type mgt subtype probe-req"
        print "Starting wiwo manager..."
        self.__mgr = Manager(self.__iface_name, self.frame_handler, self.event_handler)
        self.__look_for_workers()
        if len(self.__workers_list) == 0:
           raise NoWorkersException
        self.__assign_channels()
        self.__start_workers_interfaces()

    def __look_for_workers(self):
        """
        It looks for available workers.
        """
        print "Looking for workers..."
        self.__mgr.announce_to_worker()
        time.sleep(10)  # Require to receive the list of workers. This should be fix on the manager code.
        self.__workers_list = self.__mgr.get_workers()
        print "Found %d workers." % len(self.__workers_list)

    def __assign_channels(self):
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

    def __start_workers_interfaces(self):
        """
        Method that stops monitoring on every available worker.
        """
        for worker in self.__workers_list:
            for interface in worker.interfaces_list():
                self.__mgr.start_worker_interface(worker.raw_mac_address(), interface.name(), self.__bpf_filter)

    def __stop_workers(self):
        """
        It stops monitoring wireless traffic on every interface of all the workers.
        """
        for worker in self.__workers_list:
            self.__mgr.stop_worker_interfaces(worker.raw_mac_address())

    def stop(self):
        """
        Stop workers and manager.
        """
        self.__stop_workers()
        time.sleep(30)  # Wait for 30 seconds until all workers have stopped.
        self.__mgr.stop_receiver_processes()

    def frame_handler(self, manager, worker_addr, frame_data):
        """
        Inject probe response frames for every probe request frame.
        """
        decoder = RadioTapDecoder()
        decoder.decode(frame_data)

        management_frame = decoder.get_protocol(dot11.Dot11ManagementFrame)
        probe_req_frame = decoder.get_protocol(dot11.Dot11ManagementProbeRequest)

        if not probe_req_frame:
            return

        ssid = probe_req_frame.get_ssid()
        if not ssid:  # Ignore broadcast SSID
            return

        station_address = management_frame.get_source_address()
        print "Station: %s" % ":".join(map(lambda i: "%02X" % i, station_address))
        print "SSID: %s" % ssid

        frame = str()
        # Radiotap
        frame += "\x00\x00"  # Version
        frame += "\x0b\x00"  # Header Length
        frame += "\x04\x0c\x00\x00"  # Presence Flags
        frame += "\x6c"  # Rate
        frame += "\x0c"  # TX Power
        frame += "\x01"  # Antenna
        # Management Frame
        frame += "\x50\x00"  # Frame Control
        frame += "\x31\x01"  # Duration
        frame += "".join(chr(i) for i in station_address)  # Destination Address
        frame += "\x00\xde\xad\xbe\xef\x00"  # Source Address
        frame += "\x00\xde\xad\xbe\xef\x00"  # BSSID Address
        frame += "\x00\x00"  # Sequence Control
        frame += "\x00\x00\x00\x00\x00\x00\x00\x00"  # Timestamp
        frame += "\x64\x00"  # Beacon Interval
        frame += "\x01\x04"  # Capabilities
        frame += "\x00%s%s" % (struct.pack("B", len(ssid)), ssid)  # SSID
        frame += "\x01\x08\x82\x84\x8b\x96\x24\x30\x48\x6c"  # Supported Rates
        frame += "\x03\x01\x0e"  # DS parameter set
        frame += "\xdd\x06\xfa\xfa\xfa\x00\xde\xad"  # Vendor Specific

        workers = manager.get_workers()
        for worker in workers:
            if worker.raw_mac_address() == worker_addr:
                break

        for iface in worker.interfaces_list():
            manager.inject_data_from_worker_interface(worker.raw_mac_address(), iface.name(), frame)


    def event_handler(self, event):
        """
        Ignore Wiwo events.
        """
        pass


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
    print " %s <network interface> <timeout in minutes>\n" % sys.argv[0]
    print "Example:"
    print " %s eth0 10\n" % sys.argv[0]
    print "Available Interfaces:"
    if platform.uname()[0].lower() == "windows":
        print_windows_network_interfaces()
    else:
        print_unix_network_interfaces()


if __name__ == "__main__":
    platform_name = platform.uname()[0].lower()
    if platform_name == 'linux':
        if os.geteuid() != 0:
            print 'Error: do you have root?'
            sys.exit(-1)

    if len(sys.argv) != 3:
        show_usage()
        sys.exit(-1)

    iface_name = sys.argv[1]
    minutes = int(sys.argv[2])

    if iface_name not in pcapy.findalldevs():
        show_usage()
        sys.exit(-1)

    ii = None

    try:
        ii = Injector(iface_name)
        timeout = 60 * minutes
        print "Executing for %d minutes." % minutes
        time.sleep(timeout)
    finally:
        print "Stopping..."
        if ii:
            ii.stop()
