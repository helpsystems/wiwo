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
#              Example of how to use the wiwo python module and forward the received frames to Wireshark.
#

import os
import sys
import time
import struct
import tempfile
import platform
import subprocess

import pcapy

from wiwo.manager import Manager

if platform.uname()[0].lower() == "windows":
    from wiwo.helpers import windows


class WiresharkForwarder(object):
    """
    Class that handles Wiwo workers to forward traffic to Wireshark.
    """

    def __init__(self, iface, bpf_filter):
        self.__iface = iface
        self.__bpf_filter = bpf_filter
        self.__workers_list = None

        self.__pipe = None
        self.__pipe_path = None

        self.__initialize_pipe()
        self.__mgr = Manager(self.__iface, self.data_handler, self.event_handler)
        self.__looks_for_workers()
        self.__assign_channels()
        self.__start_workers_interfaces()

    def __del__(self):
        # TODO: Verify pipe close.
        self.__pipe.close()

    def stop(self):
        """
        Method that stops the Manager instance the way it should be done. This object has several python vm instances
        running simultaneous. It also stops all the workers.
        """
        self.__mgr.stop_worker_interfaces("\xff\xff\xff\xff\xff\xff")
        time.sleep(40)
        self.__mgr.stop_receiver_processes()

    def __initialize_pipe(self):
        """
        Its creates a fifo pipe to communicate with Wireshark.
        """
        if platform.uname()[0].lower() == "windows":
            self.__initialize_windows_pipe()
        else:
            self.__initialize_unix_pipe()

    def __initialize_windows_pipe(self):
        """
        Windows pipe initialization method.
        """
        self.__pipe_path = r'\\.\pipe\wireshark'
        print "Execute the following command: %r" % "wireshark -k -i %s" % self.__pipe_path
        self.__pipe = windows.CreateNamedPipe(self.__pipe_path,
                                              windows.PIPE_ACCESS_OUTBOUND,
                                              windows.PIPE_TYPE_MESSAGE | windows.PIPE_WAIT,
                                              1,
                                              65536,
                                              65536,
                                              300,
                                              None)
        if not self.__pipe:
            raise Exception("Unable to create pipe using CreateNamedPipe function.")
        connected = windows.ConnectNamedPipe(self.__pipe, None)
        if connected == 0:
            raise Exception("Unable to create pipe using CreateNamedPipe function.")
        windows.WriteFile(self.__pipe, "\xd4\xc3\xb2\xa1", 4)  # Magic Signature
        windows.WriteFile(self.__pipe, "\x02\x00\x04\x00", 4)  # Version
        windows.WriteFile(self.__pipe, "\x00\x00\x00\x00", 4)  # GMT
        windows.WriteFile(self.__pipe, "\x00\x00\x00\x00", 4)  # GMT
        windows.WriteFile(self.__pipe, "\xff\xff\x00\x00", 4)  # Snaplen
        windows.WriteFile(self.__pipe, "\x7f\x00\x00\x00", 4)  # Data link

    def __initialize_unix_pipe(self):
        """
        Unix pipe initialization method.
        """
        tmpdir = tempfile.mkdtemp()
        self.__pipe_path = os.path.join(tmpdir, "pipe")
        try:
            os.mkfifo(self.__pipe_path)
        except OSError, e:
            raise e
        args = ['/usr/bin/wireshark', '-k', '-i', self.__pipe_path]
        # print "Executing the following command: %s" % " ".join(args)
        proc = subprocess.Popen(args)
        self.__pipe = open(self.__pipe_path, "w+")
        self.__pipe.write("\xd4\xc3\xb2\xa1")  # Magic Signature
        self.__pipe.write("\x02\x00\x04\x00")  # Version
        self.__pipe.write("\x00\x00\x00\x00")  # GMT
        self.__pipe.write("\x00\x00\x00\x00")  # GMT
        self.__pipe.write("\xff\xff\x00\x00")  # Snaplen
        self.__pipe.write("\x7f\x00\x00\x00")  # Data link

    def event_handler(self, event):
        """
        Wiwo Event Handler callback method.
        """
        # print "Event recv: %r" % event
        pass

    def data_handler(self, manager, worker, frame_data):
        """
        Wiwo Data Handler callback method.
        """
        timestamp_seconds = struct.pack("I", int(time.time()))
        timestamp_microseconds = struct.pack("I", 0)  # No microseconds :(
        if platform.uname()[0].lower() == "windows":
            windows.WriteFile(self.__pipe, timestamp_seconds, 4)
            windows.WriteFile(self.__pipe, timestamp_microseconds, 4)
            windows.WriteFile(self.__pipe, struct.pack("I", len(frame_data)), 4)
            windows.WriteFile(self.__pipe, struct.pack("I", len(frame_data)), 4)
            windows.WriteFile(self.__pipe, frame_data, len(frame_data))
        else:
            self.__pipe.write(timestamp_seconds)
            self.__pipe.write(timestamp_microseconds)
            self.__pipe.write(struct.pack("I", len(frame_data)))
            self.__pipe.write(struct.pack("I", len(frame_data)))
            self.__pipe.write(frame_data)

    def __looks_for_workers(self):
        """
        It looks for available workers.
        """
        print "Looking for workers..."
        self.__mgr.announce_to_worker("\xFF\xFF\xFF\xFF\xFF\xFF")
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


def initial_checks():
    """
    It does basic cheks before start the application.
    """
    platform_name = platform.uname()[0].lower()
    if platform_name == 'linux':
        if os.geteuid() != 0:
            print 'Error: do you have root?'
            return False
            
    if len(sys.argv) != 4:
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
    print " %s <network interface> <bpf filter> <timeout in minutes>\n" % sys.argv[0]
    print "Example:"
    print " %s eth0 \"type mgt subtype beacon\" 10\n" % sys.argv[0]
    print "Available Interfaces:"
    if platform.uname()[0].lower() == "windows":
        print_windows_network_interfaces()
    else:
        print_unix_network_interfaces()


if __name__ == "__main__":
    # Check root (linux) and command line arguments.
    if not initial_checks():
        sys.exit(-1)
        
    iface_name = sys.argv[1]
    bpf_filter = sys.argv[2]
    minutes = int(sys.argv[3])
    
    # Check if iface_name is a valid interface name.
    if iface_name not in pcapy.findalldevs():
        show_usage()
        sys.exit(-1)
        
    wf = None
    
    try:
        wf = WiresharkForwarder(iface_name, bpf_filter)
        timeout = 60 * minutes
        print "Executing for %d minutes." % minutes
        time.sleep(timeout)
    except KeyboardInterrupt:
        print " Caught CTRL+C."
    finally:
        print "Stopping..."
        if wf: 
            wf.stop()
