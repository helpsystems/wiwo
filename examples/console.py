#!/usr/bin/env python
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

from wiwo.manager import Manager
from wiwo.events import WiwoEvent
from wiwo.helpers import interface

if platform.uname()[0].lower() == "windows":
    from wiwo.helpers import windows


VERSION_MAJOR = 0
VERSION_MINOR = 1


def show_usage():
    """
    It shows how to run the Wimowo console manager.
    """
    print '%s %d.%d\nusage:\n\t%s <interface>' % (sys.argv[0],
                                                  VERSION_MAJOR,
                                                  VERSION_MINOR,
                                                  sys.argv[0])
    print "Available Interfaces:"
    if platform.uname()[0].lower() == "windows":
        print_windows_network_interfaces()
    else:
        print_unix_network_interfaces()
    sys.exit(-1)


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


def initial_interface_checks(iface_name):
    """
    It does basic interface checks before start the application
    """
    if not interface.is_valid_interface(iface_name):
        print 'Error: %s is not a valid interface.' % iface_name
        return False

    return True


def show_workers(worker_list):
    """
    It shows the info of a list of workers.
    """
    print ''
    print '-----------------------------------------'
    print ' List of workers\n'
    worker_idx = 1
    for worker in worker_list:
        print ' %d. %s' % (worker_idx, worker.mac_address())
        interfaces_list = worker.interfaces_list()
        interfaces_ixd = 1
        for interface in interfaces_list:
            if interfaces_ixd == 1:
                print '\t- interfaces:'
            print '\t  %d. %s (%s) - channel: %d - Supported Channels: %r' % (interfaces_ixd,  interface.name(), interface.protocol(), interface.channel(),  interface.supported_channels())

            monitors = interface.monitors()
            monitor_idx = 1
            for monitor in monitors:
                if monitor_idx == 1:
                    print '\t\t- monitors:'
                print '\t\t  %d. %s' % (monitor_idx, monitor.get_filter())
            interfaces_ixd += 1
        print ''
        worker_idx += 1


def select_worker(worker_list):
    """
    It gets a worker to do something.
    """
    show_workers(worker_list)

    option = raw_input(' Select worker -> ')
    if option == '':
        return -1

    while not option.isdigit() or int(option) < 1 or int(option) > len(worker_list):
        print ' Error. None worker was selected.'
        option = raw_input(' Select worker -> ')
        if option == '':
            return -1

    return int(option)


def select_interface(worker):
    """
    It gets a worker interface channel to do something.
    """
    interfaces = worker.interfaces_list()
    if len(interfaces) == 0:
        print ' Error. Worker without interface known.'
        return -1
    elif len(interfaces) == 1:
        return 1

    option = raw_input(' Select interface -> ')
    if option == '':
        return -1

    while not option.isdigit() or int(option) < 1 or int(option) > len(interfaces):
        print ' Error. None worker interface was selected.'
        option = raw_input(' Select interface -> ')
        if option == '':
            return -1

    return int(opt)


def select_channel(iface):
    """
    It gets a worker interface channel to do something.
    """
    option = raw_input(' Channel to set -> ')
    if option == '':
        return -1

    supported_channel_list = iface.supported_channels()
    
    while not option.isdigit() or not int(option) in supported_channel_list:
        print ' Error. None channel was selected.'
        option = raw_input(' Channel to set -> ')
        if option == '':
            return -1

    return int(option)


def confirmation(msg):
    """
    Ask for Yes or No.
    """
    option = raw_input(msg + ' (y/n)? ')
   
    while option != '' and option.lower() != 'y' and option.lower() != 'n':
        print ' Error. Y(yes) or N(no) is expected.'
        option = raw_input(msg + ' (y/n)? ')
        
    if option == '' or option.lower() == 'n':
        return False
    else:
        return True


def list_workers(mgr):
    """
    It gets the list of workers from the manager service and it shows it in the console.
    """
    worker_list = mgr.get_workers()
    show_workers(worker_list)
    raw_input(' Press enter to continue...')


def send_broadcast_announce(mgr):
    """
    It sends a broadcast announce frame using the manager service and it shows info in the console.
    """
    dst = '\xFF\xFF\xFF\xFF\xFF\xFF'
    mgr.announce_to_worker(dst)
    print 'Announcing...'
    time.sleep(1)


def set_channel_to_worker_interface(mgr):
    """
    It sends a set channel frame to a selected worker using the manager service and it shows info in the console.
    """
    worker_list = mgr.get_workers()

    opt_worker = select_worker(worker_list)
    if opt_worker == -1:
        return

    worker = worker_list[opt_worker - 1]

    opt_iface = select_interface(worker)
    if opt_iface == -1:
        return

    iface = worker.interfaces_list()[opt_iface - 1]

    channel_to_set = select_channel(iface)
    if channel_to_set == -1:
        return

    mgr.set_channel_to_worker_interface(worker.raw_mac_address(), iface.name(), channel_to_set)


def start_worker_interface(mgr):
    """
    It sends a start frame to a selected worker using the manager service and it shows info in the console.
    """
    worker_list = mgr.get_workers()

    opt_worker = select_worker(worker_list)
    if opt_worker == -1:
        return

    worker = worker_list[opt_worker - 1]

    opt_iface = select_interface(worker)
    if opt_iface == -1:
        return

    iface = worker.interfaces_list()[opt_iface - 1]

    filter_to_set = raw_input(' Filter to set -> ')

    mgr.start_worker_interface(worker.raw_mac_address(), iface.name(), filter_to_set)


def stop_worker_interfaces(mgr):
    """
    It sends a start frame to a selected worker using the manager service and it shows info in the console.
    """
    worker_list = mgr.get_workers()

    opt_worker = select_worker(worker_list)
    if opt_worker == -1:
        return

    worker = worker_list[opt_worker - 1]

    if not confirmation(' All the monitors in the worker will be stopped. Are you sure'):
        return

    mgr.stop_worker_interfaces(worker.raw_mac_address())


def inject_data_from_worker_interface(mgr):
    """
    It sends data to be injected from a selected worker using the manager service and it shows info in the console.
    """
    worker_list = mgr.get_workers()
    
    opt_worker = select_worker(worker_list)
    if opt_worker == -1:
        return
        
    worker = worker_list[opt_worker - 1]
        
    opt_iface = select_interface(worker_list[opt_worker - 1])
    if opt_iface == -1:
        return

    iface = worker.interfaces_list()[opt_iface - 1]
    
    data_to_inject = raw_input(' Data to inject -> ')

    mgr.inject_data_from_worker_interface(worker.raw_mac_address(), iface.name(), data_to_inject)


def show_workers_frame_log(mgr):
    """
    It shows a list of frames sent.
    """
    worker_list = mgr.get_workers()
    
    opt_worker = select_worker(worker_list)
    if opt_worker == -1:
        return
        
    worker = worker_list[opt_worker - 1]
    
    print ''
    print '-----------------------------------------'
    print 'Frame log\n'
    frame_log = mgr.get_frame_log(worker.raw_mac_address())
    for log_line_idx in range(len(frame_log)):
        print frame_log[log_line_idx]
    print '\n'
    raw_input(' Press enter to continue...')


def stop(mgr):
    """
    It stops all the workers and the manager processes.
    """
    mgr.stop_worker_interfaces("\xff\xff\xff\xff\xff\xff")
    time.sleep(40)
    mgr.stop_receiver_processes()
    
    
def data_handler(manager, mac, frame):
    """
    It writes frames in files inside the data folder.
    """
    data_dir = os.path.join(os.getcwd(), "data")

    if not os.path.isdir(data_dir):
        os.mkdir(data_dir)

    filename = os.path.join(data_dir,
                            "%s.pcap" % interface.transform_mac_address_to_string_mac_address(mac).replace(":", "-"))

    if not os.path.isfile(filename):
        fd = open(filename, "wb")
        fd.write("\xd4\xc3\xb2\xa1")  # Magic Signature
        fd.write("\x02\x00\x04\x00")  # Version
        fd.write("\x00\x00\x00\x00")  # GMT
        fd.write("\x00\x00\x00\x00")  # GMT
        fd.write("\xff\xff\x00\x00")  # Snaplen
        fd.write("\x7f\x00\x00\x00")  # Data link
        fd.close()

    fd = open(filename, "ab")
    fd.write("\x00\x00\x00\x00")
    fd.write("\x00\x00\x00\x00")
    fd.write(struct.pack("I", len(frame)))
    fd.write(struct.pack("I", len(frame)))
    fd.write(frame)

    fd.close()


def event_handler(event):
    """
    It handles the manager events.
    """
    if event.get_type() == WiwoEvent.Error:
        print "Error! %s - mac: %s" % (event.get_msg(),
                                       interface.transform_mac_address_to_string_mac_address(event.get_mac()))


if __name__ == '__main__':
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
        mgr = Manager(iface_name,  data_handler,  event_handler)
        send_broadcast_announce(mgr)

        while True:
            os.system('cls' if os.name == 'nt' else 'clear')

            print 'Wiwo Manager'
            print '------------\n'

            print 'Interface: %s' % iface_name
            print 'MAC Address: %s' % interface.get_string_mac_address(iface_name)

            strs = (" 1. List workers\n"
                    " 2. Send broadcast announce\n"
                    " 3. Set channel to worker's interface\n"
                    " 4. Start worker's interface\n"
                    " 5. Stop worker's interfaces\n"
                    " 6. Inject data from worker's interface\n"
                    " 7. Show worker's frame log\n"
                    " 8. Exit\n"
                    " -> ")
            opt = raw_input(strs)
            while not opt.isdigit() or int(opt) < 1 or int(opt) > 8:
                if opt != '':
                    print ' Error. Wrong option'
                opt = raw_input(' -> ') 
            opt = int(opt)

            if opt == 1:
                list_workers(mgr)
            elif opt == 2:
                send_broadcast_announce(mgr)
            elif opt == 3:
                set_channel_to_worker_interface(mgr)
            elif opt == 4:
                start_worker_interface(mgr)
            elif opt == 5:
                stop_worker_interfaces(mgr)
            elif opt == 6:
                inject_data_from_worker_interface(mgr)
            elif opt == 7:
                show_workers_frame_log(mgr)
            elif opt == 8:
                break

    except KeyboardInterrupt:
        print " Caught CTRL+C."
    finally:
        print "Stopping..."
        if mgr:
            stop(mgr)
