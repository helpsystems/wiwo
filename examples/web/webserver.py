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
#              Web example of how to use the wiwo python module to generate statistics and perform traffic analysis.

from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
from wiwo.manager import Manager
from os import curdir, sep
import time
import urlparse
import re
import platform
import sys
import os
import pcapy

if platform.uname()[0].lower() == "windows":
    from wiwo.helpers import windows

#------------------------------------------------------------------------------------
# Charts data generators.
from api.frames_per_channel import FramesPerChannel
from api.traffic_encryption import TrafficEncryption
from api.access_points_per_channel import AccessPointsPerChannel
from api.data_qos_data_frames_per_channel import DataQoSDataFramesPerChannel

# API dictonary.
api_dict = dict()
api_dict['frames_per_channel'] = FramesPerChannel(1)
api_dict['traffic_encryption'] = TrafficEncryption(1)
api_dict['access_points_per_channel'] = AccessPointsPerChannel(1)
api_dict['data_qos_data_frames_per_channel'] = DataQoSDataFramesPerChannel(2)
#------------------------------------------------------------------------------------


# Web server HTTP request handler.
class MyHandler(BaseHTTPRequestHandler):
    """
    It handles all the HTTP requests.
    """
    
    def __init__(self, *args):
        self.file_types = dict()
        self.file_types['html'] = 'text/html'
        self.file_types['css'] = 'text/css'
        self.file_types['js'] = 'text/javascript'
        self.file_types['png'] = 'image/png'
        self.file_types['ico'] = 'image/ico'
        BaseHTTPRequestHandler.__init__(self, *args)
    
    def get_file(self, url):
        """
        It returns the file from an URL.
        """
        url_parsed = urlparse.urlparse(url)
        return url_parsed.path

    def get_file_extension(self,  url):
        """
        It returns the file's extension.
        """
        path = self.get_file(url)
        return path.split('.')[-1]

    def get_content_type(self,  url):
        """
        It returns the right content type for a file type.
        """
        try:
            ext = self.get_file_extension(url)
            return self.file_types[ext]
        except KeyError:
            return None
     
    def do_GET(self): 
        """
        It handles all the HTTP GET request.
        """
        try:
            if None != re.search('/api/*', self.path):
                api_name = self.path.split('/')[-1]
                print api_name
                
                try:
                    api = api_dict[api_name]
                except KeyError:
                    self.send_response(400, 'Bad Request: record does not exist')
                    self.send_header('Content-Type', 'application/json')
                    self.end_headers()
                    return
                
                resp = api.get_data()
                print resp
                
                self.send_response(200)
                self.send_header('Content-type', "text/html")
                self.end_headers()
                self.wfile.write(resp)
                return
                
            else:
                _path = self.path
                if self.path == "/":
                    _path = "/wiwo-traffic-analyzer.html"
                    
                content_type = self.get_content_type(_path)
                if content_type == None:
                    return
                    
                f = open(curdir + sep + self.get_file(_path))
                self.send_response(200)
                self.send_header('Content-type', content_type)
                self.end_headers()
                self.wfile.write(f.read())
                f.close()
                return

        except IOError:
            self.send_error(404,'File Not Found: %s' % self.get_file(_path))


# Wiwo manager wrapper.
class WiwoManager:
    """
    Class that handles Wiwo workers.
    """
    
    def __init__(self, iface, bpf_filter):
        self.__iface = iface
        self.__bpf_filter = bpf_filter
        self.__workers_list = None
        self.__mgr = Manager(self.__iface, self.data_handler, self.event_handler)
        self.__look_for_workers()
        self.__assign_channels()
        self.__start_workers_interfaces()
        
    def data_handler(self, manager, mac, frame):
        """
        It handles all the Wiwo's data frame.
        """
        apis_list = api_dict.values()
        for api in apis_list:
            api.process(mac,  frame)

    def event_handler(self,  event):
        """
        It handles the Wiwo manager's event.
        """
        pass

    def __look_for_workers(self):
        """
        It Looks for available workers.
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

    def stop(self):
        """
        It stops workes and processes.
        """
        self.__mgr.stop_worker_interfaces("\xff\xff\xff\xff\xff\xff")
        time.sleep(40)
        self.__mgr.stop_receiver_processes()
        

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
    

if __name__ == '__main__':
    # Check root (linux) and command line arguments.
    if not initial_checks():
        sys.exit(-1)
        
    iface_name = sys.argv[1]

    # Check if iface_name is a valid interface name.
    if iface_name not in pcapy.findalldevs():
        show_usage()
        sys.exit(-1)
        
    wm = None
    server = None
        
    try:
        # Create Wiwo manager.
        wm = WiwoManager(iface_name, '')
        
        # Run the web server
        print 'Starting web server...'
        server = HTTPServer(('127.0.0.1', 80), MyHandler)
        print 'Web server started in 127.0.0.1:80!'
        server.serve_forever()
        
    except KeyboardInterrupt:
        print " Caught CTRL+C."
        print "Stopping..."
        if server:
            server.socket.close()
        if wm:
            wm.stop()
        


