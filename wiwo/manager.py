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

import time

from multiprocessing import Queue

from manager_svc import ManagerSvc
from receivers import WiWoDataFrameHandler
from receivers import WiWoManagementFrameHandler


class Manager:
    """
    Represents the Manager which is an interface between the user and the Manager Service.
    """

    def __init__(self, iface_name, data_handler, event_handler):
        self.command_queue = Queue()
        self.mgnt_frames_queue = Queue()
        self.command_response_queue = Queue()

        self.__manager_service = ManagerSvc(iface_name,
                                            self.command_queue,
                                            self.command_response_queue,
                                            self.mgnt_frames_queue,
                                            event_handler)
        self.__management_frame_handler = WiWoManagementFrameHandler(iface_name,  self.mgnt_frames_queue)
        self.__data_frame_handler = WiWoDataFrameHandler(self, iface_name, data_handler)

        self.__manager_service.start()
        self.__management_frame_handler.start()
        self.__data_frame_handler.start()
        # We are using multiprocess.Lock to make sure that self.__management_frame_handler and
        # self.__data_frame_handler are initialized and already processing frames. But due to the use of pcap_loop
        # function we need to wait some seconds to make sure we don't lose frames on the initialization. On our
        # system 2 seconds was enough but to make sure we wait for 10 seconds.
        # TODO:  This is a workaround! We need to fix this in a correct way.
        time.sleep(10)

    def stop_receiver_processes(self):
        """
        Method that stops Manager Service, Management Frame Handler and Data Frame Handler Processes.
        method.
        """
        timeout = 5
        self.__manager_service.join(timeout)
        self.__management_frame_handler.join(timeout)
        self.__data_frame_handler.join(timeout)
        if self.__manager_service.is_alive():
            self.__manager_service.terminate()
        if self.__management_frame_handler.is_alive():
            self.__management_frame_handler.terminate()
        if self.__data_frame_handler.is_alive():
            self.__data_frame_handler.terminate()

    def get_workers(self):
        """
        Returns a dictionary with Workers information.
        """
        cmd = {'command': 'get_workers'}
        self.command_queue.put(cmd)
        worker_list = self.command_response_queue.get()
        return worker_list

    def announce_to_worker(self, dst="\xff\xff\xff\xff\xff\xff"):
        """
        Puts a announce command in the command queue. By default it sends a broadcast frame.
        """
        cmd = {'command': 'announce', 'dst': dst}
        self.command_queue.put(cmd)

    def set_channel_to_worker_interface(self, dst, iface_name, channel):
        """
        Puts a set channel command on the command queue.
        """
        cmd = {'command': 'set_channel', 'dst': dst, 'iface_name': iface_name, 'channel': channel}
        self.command_queue.put(cmd)

    def start_worker_interface(self, dst, iface_name, bpf_filter):
        """
        Puts a start command on the command queue.
        """
        cmd = {'command': 'start', 'dst': dst, 'iface_name': iface_name, 'bpf_filter': bpf_filter}
        self.command_queue.put(cmd)

    def stop_worker_interfaces(self, dst):
        """
        Puts a stop command on the command queue.
        """
        cmd = {'command': 'stop', 'dst': dst}
        self.command_queue.put(cmd)

    def inject_data_from_worker_interface(self, dst, iface_name, data):
        """
        Puts a inject data command on the command queue.
        """
        cmd = {'command': 'inject_data', 'dst': dst, 'iface_name': iface_name, 'data': data}
        self.command_queue.put(cmd)

    def get_frame_log(self, mac):
        """
        Returns a dictionary with the worker frame log.
        """
        cmd = {'command': 'get_frame_log', 'mac':mac}
        self.command_queue.put(cmd)
        frame_log = self.command_response_queue.get()
        return frame_log
