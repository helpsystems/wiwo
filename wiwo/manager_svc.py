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
import Queue
import array
import signal

from multiprocessing import Process

from impacket.ImpactPacket import Ethernet

import frames

from worker import Worker
from sender import Sender
from events import WiwoEvent
from helpers import interface


class ManagerSvc(Process):
    """
    Represents the Manager Service which is an interface between the Manager (the framework interface for the user) and
    the Workers.
    """

    def __init__(self, iface_name, command_queue, command_response_queue, mgnt_frames_queue, event_handler):
        Process.__init__(self)

        self.__iface_name = iface_name
        self.__mac = interface.get_mac_address(self.__iface_name)

        self.__command_queue = command_queue
        self.__command_response_queue = command_response_queue
        self.__mgnt_frames_queue = mgnt_frames_queue

        self.__event_handler = event_handler

        self.__worker_dict = dict()

    def run(self):
        """
        Method representing the Manager Service activity, acting as an interface between the Manager and the Workers.
        """
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        while True:
            self.__process_commands()
            self.__process_mgnt_frames()

    def __get_command(self):
        """
        Method that gets a command from the command queue. This is a protected method used by the __process_commands
        method.
        """
        try:
            return self.__command_queue.get_nowait()
        except Queue.Empty:
            pass
        return None

    def __process_commands(self):
        """
        Method that process commands from a Manager instance.
        """
        cmd = self.__get_command()
        if cmd:
            if cmd['command'] == 'get_workers':
                self.get_workers()
            elif cmd['command'] == 'announce':
                self.announce_to_worker(cmd['dst'])
            elif cmd['command'] == 'set_channel':
                self.set_channel_to_worker_interface(cmd['dst'], cmd['iface_name'], cmd['channel'])
            elif cmd['command'] == 'start':
                self.start_worker_interface(cmd['dst'], cmd['iface_name'], cmd['bpf_filter'])
            elif cmd['command'] == 'stop':
                self.stop_worker_interfaces(cmd['dst'])
            elif cmd['command'] == 'inject_data':
                self.inject_data_from_worker_interface(cmd['dst'], cmd['iface_name'], cmd['data'])
            elif cmd['command'] == 'get_frame_log':
                self.get_frame_log(cmd['mac'])

    def __get_mgnt_frame(self):
        """
        Method that gets a WiWo management frame from the management frame queue. This is a protected method used by
        the __process_mgnt_frames method.
        """
        try:
            return self.__mgnt_frames_queue.get_nowait()
        except Queue.Empty:
            pass
            
        return None

    def __process_mgnt_frames(self):
        """
        Method that process management frame from a WiWo Worker.
        """
        mgnt_frame = self.__get_mgnt_frame()
        if mgnt_frame:
            self.__management_frame_handler(mgnt_frame)

    def __send_frame(self, dst, frame):
        """
        Method that send frame to a WiWo Worker.
        """
        if dst == "\xff\xff\xff\xff\xff\xff":
            self.__send_broadcast_frame(frame)
        else:
            self.__send_frame_to_worker(dst, frame)

    def __send_frame_to_worker(self, dst, frame):
        """
        Method that send a frame to a WiWo Worker in the Worker dictionary.
        """
        if dst in self.__worker_dict.keys():
            worker = self.__worker_dict[dst] 
            worker.send(frame, self.__iface_name)

    def __send_broadcast_frame(self, frame):
        """
        Method that send broadcast frame if possible or push the frame to the queue of all Workers.
        This is necessary because we are not able to identify ACK frames because of the missing sequence number on WiWo
        frames.
        """
        if self.__are_workers_available_for_broadcast_frame():
            self.__set_workers_to_wait_response(frame)
            Sender.send(frame, self.__iface_name)
        else:
            time.sleep(1)  # TODO: Fix this code, it's not clear.
            if self.__are_workers_available_for_broadcast_frame():
                self.__set_workers_to_wait_response(frame)
                Sender.send(frame, self.__iface_name)

    def __are_workers_available_for_broadcast_frame(self):
        """
        Method that returns True if all workers are able to receive a WiWo broadcast frame. This only happens when we
        don't have queued frames on any Worker.
        """
        for worker_mac_addr in self.__worker_dict.keys():
            worker = self.__worker_dict[worker_mac_addr]
            if worker.is_waiting_for_response():
                return False
        return True

    def __set_workers_to_wait_response(self, frame):
        """
        Method that puts a frame on every Worker queue.
        """
        for worker_mac_addr in self.__worker_dict.keys():
            worker = self.__worker_dict[worker_mac_addr]
            worker.set_worker_to_wait_response(frame)
            self.__worker_dict[worker_mac_addr] = worker

    @staticmethod
    def __create_wiwo_ethernet_frame(dst, src):
        """
        Returns a WiWo Ethernet frame.
        """
        ethernet_frame = Ethernet()
        dst_array = array.array('B', dst)
        ethernet_frame.set_ether_dhost(dst_array)
        src_array = array.array('B', src)
        ethernet_frame.set_ether_shost(src_array)
        ethernet_frame.set_ether_type(frames.WiwoFrame.ethertype)
        return ethernet_frame

    def __create_wiwo_request_info_frame(self, dst, src):
        """
        Returns a WiWo Info Request frame.
        """
        wiwo_frame = frames.WiwoFrame()
        wiwo_frame.set_type(frames.WiwoInfoRequestFrame.frametype)
        wiwo_info_request_frame = frames.WiwoInfoRequestFrame()
        wiwo_frame.contains(wiwo_info_request_frame)
        ethernet_frame = self.__create_wiwo_ethernet_frame(dst, src)
        ethernet_frame.contains(wiwo_frame)
        return ethernet_frame

    def get_workers(self):
        """
        Puts workers information dictionary in the __command_response_queue for the Manager to get.
        """
        worker_list = list()
        for worker_mac_addr in self.__worker_dict.keys():
            worker = self.__worker_dict[worker_mac_addr]
            worker_list.append(worker.get_worker_info())
        self.__command_response_queue.put(worker_list)

    def announce_to_worker(self, dst):
        """
        Sends a WiWo Announce frame to find Workers.
        """
        wiwo_frame = frames.WiwoFrame()
        wiwo_frame.set_type(frames.WiwoAnnounceFrame.frametype)
        wiwo_announce_frame = frames.WiwoAnnounceFrame()
        wiwo_frame.contains(wiwo_announce_frame)
        ethernet_frame = self.__create_wiwo_ethernet_frame(dst, self.__mac)
        ethernet_frame.contains(wiwo_frame)
        self.__send_frame(dst, ethernet_frame)

    def set_channel_to_worker_interface(self, dst, iface_name, channel):
        """
        Sends a WiWo Set Channel frame to a Worker.
        """
        wiwo_frame = frames.WiwoFrame()
        wiwo_frame.set_type(frames.WiwoSetChannelFrame.frametype)
        wiwo_set_channel_frame = frames.WiwoSetChannelFrame()
        wiwo_set_channel_frame.set_iface_len(len(iface_name))
        wiwo_set_channel_frame.set_iface_from_string(iface_name)
        wiwo_set_channel_frame.set_channel(channel)
        wiwo_frame.contains(wiwo_set_channel_frame)
        ethernet_frame = self.__create_wiwo_ethernet_frame(dst, self.__mac)
        ethernet_frame.contains(wiwo_frame)
        self.__send_frame(dst, ethernet_frame)

    def start_worker_interface(self, dst, iface_name, bpf_filter):
        """
        Sends a WiWo Start frame to a worker in order to start capturing data.
        """
        wiwo_frame = frames.WiwoFrame()
        wiwo_frame.set_type(frames.WiwoStartFrame.frametype)
        wiwo_start_frame = frames.WiwoStartFrame()
        wiwo_start_frame.set_iface_len(len(iface_name))
        wiwo_start_frame.set_iface_from_string(iface_name)
        wiwo_start_frame.set_filter_len(len(bpf_filter))
        wiwo_start_frame.set_filter_from_string(bpf_filter)
        wiwo_frame.contains(wiwo_start_frame)
        ethernet_frame = self.__create_wiwo_ethernet_frame(dst, self.__mac)
        ethernet_frame.contains(wiwo_frame)
        self.__send_frame(dst, ethernet_frame)

    def stop_worker_interfaces(self, dst):
        """
        Sends a WiWo Stop frame to a worker in order to stop capturing data.
        """
        wiwo_frame = frames.WiwoFrame()
        wiwo_frame.set_type(frames.WiwoStopFrame.frametype)
        wiwo_stop_frame = frames.WiwoStopFrame()
        wiwo_frame.contains(wiwo_stop_frame)
        ethernet_frame = self.__create_wiwo_ethernet_frame(dst, self.__mac)
        ethernet_frame.contains(wiwo_frame)
        return self.__send_frame(dst, ethernet_frame)

    def inject_data_from_worker_interface(self, dst, iface_name, data):
        """
        Sends WiWo Data Inject frame to injected data from a Worker.
        """
        wiwo_frame = frames.WiwoFrame()
        wiwo_frame.set_type(frames.WiwoDataInjectFrame.frametype)
        wiwo_data_inject_frame = frames.WiwoDataInjectFrame()
        wiwo_data_inject_frame.set_iface_len(len(iface_name))
        wiwo_data_inject_frame.set_iface_from_string(iface_name)
        wiwo_data_inject_frame.set_data_from_string(data)
        wiwo_frame.contains(wiwo_data_inject_frame)
        ethernet_frame = self.__create_wiwo_ethernet_frame(dst, self.__mac)
        ethernet_frame.contains(wiwo_frame)
        self.__send_frame(dst, ethernet_frame)

    def get_frame_log(self, worker_mac_addr):
        """
        Puts workers frame log in the __command_response_queue for the Manager to get.
        """
        worker_frame_log = []
        for worker_mac_addr in self.__worker_dict.keys():
            worker = self.__worker_dict[worker_mac_addr]
            worker_frame_log = worker.get_frame_log()[:]
        self.__command_response_queue.put(worker_frame_log)

    def __management_frame_handler(self, wiwo_frame_buffer):
        """
        Method that process management frame from a WiWo Worker.
        """
        ethernet_frame = Ethernet(wiwo_frame_buffer)
        ether_dst_addr = ethernet_frame.get_ether_dhost().tostring()
        ether_src_addr = ethernet_frame.get_ether_shost().tostring()

        ether_type = ethernet_frame.get_ether_type()

        if ether_type != frames.WiwoFrame.ethertype:
            return

        wiwo_frame_buffer = wiwo_frame_buffer[ethernet_frame.get_header_size():]
        wiwo_frame = frames.WiwoFrame(wiwo_frame_buffer)
        ethernet_frame.contains(wiwo_frame)

        if not (ether_src_addr in self.__worker_dict.keys()):
            if wiwo_frame.get_type() == frames.WiwoAckFrame.frametype:  # We assume it's a ACK from an Announce
                worker = Worker(ether_src_addr)
                self.__worker_dict[ether_src_addr] = worker
                wiwo_req_info_frame_buffer = self.__create_wiwo_request_info_frame(ether_src_addr, ether_dst_addr)
                worker.send(wiwo_req_info_frame_buffer, self.__iface_name)
                self.__event_handler(WiwoEvent(ether_src_addr, WiwoEvent.WorkerAdded))
        else:
            if wiwo_frame.get_type() == frames.WiwoErrorFrame.frametype:
                worker = self.__worker_dict[ether_src_addr]
                worker.update_after_error()
                wiwo_error_frame_buffer = wiwo_frame_buffer[wiwo_frame.get_header_size():]
                we = frames.WiwoErrorFrame(wiwo_error_frame_buffer)
                self.__event_handler(WiwoEvent(ether_src_addr, WiwoEvent.Error, we.get_msg_as_string()))
            else:
                worker = self.__worker_dict[ether_src_addr]
                type_from_last_frame_sent = worker.get_type_from_last_frame_sent()
                worker.process_ctrl_and_mgnt_frame_received(ethernet_frame, self.__iface_name)

                if type_from_last_frame_sent == -1:
                    return
                elif type_from_last_frame_sent == frames.WiwoDataInjectFrame.frametype:
                    self.__event_handler(WiwoEvent(ether_src_addr, WiwoEvent.DataInjected))
                else:
                    self.__event_handler(WiwoEvent(ether_src_addr, WiwoEvent.WorkerUpdated))
