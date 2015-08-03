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

from sender import Sender
from collections import deque

from wiwo import frames
from wiwo.helpers import interface


class Monitor(object):
    """
    Represents a monitoring instance on a worker interface.
    """

    def __init__(self, bpf_filter):
        self.__bpf_filter = bpf_filter

    def get_filter(self):
        return self.__bpf_filter


class Interface(object):
    """
    Represents a worker network interface.
    """

    INTERFACE_STOPPED = 0
    INTERFACE_STARTED = 1

    def __init__(self, name, protocol, channels, channel):
        self.__name = name
        self.__protocol = protocol
        self.__channels = channels
        self.__channel = channel
        self.__status = Interface.INTERFACE_STOPPED
        self.__monitors = list()

    def get_name(self):
        return self.__name

    def set_iface_name(self, iface_name):
        self.__name = iface_name

    def get_protocol(self):
        return self.__protocol

    def set_protocol(self, protocol):
        self.__protocol = protocol

    def get_channels(self):
        return self.__channels

    def set_channels(self, channels):
        self.__channels = channels

    def get_channel(self):
        return self.__channel

    def set_channel(self, channel):
        self.__channel = channel

    def get_status(self):
        return self.__status

    def set_status(self, status):
        self.__status = status
        if status == Interface.INTERFACE_STOPPED:
            self.__monitors = []

    def get_monitors(self):
        return self.__monitors

    def add_monitor(self, monitor):
        self.__monitors.append(monitor)


class InterfaceInformation(object):
    """
    Represents a worker network interface information.
    """

    def __init__(self, name, protocol, supported_channels, channel, status, monitors_list):
        self.__name = name
        self.__protocol = protocol
        self.__supported_channels = supported_channels
        self.__channel = channel
        self.__status = status
        self.__monitors_list = monitors_list

    def name(self):
        return self.__name

    def protocol(self):
        return self.__protocol

    def supported_channels(self):
        return self.__supported_channels.tolist()

    def is_a_supported_channel(self, channel):
        return channel in self.__supported_channels

    def channel(self):
        return self.__channel

    def status(self):
        return self.__status

    def monitors(self):
        return self.__monitors_list


class Worker(object):
    """
    Represents a worker instance.
    """

    COMMUNICATION_IDLE = 0
    COMMUNICATION_WAITING = 1

    def __init__(self, mac):
        self.__mac = mac
        self.__interfaces_list = list()
        self.__communication_status = Worker.COMMUNICATION_IDLE
        self.__last_frame_sent = None
        self.__frame_queue = deque()
        self.__frame_log = list()

    def get_mac(self):
        return self.__mac

    def get_interfaces(self):
        return self.__interfaces_list

    def get_interface(self, iface_name):
        for interface in self.__interfaces_list:
            if interface.get_name() == iface_name:
                return interface
        return None

    def add_interface(self, interface):
        self.__interfaces_list.append(interface)

    def remove_interfaces(self):
        self.__interfaces_list = []

    def is_waiting_for_response(self):
        return self.__communication_status == self.COMMUNICATION_WAITING

    def set_worker_to_wait_response(self, frame):
        self.__communication_status = Worker.COMMUNICATION_WAITING
        self.__last_frame_sent = frame

    def get_frame_log(self):
        return self.__frame_log

    def _send(self, frame, iface_name):
        self.__communication_status = Worker.COMMUNICATION_WAITING
        self.__last_frame_sent = frame
        frame = Sender.send(frame, iface_name)
        log_line = "- [SENT]: %s" % repr(frame)
        self.__frame_log.append(log_line)
        return frame

    def _queue(self, frame):
        self.__frame_queue.append(frame)
        frame = frame.get_packet()
        log_line = "- [QUEUED]: %s" % repr(frame)
        self.__frame_log.append(log_line)
        return ""

    def update_after_error(self):
        self.__communication_status = Worker.COMMUNICATION_IDLE
        self.__last_frame_sent = None
        self.__frame_queue.clear()

    def get_type_from_last_frame_sent(self):
        lc = self.__last_frame_sent
        if lc is None: 
            return -1
        buff = lc.get_packet()
        lc_wiwo_frame = buff[lc.get_header_size():]
        lcw = frames.WiwoFrame(lc_wiwo_frame)
        return lcw.get_type()

    def send(self, frame, iface_name):
        if self.__communication_status == Worker.COMMUNICATION_IDLE:
            return self._send(frame, iface_name)
        else:
            return self._queue(frame)

    def get_worker_info(self):
        interfaces_list = list()
        for interface in self.__interfaces_list:
            iface_info = InterfaceInformation(interface.get_name(),
                                              interface.get_protocol(),
                                              interface.get_channels()[:],
                                              interface.get_channel(),
                                              interface.get_status(),
                                              interface.get_monitors())
            interfaces_list.append(iface_info)
        return WorkerInformation(self.__mac, interfaces_list)

    def process_ctrl_and_mgnt_frame_received(self, e, iface_name):
        w = e.child()

        log_line = "- [RECEIVED]: %s" % repr(e.get_packet())
        self.__frame_log.append(log_line)

        if w.get_type() == frames.WiwoAckFrame.frametype:
            lc = self.__last_frame_sent
            if lc is None:
                return 

            buff = lc.get_packet()
            lc_wiwo_frame = buff[lc.get_header_size():]
            lcw = frames.WiwoFrame(lc_wiwo_frame)
            lc_wiwo_sub_frame = lcw.get_body_as_string()

            if lcw.get_type() == frames.WiwoSetChannelFrame.frametype:
                wsc = frames.WiwoSetChannelFrame(lc_wiwo_sub_frame)
                worker_iface_name = wsc.get_iface_as_string()
                channel = wsc.get_channel()
                iface = self.get_interface(worker_iface_name)
                if iface is not None:
                    iface.set_channel(channel)

            elif lcw.get_type() == frames.WiwoStartFrame.frametype:
                ws = frames.WiwoStartFrame(lc_wiwo_sub_frame)
                worker_iface_name = ws.get_iface_as_string()
                bpf_filter = ws.get_filter_as_string()
                iface = self.get_interface(worker_iface_name)
                if iface is not None:
                    iface.add_monitor(Monitor(bpf_filter))
                    iface.set_status(Interface.INTERFACE_STARTED)

            elif lcw.get_type() == frames.WiwoStopFrame.frametype:
                for iface in self.__interfaces_list:
                    iface.set_status(Interface.INTERFACE_STOPPED)

        elif w.get_type() == frames.WiwoInfoResponseFrame.frametype:
            self.remove_interfaces()
            wiwo_info_response_frame = w.get_body_as_string()
            wir = frames.WiwoInfoResponseFrame(wiwo_info_response_frame)
            interfaces = wir.get_interfaces()
            for i in interfaces:
                iface = i.get_iface_as_string()
                protocol = i.get_protocol_as_string()
                channels = i.get_channels()
                channel = i.get_channel()
                ii = Interface(iface, protocol, channels, channel)
                self.add_interface(ii) 

        if self.__frame_queue.__len__() > 0:
            frame = self.__frame_queue.popleft()
            self._send(frame, iface_name)
        else:
            self.__communication_status = Worker.COMMUNICATION_IDLE


class WorkerInformation(object):
    """
    Represents a worker information.
    """

    def __init__(self, mac_address, interfaces_list):
        self.__raw_mac_address = mac_address
        self.__mac_address = interface.transform_mac_address_to_string_mac_address(mac_address)
        self.__interfaces_list = interfaces_list

    def raw_mac_address(self):
        return self.__raw_mac_address

    def mac_address(self):
        return self.__mac_address

    def interfaces_list(self):
        return self.__interfaces_list
