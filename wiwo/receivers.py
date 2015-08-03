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

import signal
from multiprocessing import Lock
from multiprocessing import Process

from helpers import interface

import ethernet
import frames

from impacket.ImpactPacket import Ethernet

import pcapy


class WiWoDataFrameHandler(Process):
    """
    It represents the data frame handler object. It handles frames such as Data and Data Fragment frames.
    """

    def __init__(self, manager, iface_name, data_handler):
        Process.__init__(self)
        self.data_fragments = dict()
        self.manager = manager
        self.iface_name = iface_name
        self.data_handler = data_handler

    def run(self):
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        l = Lock()
        l.acquire()
        pd = pcapy.open_live(self.iface_name, ethernet.ETHERNET_MTU, 0, 100)
        pcap_filter = "ether proto %s" % hex(frames.WiwoFrame.ethertype) \
                      + " and (ether[14:1] = 0x07 or ether[14:1] = 0x08)"
        pd.setfilter(pcap_filter)
        l.release()
        pd.loop(-1, self.frame_handler)

    def frame_handler(self, hdr, buff):
        e = Ethernet(buff)
        src = e.get_ether_shost().tostring()
        ether_type = e.get_ether_type()

        if ether_type != frames.WiwoFrame.ethertype:
            return

        wf = frames.WiwoFrame(buff[e.get_header_size():])

        wiwo_sub_frame = wf.get_packet()[wf.get_header_size():]

        if wf.get_type() == frames.WiwoDataFrame.frametype:
            self.data_handler(self.manager, src, wiwo_sub_frame)
        elif wf.get_type() == frames.WiwoDataFragmentFrame.frametype:
            wdf = frames.WiwoDataFragmentFrame(wf.get_packet()[wf.get_header_size():])

            if not(src in self.data_fragments):
                self.data_fragments[src] = list()

            self.data_fragments[src].append(wdf.get_data_as_string())

            if wdf.is_last_fragment():
                frame = str()
                for fragment in self.data_fragments[src]:
                    frame += fragment
                self.data_handler(self.manager, src, frame)
                del(self.data_fragments[src])


class WiWoManagementFrameHandler(Process):
    """
    It represents the management frame handler object. It handles frames such as ACK and Error frames.
    """

    def __init__(self, iface_name, mgnt_frames_queue):
        Process.__init__(self)
        self.iface_name = iface_name
        self.mgnt_frames_queue = mgnt_frames_queue

    def run(self):
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        l = Lock()
        l.acquire()
        pd = pcapy.open_live(self.iface_name, ethernet.ETHERNET_MTU, 0, 100)
        iface_mac_addr = interface.get_string_mac_address(self.iface_name)
        pcap_filter = "ether dst " \
                      + iface_mac_addr \
                      + " and ether proto %s " % hex(frames.WiwoFrame.ethertype) \
                      + "and not (ether[14:1] = 0x07 or ether[14:1] = 0x08)"
        pd.setfilter(pcap_filter)
        l.release()
        pd.loop(-1, self.frame_handler)

    def frame_handler(self, hdr, buff):
        self.mgnt_frames_queue.put(buff)
