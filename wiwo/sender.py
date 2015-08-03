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

import ethernet

import pcapy


class Sender(object):

    @staticmethod
    def send(frame_obj, iface_name):
        """
        Method that inject/send a frame.
        """
        frame = frame_obj.get_packet()
        if len(frame) < ethernet.ETHERNET_MIN_SIZE:
            padding = "\x00" * (ethernet.ETHERNET_MIN_SIZE - len(frame))
            frame += padding
        pd = pcapy.open_live(iface_name, ethernet.ETHERNET_MTU, 0, 100)
        pd.sendpacket(frame)
        return frame
