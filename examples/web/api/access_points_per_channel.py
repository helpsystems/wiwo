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

from api_base import APIBase
from impacket import dot11
import helpers

# It processes frames in order to taken statistics of amount of access points per channel.
class AccessPointsPerChannel(APIBase):
    def __init__(self, number_of_values):
        APIBase.__init__(self, number_of_values)
        self.bssids = dict()
        
    def process(self,  mac, frame):
        """
        It processes the received frame.
        """
        radio_tap = dot11.RadioTap(frame)
        buf = radio_tap.get_body_as_string()

        d11 = dot11.Dot11(buf)
        if d11.get_type() != dot11.Dot11Types.DOT11_TYPE_MANAGEMENT:
            return
            
        if d11.get_subtype() != dot11.Dot11Types().DOT11_SUBTYPE_MANAGEMENT_BEACON:
            return

        buf = d11.get_body_as_string()
        mgt = dot11.Dot11ManagementFrame(buf)
        bssid = mgt.get_bssid()
        bssid_str = bssid.tostring()
        
        # Check if the access point was already counted.
        if self.bssids.has_key(bssid_str):
            return

        self.bssids[bssid_str] = ""

        channel = helpers.get_channel_from_frame(frame)
        if channel == -1:
            return
           
        self.add(channel, 0, 1)
