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

# It processes frames in order to taken statistics of traffic encryption.
class TrafficEncryption(APIBase):
    def process(self,  mac, frame):
        """
        It processes the received frame.
        """
        radio_tap = dot11.RadioTap(frame)
        buf = radio_tap.get_body_as_string()

        d11 = dot11.Dot11(buf)

        if d11.get_type() != dot11.Dot11Types.DOT11_TYPE_DATA:
            return 

        buf = d11.get_body_as_string()
        
        data = dot11.Dot11DataFrame(buf)
        data_str = data.get_body_as_string()
        
        wpa2 = dot11.Dot11WPA2(data_str)
        if wpa2.is_WPA2() == 1:
            self.add("WPA2", 0, 1)
        else:
            wap = dot11.Dot11WPA(data_str)
            if wap.is_WPA():
                self.add("WPA", 0, 1)
            else:
                wep = dot11.Dot11WEP(data_str)
                if wep.is_WEP():
                    self.add("WEP", 0, 1)
                else:
                    self.add("Open", 0, 1)









