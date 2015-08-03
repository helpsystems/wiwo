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

class WiwoEvent:
    """
    Represents an event on the wiwo framework.
    """

    WorkerAdded = 0
    WorkerUpdated = 1
    DataInjected = 2
    Error = 3

    def __init__(self, mac, event_type, msg=""):
        self._mac = mac
        self._type = event_type
        self._msg = msg

    def get_mac(self):
        return self._mac

    def get_type(self):
        return self._type

    def get_msg(self):
        return self._msg
