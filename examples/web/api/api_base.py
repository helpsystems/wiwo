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
#                       This is the base class for all the classes that process frames in order to get data for charts.
#

import multiprocessing
import json

class APIBase:
    def __init__(self, number_of_values):
        self.dict = multiprocessing.Manager().dict()
        self.number_of_values = number_of_values
        
    def process(self,  mac,  frame):
        """
        It processes the received frame.
        """
        pass

    def add(self, key, value_index, value):
        """
        It stores the value in the data to later return with get_data method.
        """
        if value_index >= self.number_of_values:
            return
        
        if not self.dict.has_key(key):
            values = []
            for i in range(self.number_of_values):
                values.append(0)
            self.dict[key] = values

        values = self.dict[key]
        values[value_index] = values[value_index] + value
        self.dict[key] = values
    
    def get_data(self):
        """
        It returns the data for a chart.
        """
        ret = (self.dict.keys(), self.dict.values())
        return json.dumps(ret)
        

