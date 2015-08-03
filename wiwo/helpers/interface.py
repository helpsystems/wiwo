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

import os
import platform

if platform.uname()[0].lower() == "windows":
    import windows


def transform_mac_address_to_string_mac_address(string_mac_address):
    """
    It transforms a MAC address from raw string format("\x00\x11\x22\x33\x44\x55") to a human readable
    string("00:11:22:33:44:55").
    """
    return ':'.join('%02x' % ord(b) for b in string_mac_address)


def transform_string_mac_address_to_mac_address(string_mac_address):
    """
    It transforms a MAC address from human readable string("00:11:22:33:44:55") to a raw string
    format("\x00\x11\x22\x33\x44\x55").
    """
    result = str()    
    for i in string_mac_address.split(':'):
        result += chr(int(i, 16))
    return result


def get_mac_address(iface_name):
    """
    It returns the MAC from an interface in a raw string format("\x00\x11\x22\x33\x44\x55").
    """
    return transform_string_mac_address_to_mac_address(get_string_mac_address(iface_name))


def get_string_mac_address(iface_name):
    """
    It returns the MAC from an interface as an string.
    """
    platform_name = platform.uname()[0].lower()
    if platform_name == 'windows':
        return windows_get_string_mac_address(iface_name)
    elif platform_name == 'linux':
        return linux_get_string_mac_address(iface_name)
    else:
        raise Exception("Invalid platform.")


def linux_get_string_mac_address(iface_name):
    """
    It returns the MAC from an interface in Linux platforms as a string.
    """
    address_path = '/sys/class/net/%s/address' % iface_name
    fd = open(address_path, 'r')
    mac_address = fd.read()
    fd.close()
    return mac_address.strip()


def windows_get_string_mac_address(iface_name):
    """
    It returns the MAC from an interface in Windows platforms as a string.
    """
    ifaces = windows.getNetworkInterfacesInfo()
    for iface in ifaces:
        if "\Device\NPF_%s" % iface == iface_name:
            if ifaces[iface].has_key('mac address'):
                return ifaces[iface]['mac address']
    raise Exception("Unable to get mac address.")
