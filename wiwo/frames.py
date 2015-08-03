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

import array
import struct

from impacket.ImpactPacket import ProtocolPacket


class WiwoFrame(ProtocolPacket):
    """
    Represents the header that appears on every wiwo frame.

    +-----------------+--------+
    | Ethernet Header |  Type  |
    +-----------------+--------+
         14 bytes       1 byte
    """
    ethertype = 0xFAFA

    def __init__(self, buff=None):
        header_size = 1
        tail_size = 0
        ProtocolPacket.__init__(self, header_size, tail_size)
        if buff:
            self.load_packet(buff)

    def get_type(self):
        return self.header.get_byte(0)

    def set_type(self, value):
            self.header.set_byte(0, value)


class WiwoEmptyFrame(ProtocolPacket):
    """
    Represents the header that appears on every Wiwo empty frame.
    """
    def __init__(self, buff=None):
        header_size = 0
        tail_size = 0
        ProtocolPacket.__init__(self, header_size, tail_size)
        if buff:
            self.load_packet(buff)


class WiwoAckFrame(WiwoEmptyFrame):
    """
    Represents the header that appears on every wiwo ACK frame. This is an empty header.
    """
    frametype = 0x00


class WiwoAnnounceFrame(WiwoEmptyFrame):
    """
    Represents the header that appears on every wiwo announce frame. This is an empty header.
    """
    frametype = 0x01


class WiwoInfoRequestFrame(WiwoEmptyFrame):
    """
    Represents the header that appears on every wiwo info request frame. This is an empty header.
    """
    frametype = 0x02


class WiwoInfoResponseFrame(ProtocolPacket):
    """
    Represents the header that appears on every wiwo info response frame.

    +-----------------+--------+---------------------+
    | Ethernet Header |  Type  | Info Response Items |
    +-----------------+--------+---------------------+
         14 bytes       1 byte         N bytes
                                          |
            +-----------------------------+
            |
    +-------------+------------+-------------+---------------+-------------+--------------------+---------+
    | Item Length | Iface Name | Item Length | Protocol Name | Item Length | Supported Channels | Channel |
    +-------------+------------+-------------+---------------+-------------+--------------------+---------+
        1 byte        N bytes       1 byte         N bytes        1 byte           N bytes        1 byte
    """

    frametype = 0x03

    def __init__(self, buff=None):
        header_size = 0
        tail_size = 0
        ProtocolPacket.__init__(self, header_size, tail_size)
        if buff:
            self.load_packet(buff)

    def get_interfaces(self):
        interfaces = list()

        buff = self.body.get_bytes()

        while len(buff):
            wirfi = WiwoInfoResponseFrameInterface(buff)
            if wirfi.get_iface_len() == 0:
                break
            interfaces.append(wirfi)
            buff = buff[wirfi.get_len():]

        return interfaces


class WiwoInfoResponseFrameInterface(ProtocolPacket):

    SIZE_ITEM_LENGTH = 1
    SIZE_ITEM_CHANNEL = 1

    def __init__(self, buff=None):
        header_size = 0
        tail_size = 0

        ProtocolPacket.__init__(self, header_size, tail_size)
        if buff:
            self.load_packet(buff)

    def get_len(self):
        result = self.SIZE_ITEM_LENGTH + self.get_iface_len()
        result += self.SIZE_ITEM_LENGTH + self.get_protocol_len()
        result += self.SIZE_ITEM_LENGTH + self.get_channels_count()
        result += self.SIZE_ITEM_CHANNEL
        return result

    def get_iface_len(self):
        return self.body.get_byte(0)

    def set_iface_len(self, value):
        self.body.set_byte(0, value)
            
    def get_iface(self):
        return self.body.get_bytes()[self.SIZE_ITEM_LENGTH:self.get_iface_len()+self.SIZE_ITEM_LENGTH]

    def get_iface_as_string(self):
        return self.get_iface().tostring()

    def set_iface(self, value):
        self.body.get_bytes()[self.SIZE_ITEM_LENGTH:] = value
        
    def set_iface_from_string(self, value):
        self.body.get_bytes()[self.SIZE_ITEM_LENGTH:] = array.array('B', value)

    def get_protocol_len(self):
        return self.body.get_byte(self.SIZE_ITEM_LENGTH + self.get_iface_len())

    def set_protocol_len(self, value):
        self.body.set_byte(self.SIZE_ITEM_LENGTH + self.get_iface_len(), value)

    def get_protocol(self):
        offset = int()
        offset += self.SIZE_ITEM_LENGTH + self.get_iface_len()
        offset += self.SIZE_ITEM_LENGTH
        return self.body.get_bytes()[offset:offset+self.get_protocol_len()]

    def get_protocol_as_string(self):
        return self.get_protocol().tostring()

    def set_protocol(self, value):
        offset = int()
        offset += self.SIZE_ITEM_LENGTH + self.get_iface_len()
        offset += self.SIZE_ITEM_LENGTH
        self.body.get_bytes()[offset:offset+self.get_protocol_len()] = value
        
    def set_protocol_from_string(self, value):
        offset = int()
        offset += self.SIZE_ITEM_LENGTH + self.get_iface_len()
        offset += self.SIZE_ITEM_LENGTH
        self.body.get_bytes()[offset:offset+self.get_protocol_len()] = array.array('B', value)
    
    def get_channels_count(self):
        offset = int()
        offset += self.SIZE_ITEM_LENGTH + self.get_iface_len()
        offset += self.SIZE_ITEM_LENGTH + self.get_protocol_len()
        return self.body.get_byte(offset)

    def set_channels_count(self, value):
        offset = int()
        offset += self.SIZE_ITEM_LENGTH + self.get_iface_len()
        offset += self.SIZE_ITEM_LENGTH + self.get_protocol_len()
        self.body.set_byte(offset, value)

    def get_channels(self):
        offset = int()
        offset += self.SIZE_ITEM_LENGTH + self.get_iface_len()
        offset += self.SIZE_ITEM_LENGTH + self.get_protocol_len()
        offset += self.SIZE_ITEM_LENGTH
        return self.body.get_bytes()[offset:offset+self.get_channels_count()]

    def set_channels(self, value):
        offset = int()
        offset += self.SIZE_ITEM_LENGTH + self.get_iface_len()
        offset += self.SIZE_ITEM_LENGTH + self.get_protocol_len()
        offset += self.SIZE_ITEM_LENGTH
        self.body.get_bytes()[offset:offset+self.get_channels_count()] = value

    def get_channel(self):
        offset = int()
        offset += self.SIZE_ITEM_LENGTH + self.get_iface_len()
        offset += self.SIZE_ITEM_LENGTH + self.get_protocol_len()
        offset += self.SIZE_ITEM_LENGTH + self.get_channels_count()
        return self.body.get_byte(offset)

    def set_channel(self, value):
        offset = int()
        offset += self.SIZE_ITEM_LENGTH + self.get_iface_len()
        offset += self.SIZE_ITEM_LENGTH + self.get_protocol_len()
        offset += self.SIZE_ITEM_LENGTH + self.get_channels_count()
        self.body.set_byte(offset, value)


class WiwoSetChannelFrame(ProtocolPacket):
    """
    Represents the header that appears on every wiwo set channel frame.

    +-----------------+--------+--------------+------------+---------+
    | Ethernet Header |  Type  | Iface Length | Iface Name | Channel |
    +-----------------+--------+--------------+------------+---------+
         14 bytes       1 byte      1 byte        N bytes    1 byte
    """

    SIZE_ITEM_LENGTH = 1
    SIZE_ITEM_CHANNEL = 1

    frametype = 0x04

    def __init__(self, buff=None):

        header_size = 0
        tail_size = 0

        ProtocolPacket.__init__(self, header_size, tail_size)
        if buff:
            self.load_packet(buff)

    def get_iface_len(self):
        return self.body.get_byte(0)

    def set_iface_len(self, value):
        self.body.set_byte(0, value)

    def get_iface(self):
        return self.body.get_bytes()[self.SIZE_ITEM_LENGTH:self.SIZE_ITEM_LENGTH+self.get_iface_len()]

    def get_iface_as_string(self):
        return self.get_iface().tostring()

    def set_iface(self, value):
        self.body.get_bytes()[self.SIZE_ITEM_LENGTH:] = value
        
    def set_iface_from_string(self, value):
        self.body.get_bytes()[self.SIZE_ITEM_LENGTH:] = array.array('B', value)
    
    def get_channel(self):
        return self.body.get_byte(self.SIZE_ITEM_LENGTH+self.get_iface_len())

    def set_channel(self, value):
        self.body.set_byte(self.SIZE_ITEM_LENGTH+self.get_iface_len(), value)


class WiwoStartFrame(ProtocolPacket):
    """
    Represents the header that appears on every wiwo start frame.

    +-----------------+--------+--------------+------------+-------------------+------------+
    | Ethernet Header |  Type  | Iface Length | Iface Name | BPF Filter Length | BPF Filter |
    +-----------------+--------+--------------+------------+-------------------+------------+
         14 bytes       1 byte      1 byte        N bytes         2 bytes         N bytes
    """

    SIZE_ITEM_LENGTH = 1
    SIZE_BPF_FILTER_LENGTH = 2

    frametype = 0x05

    def __init__(self, buff=None):
        header_size = 0
        tail_size = 0

        ProtocolPacket.__init__(self, header_size, tail_size)
        if buff:
            self.load_packet(buff)

    def get_iface_len(self):
        return self.body.get_byte(0)

    def set_iface_len(self, value):
        self.body.set_byte(0, value)
            
    def get_iface(self):
        return self.body.get_bytes()[self.SIZE_ITEM_LENGTH:self.SIZE_ITEM_LENGTH+self.get_iface_len()]

    def get_iface_as_string(self):
        return self.get_iface().tostring()

    def set_iface(self, value):
        self.body.get_bytes()[self.SIZE_ITEM_LENGTH:] = value
        
    def set_iface_from_string(self, value):
        self.body.get_bytes()[self.SIZE_ITEM_LENGTH:] = array.array('B', value)

    def get_filter_len(self):
        return self.body.get_word(self.SIZE_ITEM_LENGTH+self.get_iface_len())

    def set_filter_len(self, value):
        self.body.set_word(self.SIZE_ITEM_LENGTH+self.get_iface_len(), value)

    def get_filter(self):
        offset = int()
        offset += self.SIZE_ITEM_LENGTH+self.get_iface_len()+self.SIZE_BPF_FILTER_LENGTH
        return self.body.get_bytes()[offset:]

    def get_filter_as_string(self):
        return self.get_filter().tostring()

    def set_filter(self, value):
        offset = int()
        offset += self.SIZE_ITEM_LENGTH+self.get_iface_len()+self.SIZE_BPF_FILTER_LENGTH
        self.body.get_bytes()[offset:] = value
        
    def set_filter_from_string(self, value):
        offset = int()
        offset += self.SIZE_ITEM_LENGTH+self.get_iface_len()+self.SIZE_BPF_FILTER_LENGTH
        self.body.get_bytes()[offset:] = array.array('B', value)


class WiwoStopFrame(WiwoEmptyFrame):
    """
    Represents the header that appears on every wiwo stop frame.  This is an empty header.
    """
    frametype = 0x06


class WiwoDataFrame(ProtocolPacket):
    """
    This represents the header that appears on every wiwo data frame.

    +-----------------+--------+----------+
    | Ethernet Header |  Type  |   Data   |
    +-----------------+--------+----------+
         14 bytes       1 byte    N bytes
    """

    frametype = 0x07

    def __init__(self, buff=None):
        header_size = 0
        tail_size = 0

        ProtocolPacket.__init__(self, header_size, tail_size)
        if buff:
            self.load_packet(buff)

    def get_data(self):
        return self.body.get_bytes()

    def get_data_as_string(self):
        return self.get_data().tostring()

    def set_data(self, value):
        self.body.get_bytes()[:] = value

    def set_data_from_string(self, value):
        self.body.get_bytes()[:] = array.array('B', value)


class WiwoDataFragmentFrame(ProtocolPacket):
    """
    Represents the header that appears on every wiwo data frame.

    +-----------------+--------+------------+----------+
    | Ethernet Header |  Type  |  Seq Ctrl  |   Data   |
    +-----------------+--------+------------+----------+
         14 bytes       1 byte     1 byte      N bytes
    """

    SEQUENCE_NUMBER_MASK = 0x7F
    LAST_FRAGMENT_MASK = 0x80
    SIZE_SEQ_CTRL_LENGTH = 1

    frametype = 0x08

    def __init__(self, buff=None):
        header_size = 1
        tail_size = 0

        ProtocolPacket.__init__(self, header_size, tail_size)
        if buff:
            self.load_packet(buff)

    def get_sequence_control(self):
        return self.header.get_byte(0)

    def set_sequence_control(self, value):
        self.header.set_byte(0, value)

    def get_sequence_number(self):
        return struct.unpack("B", chr(self.get_sequence_control()))[0] & self.SEQUENCE_NUMBER_MASK

    def is_last_fragment(self):
        return bool((self.get_sequence_control() & self.LAST_FRAGMENT_MASK) >> 7)

    def get_data(self):
        return self.body.get_bytes()

    def get_data_as_string(self):
        return self.get_data().tostring()

    def set_data(self, value):
        self.body.get_bytes()[:] = value

    def set_data_from_string(self, value):
        self.body.get_bytes()[:] = array.array('B', value)


class WiwoDataInjectFrame(ProtocolPacket):
    """
    Represents the header that appears on every wiwo data inject frame.

    +-----------------+--------+--------------+------------+----------+
    | Ethernet Header |  Type  | Iface Length | Iface Name |   Data   |
    +-----------------+--------+--------------+------------+----------+
         14 bytes       1 byte      1 byte        N bytes     N bytes
    """

    SIZE_ITEM_LENGTH = 1

    frametype = 0x09

    def __init__(self, buff=None):
        header_size = 0
        tail_size = 0

        ProtocolPacket.__init__(self, header_size, tail_size)
        if buff:
            self.load_packet(buff)

    def get_iface_len(self):
        return self.body.get_byte(0)

    def set_iface_len(self, value):
        self.body.set_byte(0, value)
            
    def get_iface(self):
        return self.body.get_bytes()[self.SIZE_ITEM_LENGTH:self.SIZE_ITEM_LENGTH+self.get_iface_len()]

    def get_iface_as_string(self):
        return self.get_iface().tostring()

    def set_iface(self, value):
        self.body.get_bytes()[self.SIZE_ITEM_LENGTH:] = value
        
    def set_iface_from_string(self, value):
        self.body.get_bytes()[self.SIZE_ITEM_LENGTH:] = array.array('B', value)

    def get_data(self):
        return self.body.get_bytes()[self.SIZE_ITEM_LENGTH+self.get_iface_len():]

    def get_data_as_string(self):
        return self.get_data().tostring()

    def set_data(self, value):
        self.body.get_bytes()[self.SIZE_ITEM_LENGTH+self.get_iface_len():] = value
        
    def set_data_from_string(self, value):
        self.body.get_bytes()[self.SIZE_ITEM_LENGTH+self.get_iface_len():] = array.array('B', value)

            
class WiwoErrorFrame(ProtocolPacket):
    """
    Represents the header that appears on every wiwo error frame.

    +-----------------+--------+---------------+
    | Ethernet Header |  Type  | Error Message |
    +-----------------+--------+---------------+
         14 bytes       1 byte      N bytes
    """

    frametype = 0x0A

    def __init__(self, buff=None):
        header_size = 0
        tail_size = 0
            
        ProtocolPacket.__init__(self, header_size, tail_size)
        if buff:
            self.load_packet(buff)
            
    def get_msg(self):
        return self.body.get_bytes()

    def get_msg_as_string(self):
        return self.get_msg().tostring()

    def set_msg(self, value):
        self.body.get_bytes()[:] = value
        
    def set_msg_from_string(self, value):
        self.body.get_bytes()[:] = array.array('B', value)
