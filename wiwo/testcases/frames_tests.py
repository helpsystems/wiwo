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

import os
import sys
import array
import struct
import unittest
sys.path.append(os.path.join(os.getcwd(), "..", ".."))

from wiwo.frames import WiwoFrame
from wiwo.frames import WiwoAckFrame
from wiwo.frames import WiwoAnnounceFrame
from wiwo.frames import WiwoInfoRequestFrame
from wiwo.frames import WiwoInfoResponseFrame
from wiwo.frames import WiwoSetChannelFrame
from wiwo.frames import WiwoStartFrame
from wiwo.frames import WiwoDataFrame
from wiwo.frames import WiwoDataFragmentFrame
from wiwo.frames import WiwoDataInjectFrame
from wiwo.frames import WiwoErrorFrame

from impacket.ImpactPacket import Ethernet


class WiwoFrameHeaderTests(unittest.TestCase):

    def test_wiwo_frame_get_type_success(self):
        """
        Getting the type of a Wiwo ACK frame should return a Wiwo ACK frame type.
        """
        frame_buffer = "\x00\x11\x22\x33\x44\x55" \
                       "\x00\xde\xad\xbe\xef\x00" \
                       "\xfa\xfa" \
                       + chr(WiwoAckFrame.frametype)
        eth = Ethernet(frame_buffer)
        data = frame_buffer[eth.get_header_size():]
        wf = WiwoFrame(data)
        self.assertEqual(WiwoAckFrame.frametype, wf.get_type())

    def test_wiwo_frame_get_type_fail(self):
        """
        Getting the type of a Wiwo ACK frame shouldn't return a Wiwo Error frame type.
        """
        frame_buffer = "\x00\x11\x22\x33\x44\x55" \
                       "\x00\xde\xad\xbe\xef\x00" \
                       "\xfa\xfa" \
                       + chr(WiwoAckFrame.frametype)
        eth = Ethernet(frame_buffer)
        data = frame_buffer[eth.get_header_size():]
        wf = WiwoFrame(data)
        self.assertNotEqual(WiwoErrorFrame.frametype, wf.get_type())

    def test_wiwo_frame_set_type_success(self):
        """
        Setting the type of a Wiwo frame to Wiwo Error frame type should return a Wiwo Error frame type.
        """
        frame_buffer = "\x00\x11\x22\x33\x44\x55" \
                       "\x00\xde\xad\xbe\xef\x00" \
                       "\xfa\xfa" \
                       + chr(WiwoAckFrame.frametype)
        eth = Ethernet(frame_buffer)
        data = frame_buffer[eth.get_header_size():]
        wf = WiwoFrame(data)
        wf.set_type(WiwoErrorFrame.frametype)
        self.assertEqual(WiwoErrorFrame.frametype, wf.get_type())

    def test_wiwo_frame_set_type_fail(self):
        """
        Setting the type of a Wiwo frame to Wiwo Error frame type shouldn't return a Wiwo ACK frame type.
        """
        frame_buffer = "\x00\x11\x22\x33\x44\x55" \
                       "\x00\xde\xad\xbe\xef\x00" \
                       "\xfa\xfa" \
                       + chr(WiwoAckFrame.frametype)
        eth = Ethernet(frame_buffer)
        data = frame_buffer[eth.get_header_size():]
        wf = WiwoFrame(data)
        wf.set_type(WiwoErrorFrame.frametype)
        self.assertNotEqual(WiwoAckFrame.frametype, wf.get_type())


class WiwoEmptyFramesTests(unittest.TestCase):

    def test_wiwo_ack_frame_type_success(self):
        """
        Getting the type of a Wiwo ACK frame should return a Wiwo ACK frame type.
        """
        frame_buffer = "\x00\x11\x22\x33\x44\x55" \
                       "\x00\xde\xad\xbe\xef\x00" \
                       "\xfa\xfa" \
                       + chr(WiwoAckFrame.frametype)
        eth = Ethernet(frame_buffer)
        data = frame_buffer[eth.get_header_size():]
        wf = WiwoFrame(data)
        self.assertEqual(WiwoAckFrame.frametype, wf.get_type())

    def test_wiwo_announce_frame_type_success(self):
        """
        Getting the type of a Wiwo Announce frame should return a Wiwo Announce frame type.
        """
        frame_buffer = "\x00\x11\x22\x33\x44\x55" \
                       "\x00\xde\xad\xbe\xef\x00" \
                       "\xfa\xfa" \
                       + chr(WiwoAnnounceFrame.frametype)
        eth = Ethernet(frame_buffer)
        data = frame_buffer[eth.get_header_size():]
        wf = WiwoFrame(data)
        self.assertEqual(WiwoAnnounceFrame.frametype, wf.get_type())

    def test_wiwo_info_request_frame_type_success(self):
        """
        Getting the type of a Wiwo Info Request frame should return a Wiwo Info Request frame type.
        """
        frame_buffer = "\x00\x11\x22\x33\x44\x55" \
                       "\x00\xde\xad\xbe\xef\x00" \
                       "\xfa\xfa" \
                       + chr(WiwoInfoRequestFrame.frametype)
        eth = Ethernet(frame_buffer)
        data = frame_buffer[eth.get_header_size():]
        wf = WiwoFrame(data)
        self.assertEqual(WiwoInfoRequestFrame.frametype, wf.get_type())


class WiwoInfoResponseFrameTests(unittest.TestCase):

    def test_wiwo_info_response_frame_success(self):
        """
        Getting the iface info of the Wiwo Info Response frame should return the same info that was defined on the info
        dictionary.
        """
        info = {"iface": "wlan0",
                "protocol": "IEEE 802.11g",
                "channels": "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e",
                "channel": "\x01"}

        frame_buffer = "\x00\x11\x22\x33\x44\x55" \
                       "\x00\xde\xad\xbe\xef\x00" \
                       "\xfa\xfa" \
                       + chr(WiwoInfoResponseFrame.frametype) \
                       + "%s%s" % (struct.pack("B", len(info["iface"])), info["iface"]) \
                       + "%s%s" % (struct.pack("B", len(info["protocol"])), info["protocol"]) \
                       + "%s%s" % (struct.pack("B", len(info["channels"])), info["channels"]) \
                       + "%s" % info["channel"]
        eth = Ethernet(frame_buffer)
        data = frame_buffer[eth.get_header_size():]
        wf = WiwoFrame(data)
        if wf.get_type() == WiwoInfoResponseFrame.frametype:
            wirf = WiwoInfoResponseFrame(wf.get_body_as_string())
            ifaces = wirf.get_interfaces()
            for iface in ifaces:
                self.assertEqual(len(info["iface"]), iface.get_iface_len())
                self.assertEqual(info["iface"], iface.get_iface_as_string())
                self.assertEqual(len(info["protocol"]), iface.get_protocol_len())
                self.assertEqual(info["protocol"], iface.get_protocol_as_string())
                self.assertEqual(len(info["channels"]), iface.get_channels_count())
                self.assertEqual(array.array("b", info["channels"]), iface.get_channels())
                self.assertEqual(struct.unpack("B", info["channel"])[0], iface.get_channel())

    def test_wiwo_info_response_multiple_interfaces_frame_success(self):
        """
        Getting the iface info of the Wiwo Info Response frame should return the same info that was defined on the info
        dictionary.
        """
        info_1 = {"iface": "wlan1",
                  "protocol": "IEEE 802.11an",
                  "channels": "\x24\x28\x2c\x30\x34\x38\x3c\x40\x95\x99\x9d\xa1\xa5",
                  "channel": "\x24"}
        info_2 = {"iface": "wlan0",
                  "protocol": "IEEE 802.11g",
                  "channels": "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e",
                  "channel": "\x01"}

        frame_buffer = "\x00\x11\x22\x33\x44\x55" \
                       "\x00\xde\xad\xbe\xef\x00" \
                       "\xfa\xfa" \
                       + chr(WiwoInfoResponseFrame.frametype) \
                       + "%s%s" % (struct.pack("B", len(info_1["iface"])), info_1["iface"]) \
                       + "%s%s" % (struct.pack("B", len(info_1["protocol"])), info_1["protocol"]) \
                       + "%s%s" % (struct.pack("B", len(info_1["channels"])), info_1["channels"]) \
                       + "%s" % info_1["channel"] \
                       + "%s%s" % (struct.pack("B", len(info_2["iface"])), info_2["iface"]) \
                       + "%s%s" % (struct.pack("B", len(info_2["protocol"])), info_2["protocol"]) \
                       + "%s%s" % (struct.pack("B", len(info_2["channels"])), info_2["channels"]) \
                       + "%s" % info_2["channel"]
        eth = Ethernet(frame_buffer)
        data = frame_buffer[eth.get_header_size():]
        wf = WiwoFrame(data)
        if wf.get_type() == WiwoInfoResponseFrame.frametype:
            wirf = WiwoInfoResponseFrame(wf.get_body_as_string())
            ifaces = wirf.get_interfaces()
            self.assertEqual(len(info_1["iface"]), ifaces[0].get_iface_len())
            self.assertEqual(info_1["iface"], ifaces[0].get_iface_as_string())
            self.assertEqual(len(info_1["protocol"]), ifaces[0].get_protocol_len())
            self.assertEqual(info_1["protocol"], ifaces[0].get_protocol_as_string())
            self.assertEqual(len(info_1["channels"]), ifaces[0].get_channels_count())
            self.assertEqual(array.array("B", info_1["channels"]), ifaces[0].get_channels())
            self.assertEqual(len(info_2["iface"]), ifaces[1].get_iface_len())
            self.assertEqual(info_2["iface"], ifaces[1].get_iface_as_string())
            self.assertEqual(len(info_2["protocol"]), ifaces[1].get_protocol_len())
            self.assertEqual(info_2["protocol"], ifaces[1].get_protocol_as_string())
            self.assertEqual(len(info_2["channels"]), ifaces[1].get_channels_count())
            self.assertEqual(array.array("B", info_2["channels"]), ifaces[1].get_channels())

    def test_wiwo_info_response_frame_fail(self):
        """
        Getting the iface info of the Wiwo Info Response frame shouldn't return the same info that was defined on the
        info dictionary.
        """
        info = {"iface": "wlan0",
                "protocol": "IEEE 802.11g",
                "channels": "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e",
                "channel": "\x01"}

        frame_buffer = "\x00\x11\x22\x33\x44\x55" \
                       "\x00\xde\xad\xbe\xef\x00" \
                       "\xfa\xfa" \
                       + chr(WiwoInfoResponseFrame.frametype) \
                       + "%s%s" % (struct.pack("B", len(info["iface"])), info["iface"]) \
                       + "%s%s" % (struct.pack("B", len(info["protocol"])), info["protocol"]) \
                       + "%s%s" % (struct.pack("B", len(info["channels"])), info["channels"]) \
                       + "%s" % info["channel"]
        eth = Ethernet(frame_buffer)
        data = frame_buffer[eth.get_header_size():]
        wf = WiwoFrame(data)
        if wf.get_type() == WiwoInfoResponseFrame.frametype:
            wirf = WiwoInfoResponseFrame(wf.get_body_as_string())
            ifaces = wirf.get_interfaces()
            for iface in ifaces:
                self.assertNotEqual(0, iface.get_iface_len())
                self.assertNotEqual("wlan1", iface.get_iface_as_string())
                self.assertNotEqual(0, iface.get_protocol_len())
                self.assertNotEqual("IEEE 802.3", iface.get_protocol_as_string())
                self.assertNotEqual(0, iface.get_channels_count())
                self.assertNotEqual(array.array("b", "\x00\x01"), iface.get_channels())
                self.assertNotEqual(14, iface.get_channel())


class WiwoSetChannelFrameTests(unittest.TestCase):

    def test_wiwo_set_channel_frame_success(self):
        """
        Getting the iface and channel of the Wiwo Set Channel frame should return the same info that was defined on the
        frame buffer.
        """
        info = {"iface": "wlan0", "channel": 1}
        frame_buffer = "\x00\x11\x22\x33\x44\x55" \
                       "\x00\xde\xad\xbe\xef\x00" \
                       "\xfa\xfa" \
                       + chr(WiwoSetChannelFrame.frametype) \
                       + "%s%s" % (struct.pack("B", len(info["iface"])), info["iface"]) \
                       + "%s" % struct.pack("B", info["channel"])
        eth = Ethernet(frame_buffer)
        data = frame_buffer[eth.get_header_size():]
        wf = WiwoFrame(data)
        if wf.get_type() == WiwoSetChannelFrame.frametype:
            wscf = WiwoSetChannelFrame(wf.get_body_as_string())
            self.assertEqual(len(info["iface"]), wscf.get_iface_len())
            self.assertEqual(info["iface"], wscf.get_iface_as_string())
            self.assertEqual(info["channel"], wscf.get_channel())

    def test_wiwo_set_channel_frame_fail(self):
        """
        Getting the iface and channel of the Wiwo Set Channel frame shouldn't return the same info that was defined on
        the frame buffer.
        """
        info = {"iface": "wlan0", "channel": 1}
        frame_buffer = "\x00\x11\x22\x33\x44\x55" \
                       "\x00\xde\xad\xbe\xef\x00" \
                       "\xfa\xfa" \
                       + chr(WiwoSetChannelFrame.frametype) \
                       + "%s%s" % (struct.pack("B", len(info["iface"])), info["iface"]) \
                       + "%s" % struct.pack("B", info["channel"])
        eth = Ethernet(frame_buffer)
        data = frame_buffer[eth.get_header_size():]
        wf = WiwoFrame(data)
        if wf.get_type() == WiwoSetChannelFrame.frametype:
            wscf = WiwoSetChannelFrame(wf.get_body_as_string())
            self.assertNotEqual(0, wscf.get_iface_len())
            self.assertNotEqual("wlan1", wscf.get_iface_as_string())
            self.assertNotEqual(14, wscf.get_channel())


class WiwoStartFrameTests(unittest.TestCase):

    def test_wiwo_start_frame_success(self):
        """
        Getting the iface and bpf filter of the Wiwo Set Channel frame should return the same info that was defined on
        the frame buffer.
        """
        info = {"iface": "wlan0", "filter": "ip and (tcp port 80 or tcp port 443)"}
        frame_buffer = "\x00\x11\x22\x33\x44\x55" \
                       "\x00\xde\xad\xbe\xef\x00" \
                       "\xfa\xfa" \
                       + chr(WiwoStartFrame.frametype) \
                       + "%s%s" % (struct.pack("B", len(info["iface"])), info["iface"]) \
                       + "%s%s" % (struct.pack("!H", len(info["filter"])), info["filter"])
        eth = Ethernet(frame_buffer)
        data = frame_buffer[eth.get_header_size():]
        wf = WiwoFrame(data)
        if wf.get_type() == WiwoStartFrame.frametype:
            wsf = WiwoStartFrame(wf.get_body_as_string())
            self.assertEqual(len(info["iface"]), wsf.get_iface_len())
            self.assertEqual(info["iface"], wsf.get_iface_as_string())
            self.assertEqual(len(info["filter"]), wsf.get_filter_len())
            self.assertEqual(info["filter"], wsf.get_filter_as_string())

    def test_wiwo_start_frame_fail(self):
        """
        Getting the iface and bpf filter of the Wiwo Set Channel frame shouldn't return the same info that was defined
        on the frame buffer.
        """
        info = {"iface": "wlan0", "filter": "ip and (tcp port 80 or tcp port 443)"}
        frame_buffer = "\x00\x11\x22\x33\x44\x55" \
                       "\x00\xde\xad\xbe\xef\x00" \
                       "\xfa\xfa" \
                       + chr(WiwoStartFrame.frametype) \
                       + "%s%s" % (struct.pack("B", len(info["iface"])), info["iface"]) \
                       + "%s%s" % (struct.pack("!H", len(info["filter"])), info["filter"])
        eth = Ethernet(frame_buffer)
        data = frame_buffer[eth.get_header_size():]
        wf = WiwoFrame(data)
        if wf.get_type() == WiwoStartFrame.frametype:
            wsf = WiwoStartFrame(wf.get_body_as_string())
            self.assertNotEqual(0, wsf.get_iface_len())
            self.assertNotEqual("wlan1", wsf.get_iface_as_string())
            self.assertNotEqual(0, wsf.get_filter_len())
            self.assertNotEqual("udp port 69", wsf.get_filter_as_string())


class WiwoDataFrameTests(unittest.TestCase):

    def test_wiwo_data_frame_success(self):
        """
        Getting the data of the Wiwo Data frame should return the same data that was defined on frame_data.
        """
        frame_data = "\x00\x01\x02\x03\x04\x05"
        frame_buffer = "\x00\x11\x22\x33\x44\x55" \
                       "\x00\xde\xad\xbe\xef\x00" \
                       "\xfa\xfa" \
                       + chr(WiwoDataFrame.frametype) \
                       + frame_data
        eth = Ethernet(frame_buffer)
        data = frame_buffer[eth.get_header_size():]
        wf = WiwoFrame(data)
        if wf.get_type() == WiwoDataFrame.frametype:
            wdf = WiwoDataFrame(wf.get_body_as_string())
            self.assertEqual(frame_data, wdf.get_data_as_string())

    def test_wiwo_data_frame_fail(self):
        """
        Getting the data of the Wiwo Data frame shouldn't return the same data that was defined on frame_data.
        """
        frame_data = "\x00\x01\x02\x03\x04\x05"
        frame_buffer = "\x00\x11\x22\x33\x44\x55" \
                       "\x00\xde\xad\xbe\xef\x00" \
                       "\xfa\xfa" \
                       + chr(WiwoDataFrame.frametype) \
                       + frame_data
        eth = Ethernet(frame_buffer)
        data = frame_buffer[eth.get_header_size():]
        wf = WiwoFrame(data)
        if wf.get_type() == WiwoDataFrame.frametype:
            wdf = WiwoDataFrame(wf.get_body_as_string())
            self.assertNotEqual("\x00\x02\x05\x06", wdf.get_data_as_string())


class WiwoDataFragmentFrameTests(unittest.TestCase):

    def test_wiwo_data_fragment_frame_success(self):
        """
        Getting the data of the Wiwo Data frame should return the same data that was defined on frame_data.
        """
        frame_data = "\x00\x01\x02" + ("\xff" * 1400)
        frame_buffer = "\x00\x11\x22\x33\x44\x55" \
                       "\x00\xde\xad\xbe\xef\x00" \
                       "\xfa\xfa" \
                       + chr(WiwoDataFragmentFrame.frametype) \
                       + "\x82" \
                       + frame_data
        eth = Ethernet(frame_buffer)
        data = frame_buffer[eth.get_header_size():]
        wf = WiwoFrame(data)
        if wf.get_type() == WiwoDataFragmentFrame.frametype:
            wdff = WiwoDataFragmentFrame(wf.get_body_as_string())
            self.assertEqual(2, wdff.get_sequence_number())
            self.assertEqual(True, wdff.is_last_fragment())
            self.assertEqual(frame_data, wdff.get_data_as_string())

    def test_wiwo_data_fragment_frame_fail(self):
        """
        Getting the data of the Wiwo Data frame shouldn't return the same data that was defined on frame_data.
        """
        frame_data = "\x00\x01\x02" + ("\xff" * 1400)
        frame_buffer = "\x00\x11\x22\x33\x44\x55" \
                       "\x00\xde\xad\xbe\xef\x00" \
                       "\xfa\xfa" \
                       + chr(WiwoDataFragmentFrame.frametype) \
                       + "\x82" \
                       + frame_data
        eth = Ethernet(frame_buffer)
        data = frame_buffer[eth.get_header_size():]
        wf = WiwoFrame(data)
        if wf.get_type() == WiwoDataFragmentFrame.frametype:
            wdff = WiwoDataFragmentFrame(wf.get_body_as_string())
            self.assertNotEqual(1, wdff.get_sequence_number())
            self.assertNotEqual(False, wdff.is_last_fragment())
            self.assertNotEqual("\x00" * 1400, wdff.get_data_as_string())


class WiwoDataInjectFrameTests(unittest.TestCase):

    def test_wiwo_data_fragment_frame_success(self):
        """
        Getting the data of the Wiwo Data Inject frame should return the same data that was defined on frame_data.
        """
        iface = "wlan0"
        frame_data = "\xff" * 1400
        frame_buffer = "\x00\x11\x22\x33\x44\x55" \
                       "\x00\xde\xad\xbe\xef\x00" \
                       "\xfa\xfa" \
                       + chr(WiwoDataInjectFrame.frametype) \
                       + "%s%s" % (struct.pack("B", len(iface)), iface) \
                       + frame_data
        eth = Ethernet(frame_buffer)
        data = frame_buffer[eth.get_header_size():]
        wf = WiwoFrame(data)
        if wf.get_type() == WiwoDataInjectFrame.frametype:
            wdif = WiwoDataInjectFrame(wf.get_body_as_string())
            self.assertEqual(len(iface), wdif.get_iface_len())
            self.assertEqual(iface, wdif.get_iface_as_string())
            self.assertEqual(frame_data, wdif.get_data_as_string())

    def test_wiwo_data_fragment_frame_fail(self):
        """
        Getting the data of the Wiwo Data Inject frame shouldn't return the same data that was defined on frame_data.
        """
        iface = "wlan0"
        frame_data = "\xff" * 1400
        frame_buffer = "\x00\x11\x22\x33\x44\x55" \
                       "\x00\xde\xad\xbe\xef\x00" \
                       "\xfa\xfa" \
                       + chr(WiwoDataInjectFrame.frametype) \
                       + "%s%s" % (struct.pack("B", len(iface)), iface) \
                       + frame_data
        eth = Ethernet(frame_buffer)
        data = frame_buffer[eth.get_header_size():]
        wf = WiwoFrame(data)
        if wf.get_type() == WiwoDataInjectFrame.frametype:
            wdif = WiwoDataInjectFrame(wf.get_body_as_string())
            self.assertNotEqual(0, wdif.get_iface_len())
            self.assertNotEqual("wlan1", wdif.get_iface_as_string())
            self.assertNotEqual("\x00" * 1400, wdif.get_data_as_string())


class WiwoErrorFrameTests(unittest.TestCase):

    def test_wiwo_error_frame_success(self):
        """
        Getting the message of the Wiwo Error frame should return the same message that was defined on error_msg.
        """
        error_msg = "Error message."
        frame_buffer = "\x00\x11\x22\x33\x44\x55" \
                       "\x00\xde\xad\xbe\xef\x00" \
                       "\xfa\xfa" \
                       + chr(WiwoErrorFrame.frametype) \
                       + error_msg
        eth = Ethernet(frame_buffer)
        data = frame_buffer[eth.get_header_size():]
        wf = WiwoFrame(data)
        if wf.get_type() == WiwoErrorFrame.frametype:
            wef = WiwoErrorFrame(wf.get_body_as_string())
            self.assertEqual(error_msg, wef.get_msg_as_string())

    def test_wiwo_error_frame_fail(self):
        """
        Getting the message of the Wiwo Error frame shouldn't return the same message that was defined on error_msg.
        """
        error_msg = "Error message."
        frame_buffer = "\x00\x11\x22\x33\x44\x55" \
                       "\x00\xde\xad\xbe\xef\x00" \
                       "\xfa\xfa" \
                       + chr(WiwoErrorFrame.frametype) \
                       + error_msg
        eth = Ethernet(frame_buffer)
        data = frame_buffer[eth.get_header_size():]
        wf = WiwoFrame(data)
        if wf.get_type() == WiwoErrorFrame.frametype:
            wef = WiwoErrorFrame(wf.get_body_as_string())
            self.assertNotEqual("fafa", wef.get_msg_as_string())


if __name__ == "__main__":
    suite = unittest.TestLoader().loadTestsFromTestCase(WiwoFrameHeaderTests)
    unittest.TextTestRunner(verbosity=1).run(suite)

    suite = unittest.TestLoader().loadTestsFromTestCase(WiwoEmptyFramesTests)
    unittest.TextTestRunner(verbosity=1).run(suite)

    suite = unittest.TestLoader().loadTestsFromTestCase(WiwoInfoResponseFrameTests)
    unittest.TextTestRunner(verbosity=1).run(suite)

    suite = unittest.TestLoader().loadTestsFromTestCase(WiwoSetChannelFrameTests)
    unittest.TextTestRunner(verbosity=1).run(suite)

    suite = unittest.TestLoader().loadTestsFromTestCase(WiwoStartFrameTests)
    unittest.TextTestRunner(verbosity=1).run(suite)

    suite = unittest.TestLoader().loadTestsFromTestCase(WiwoDataFrameTests)
    unittest.TextTestRunner(verbosity=1).run(suite)

    suite = unittest.TestLoader().loadTestsFromTestCase(WiwoDataFragmentFrameTests)
    unittest.TextTestRunner(verbosity=1).run(suite)

    suite = unittest.TestLoader().loadTestsFromTestCase(WiwoDataInjectFrameTests)
    unittest.TextTestRunner(verbosity=1).run(suite)

    suite = unittest.TestLoader().loadTestsFromTestCase(WiwoErrorFrameTests)
    unittest.TextTestRunner(verbosity=1).run(suite)
