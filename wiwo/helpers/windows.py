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

import ctypes
from ctypes import wintypes

iphlpapi = ctypes.windll.LoadLibrary('Iphlpapi.dll')

# ws2def.h
AF_UNSPEC = 0
AF_INET = 2
AF_INET6 = 23

# winbase.h
PIPE_ACCESS_OUTBOUND = 2
PIPE_TYPE_MESSAGE = 4
PIPE_WAIT = 0

ETHERNET_MAC_ADDRESS_SIZE = 6
MAX_DHCPV6_DUID_LENGTH = 130
MAX_ADAPTER_ADDRESS_LENGTH = 8
WORKING_BUFFER_SIZE = 15000

ERROR_SUCCESS = 0
ERROR_NO_DATA = 232
ERROR_BUFFER_OVERFLOW = 111
ERROR_NOT_ENOUGH_MEMORY = 8
ERROR_INVALID_PARAMETER = 87
ERROR_ADDRESS_NOT_ASSOCIATED = 1228


class GUID(ctypes.Structure):
    """
    GUIDs identify objects such as interfaces, manager entry-point vectors (EPVs), and class objects. A GUID is a
    128-bit value consisting of one group of 8 hexadecimal digits, followed by three groups of 4 hexadecimal digits
    each, followed by one group of 12 hexadecimal digits. The following example GUID shows the groupings of hexadecimal
    digits in a GUID: 6B29FC40-CA47-1067-B31D-00DD010662DA

    typedef struct _GUID {
        DWORD Data1;
        WORD  Data2;
        WORD  Data3;
        BYTE  Data4[8];
    } GUID;
    """
    _fields_ = [("Data1", wintypes.DWORD),
                ("Data2", wintypes.WORD),
                ("Data3", wintypes.WORD),
                ("Data4", wintypes.BYTE * 8)]


class SOCKADDR(ctypes.Structure):
    """
    The SOCKADDR structure is used to store an Internet Protocol (IP) address for a machine participating in a
    Windows Sockets communication.

    struct sockaddr {
        unsigned short sa_family;
        char sa_data[14];
    };
    """
    _fields_ = [('sa_family', ctypes.c_ushort),
                ('sa_data', ctypes.c_byte * 14)]


class SOCKET_ADDRESS(ctypes.Structure):
    """
    The SOCKET_ADDRESS structure stores protocol-specific address information.

    typedef struct _SOCKET_ADDRESS {
        LPSOCKADDR lpSockaddr;
        INT        iSockaddrLength;
    } SOCKET_ADDRESS, *PSOCKET_ADDRESS;
    """
    _fields_ = [('lpSockaddr', ctypes.POINTER(SOCKADDR)),
                ('iSockaddrLength', ctypes.c_int)]


class IP_ADAPTER_ADDRESSES(ctypes.Structure):
    """
    The IP_ADAPTER_ADDRESSES structure is the header node for a linked list of addresses for a particular adapter.
    This structure can simultaneously be used as part of a linked list of IP_ADAPTER_ADDRESSES structures.

    typedef struct _IP_ADAPTER_ADDRESSES {
        union {
            ULONGLONG Alignment;
            struct {
                ULONG Length;
                DWORD IfIndex;
            };
        };
        struct _IP_ADAPTER_ADDRESSES  *Next;
        PCHAR                              AdapterName;
        PIP_ADAPTER_UNICAST_ADDRESS        FirstUnicastAddress;
        PIP_ADAPTER_ANYCAST_ADDRESS        FirstAnycastAddress;
        PIP_ADAPTER_MULTICAST_ADDRESS      FirstMulticastAddress;
        PIP_ADAPTER_DNS_SERVER_ADDRESS     FirstDnsServerAddress;
        PWCHAR                             DnsSuffix;
        PWCHAR                             Description;
        PWCHAR                             FriendlyName;
        BYTE                               PhysicalAddress[MAX_ADAPTER_ADDRESS_LENGTH];
        DWORD                              PhysicalAddressLength;
        DWORD                              Flags;
        DWORD                              Mtu;
        DWORD                              IfType;
        IF_OPER_STATUS                     OperStatus;
        DWORD                              Ipv6IfIndex;
        DWORD                              ZoneIndices[16];
        PIP_ADAPTER_PREFIX                 FirstPrefix;
        ULONG64                            TransmitLinkSpeed;
        ULONG64                            ReceiveLinkSpeed;
        PIP_ADAPTER_WINS_SERVER_ADDRESS_LH FirstWinsServerAddress;
        PIP_ADAPTER_GATEWAY_ADDRESS_LH     FirstGatewayAddress;
        ULONG                              Ipv4Metric;
        ULONG                              Ipv6Metric;
        IF_LUID                            Luid;
        SOCKET_ADDRESS                     Dhcpv4Server;
        NET_IF_COMPARTMENT_ID              CompartmentId;
        NET_IF_NETWORK_GUID                NetworkGuid;
        NET_IF_CONNECTION_TYPE             ConnectionType;
        TUNNEL_TYPE                        TunnelType;
        SOCKET_ADDRESS                     Dhcpv6Server;
        BYTE                               Dhcpv6ClientDuid[MAX_DHCPV6_DUID_LENGTH];
        ULONG                              Dhcpv6ClientDuidLength;
        ULONG                              Dhcpv6Iaid;
        PIP_ADAPTER_DNS_SUFFIX             FirstDnsSuffix;
    } IP_ADAPTER_ADDRESSES, *PIP_ADAPTER_ADDRESSES;
    """
    pass


IP_ADAPTER_ADDRESSES._fields_ = [('Length', ctypes.c_ulong),
                                 ('IfIndex', wintypes.DWORD),
                                 ('Next', ctypes.POINTER(IP_ADAPTER_ADDRESSES)),
                                 ('AdapterName', ctypes.c_char_p),
                                 ('FirstUnicastAddress', ctypes.c_void_p),
                                 ('FirstAnycastAddress', ctypes.c_void_p),
                                 ('FirstMulticastAddress', ctypes.c_void_p),
                                 ('FirstDnsServerAddress', ctypes.c_void_p),
                                 ('DnsSuffix', ctypes.c_wchar_p),
                                 ('Description', ctypes.c_wchar_p),
                                 ('FriendlyName', ctypes.c_wchar_p),
                                 ('PhysicalAddress', ctypes.c_ubyte * MAX_ADAPTER_ADDRESS_LENGTH),
                                 ('PhysicalAddressLength', wintypes.DWORD),
                                 ('Flags', wintypes.DWORD),
                                 ('Mtu', wintypes.DWORD),
                                 ('IfType', wintypes.DWORD),
                                 ('OperStatus', ctypes.c_uint),
                                 ('Ipv6IfIndex', wintypes.DWORD),
                                 ('ZoneIndices', wintypes.DWORD * 16),
                                 ('FirstPrefix', ctypes.c_void_p),
                                 ('TransmitLinkSpeed', ctypes.c_uint64),
                                 ('ReceiveLinkSpeed', ctypes.c_uint64),
                                 ('FirstWinsServerAddress', ctypes.c_void_p),
                                 ('FirstGatewayAddress', ctypes.c_void_p),
                                 ('Ipv4Metric', ctypes.c_ulong),
                                 ('Ipv6Metric', ctypes.c_ulong),
                                 ('Luid', ctypes.c_uint64),
                                 ('Dhcpv4Server', SOCKET_ADDRESS),
                                 ('CompartmentId', ctypes.c_uint32),
                                 ('NetworkGuid', GUID),
                                 ('ConnectionType', ctypes.c_uint),
                                 ('TunnelType', ctypes.c_uint),
                                 ('Dhcpv6Server', SOCKET_ADDRESS),
                                 ('Dhcpv6ClientDuid', ctypes.c_byte * MAX_DHCPV6_DUID_LENGTH),
                                 ('Dhcpv6ClientDuidLength', ctypes.c_ulong),
                                 ('Dhcpv6Iaid', ctypes.c_ulong),
                                 ('FirstDnsSuffix', ctypes.c_void_p)]


def GetAdaptersAddresses():
    """
    The GetAdaptersAddresses function retrieves the addresses associated with the adapters
    on the local computer.
    ULONG WINAPI GetAdaptersAddresses(
        _In_    ULONG                 Family,
        _In_    ULONG                 Flags,
        _In_    PVOID                 Reserved,
        _Inout_ PIP_ADAPTER_ADDRESSES AdapterAddresses,
        _Inout_ PULONG                SizePointer
    );
    """
    func_ref = iphlpapi.GetAdaptersAddresses
    func_ref.argtypes = [wintypes.ULONG,
                         wintypes.ULONG,
                         ctypes.c_void_p,
                         ctypes.POINTER(IP_ADAPTER_ADDRESSES),
                         ctypes.POINTER(wintypes.ULONG)]
    func_ref.restype = wintypes.ULONG
    
    family = AF_UNSPEC
    flags = 0
    reserved = None
    size_pointer = ctypes.c_ulong()
    size_pointer.value = WORKING_BUFFER_SIZE
    buff = ctypes.create_string_buffer(size_pointer.value)
    adapter_addresses = ctypes.cast(buff, ctypes.POINTER(IP_ADAPTER_ADDRESSES))
    result = func_ref(family, flags, reserved, adapter_addresses, size_pointer)
    
    if result == ERROR_ADDRESS_NOT_ASSOCIATED:
        raise Exception("An address has not yet been associated with the network"
                        " endpoint. DHCP lease information was available.")
    elif result == ERROR_BUFFER_OVERFLOW:
        raise Exception("The buffer size indicated by the SizePointer parameter"
                        " is too small to hold the adapter information or the"
                        " AdapterAddresses parameter is NULL. The SizePointer"
                        " parameter returned points to the required size of the"
                        " buffer to hold the adapter information.")
    elif result == ERROR_INVALID_PARAMETER:
        raise Exception("One of the parameters is invalid. This error is returned"
                        " for any of the following conditions: the SizePointer"
                        " parameter is NULL, the Address parameter is not AF_INET"
                        ", AF_INET6, or AF_UNSPEC, or the address information"
                        " for the parameters requested is greater than ULONG_MAX.")
    elif result == ERROR_NOT_ENOUGH_MEMORY:
        raise Exception("Insufficient memory resources are available to complete"
                        " the operation.")
    elif result == ERROR_NO_DATA:
        raise Exception("No addresses were found for the requested parameters.")
    
    return adapter_addresses


def CreateNamedPipe(lpName, dwOpenMode, dwPipeMode, nMaxInstances, nOutBufferSize, nInBufferSize, nDefaultTimeOut,
                    lpSecurityAttributes):
    """
    Creates an instance of a named pipe and returns a handle for subsequent pipe operations. A named pipe server
    process uses this function either to create the first instance of a specific named pipe and establish its basic
    attributes or to create a new instance of an existing named pipe.
    HANDLE WINAPI CreateNamedPipe(
        _In_     LPCTSTR               lpName,
        _In_     DWORD                 dwOpenMode,
        _In_     DWORD                 dwPipeMode,
        _In_     DWORD                 nMaxInstances,
        _In_     DWORD                 nOutBufferSize,
        _In_     DWORD                 nInBufferSize,
        _In_     DWORD                 nDefaultTimeOut,
        _In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes
    );
    """
    func_ref = ctypes.windll.kernel32.CreateNamedPipeA
    func_ref.argtypes = [wintypes.LPCSTR,
                         wintypes.DWORD,
                         wintypes.DWORD,
                         wintypes.DWORD,
                         wintypes.DWORD,
                         wintypes.DWORD,
                         wintypes.DWORD,
                         wintypes.LPVOID]
    func_ref.restype = wintypes.HANDLE
    return func_ref(lpName, dwOpenMode, dwPipeMode, nMaxInstances, nOutBufferSize, nInBufferSize, nDefaultTimeOut,
                    lpSecurityAttributes)


def ConnectNamedPipe(hNamedPipe, lpOverlapped):
    """
    Enables a named pipe server process to wait for a client process to connect to an instance of a named pipe. A client
    process connects by calling either the CreateFile or CallNamedPipe function.

    BOOL WINAPI ConnectNamedPipe(
        _In_        HANDLE       hNamedPipe,
        _Inout_opt_ LPOVERLAPPED lpOverlapped
    );
    """
    func_ref = ctypes.windll.kernel32.ConnectNamedPipe
    func_ref.argtypes = [wintypes.HANDLE,
                         wintypes.LPVOID]
    func_ref.restype = wintypes.BOOL
    return func_ref(hNamedPipe, lpOverlapped)


def WriteFile(hFile, lpBuffer, nNumberOfBytesToWrite):
    """
    Writes data to the specified file or input/output (I/O) device.
    This function is designed for both synchronous and asynchronous operation. For a similar function designed solely
    for asynchronous operation, see WriteFileEx.
    BOOL WINAPI WriteFile(
        _In_        HANDLE       hFile,
        _In_        LPCVOID      lpBuffer,
        _In_        DWORD        nNumberOfBytesToWrite,
        _Out_opt_   LPDWORD      lpNumberOfBytesWritten,
        _Inout_opt_ LPOVERLAPPED lpOverlapped
    );
    """
    func_ref = ctypes.windll.kernel32.WriteFile
    func_ref.argtypes = [wintypes.HANDLE,
                         wintypes.LPCVOID,
                         wintypes.DWORD,
                         wintypes.POINTER(wintypes.DWORD),
                         wintypes.LPVOID]
    func_ref.restype = wintypes.BOOL
    lpNumberOfBytesWritten = wintypes.DWORD()
    result = func_ref(hFile, lpBuffer, nNumberOfBytesToWrite, ctypes.byref(lpNumberOfBytesWritten), None)
    return (result, lpNumberOfBytesWritten.value)


def getNetworkInterfacesInfo():
    """
        This function returns a dictionary that contains all the network interfaces of the system.
    """
    interfaces = dict()
    adapters = GetAdaptersAddresses()
    adapter = adapters.contents
    while True:
        interfaces[adapter.AdapterName] = dict()
        mac_address_lst = list()
        for idx in range(0, adapter.PhysicalAddressLength):
            mac_address_lst.append("%02X" % adapter.PhysicalAddress[idx])
        interfaces[adapter.AdapterName]['description'] = adapter.Description
        interfaces[adapter.AdapterName]['friendly name'] = adapter.FriendlyName
        if mac_address_lst:
            interfaces[adapter.AdapterName]['mac address'] = ":".join(mac_address_lst)
        try:
            adapter = adapter.Next.contents
        except ValueError:
            break
    return interfaces
