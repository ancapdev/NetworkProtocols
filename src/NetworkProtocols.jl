module NetworkProtocols

using Printf
using UnsafeArrays

export MACAddress
export isunicast, ismulticast, isuniversal, islocal

export EthernetHeader, EthernetPacket
export ETHERTYPE_IPV4, ETHERTYPE_ARP
export decode_ethernet, ethertype_string

export IPv4Address, IPv4Header, IPv4Packet
export IPPROTOCOL_IGMP, IPPROTOCOL_TCP, IPPROTOCOL_UDP
export decode_ipv4

export UDPHeader, UDPPacket
export decode_udp

export dispatch_ethernet

include("mac_address.jl")
include("ethernet.jl")
include("ip.jl")
include("udp.jl")
include("dispatch.jl")

end
