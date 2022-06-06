module NetworkProtocols

using Printf
using Sockets
using UnsafeArrays

export MACAddress
export isunicast, ismulticast, isuniversal, islocal

export EthernetHeader, EthernetPacket
export ETHERTYPE_IPV4, ETHERTYPE_ARP
export decode_ethernet, ethertype_string

export IPv4Header, IPv4Packet
export IPPROTOCOL_IGMP, IPPROTOCOL_TCP, IPPROTOCOL_UDP
export decode_ipv4

export TCPHeader, TCPPacket
export UDPHeader, UDPPacket
export decode_tcp, decode_udp

export dispatch_ethernet

include("mac_address.jl")
include("ethernet.jl")
include("ip.jl")
include("tcp.jl")
include("udp.jl")
include("dispatch.jl")

module Experimental
    import FunctionWrappers.FunctionWrapper
    using Sockets
    using ..NetworkProtocols

    export TCPStream, tcpstreamid
    export TCPEvent, TCPE_OPEN, TCPE_CONNECTED, TCPE_CLOSE, TCPE_DISCONNECTED, TCPE_ERROR, TCPE_RETRANSMIT

    include("experimental/tcp_stream.jl")
end

end
