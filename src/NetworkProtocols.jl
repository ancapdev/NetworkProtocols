module NetworkProtocols

using Blobs

# TODO:
# Link Layer:
# - Ethernet
# Internet Layer:
# - IPv4
# - IGMP
# Transport Layer:
# - TCP
# - UDP

# NOTE: Not using @enum because it craps out when displaying unknown values
const ETHERTYPE_IPV4 = UInt16(0x0800)
const ETHERTYPE_ARP  = UInt16(0x0806)

const MacAddress = NTuple{6, UInt8}
const IPv4Address = NTuple{4, UInt8}

struct EthernetHeader
    dst_mac::MacAddress
    src_mac::MacAddress
    ethertype::UInt16
end

struct EthernetPacket
    header::EthernetHeader
    payload::Ptr{Nothing}
    payload_length::Int64
end

# TODO: check minimum packet length
# TODO: support various header types
# TODO: read FCS, heuristically (not always in pcap)
function decode_ethernet(data::Ptr{Nothing}, len::Integer)
    h = Blob{EthernetHeader}(data, 0, len)[]
    h = EthernetHeader(h.dst_mac, h.src_mac, bswap(h.ethertype))
    EthernetPacket(
        h,
        data + sizeof(EthernetHeader),
        len - sizeof(EthernetHeader))
end

struct IPv4HeaderRaw
    version_ihl::UInt8
    dscp_ecn::UInt8
    total_length::UInt16
    id::UInt16
    flags_fragmentoffset::UInt16
    ttl::UInt8
    protocol::UInt8
    header_checksum::UInt16
    src_ip::IPv4Address
    dst_ip::IPv4Address
end

const IPPROTOCOL_IGMP = UInt8(0x02)
const IPPROTOCOL_TCP = UInt8(0x06)
const IPPROTOCOL_UDP = UInt8(0x11)

struct IPv4Header
    header_length::UInt8
    dscp::UInt8
    total_length::UInt16
    id::UInt16
    flags::UInt8
    fragment_offset::UInt16
    ttl::UInt8
    protocol::UInt8
    src_ip::IPv4Address
    dst_ip::IPv4Address
end

struct IPv4Packet
    header::IPv4Header
    payload::Ptr{Nothing}
    payload_length::Int64
end

function decode_ipv4(data::Ptr{Nothing}, len::Integer)
    rh = Blob{IPv4HeaderRaw}(data, 0, Int(len))[]
    h = IPv4Header(
        (rh.version_ihl & 0x0f) * 4,
        rh.dscp_ecn >> 2,
        ntoh(rh.total_length),
        ntoh(rh.id),
        ntoh(rh.flags_fragmentoffset) >> 13,
        (ntoh(rh.flags_fragmentoffset) & 0x1fff) * 8,
        rh.ttl,
        rh.protocol,
        rh.src_ip,
        rh.dst_ip)
    IPv4Packet(h, data + h.header_length, h.total_length - h.header_length)
end

struct UDPHeader
    src_port::UInt16
    dst_port::UInt16
    len::UInt16
    checksum::UInt16
end

struct UDPPacket
    header::UDPHeader
    payload::Ptr{Nothing}
    payload_length::Int64
end

function decode_udp(data::Ptr{Nothing}, len::Integer)
    h = Blob{UDPHeader}(data, 0, Int(len))[]
    h = UDPHeader(
        ntoh(h.src_port),
        ntoh(h.dst_port),
        ntoh(h.len),
        ntoh(h.checksum))
    UDPPacket(h, data + 8, h.len - 8)
end

function dispatch_ethernet(visitor, data::Ptr{Nothing}, len::Integer)
    ep = decode_ethernet(data, len)
    if ep.header.ethertype == ETHERTYPE_IPV4
        ipp = decode_ipv4(ep.payload, ep.payload_length)
        if ipp.header.protocol == IPPROTOCOL_UDP
            udpp = NetworkProtocols.decode_udp(ipp.payload, ipp.payload_length)
            visitor(ep.header, ipp.header, udpp.header, udpp.payload, udpp.payload_length)
        elseif ipp.header.protocol == IPPROTOCOL_TCP
        elseif ipp.header.protocol == IPPROTOCOL_IGMP
        end
    end
end

end
