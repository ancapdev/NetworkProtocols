# NOTE: Not using @enum because it craps out when displaying unknown values
const ETHERTYPE_IPV4 = UInt16(0x0800)
const ETHERTYPE_ARP  = UInt16(0x0806)

function ethertype_string(x::UInt16)
    x == ETHERTYPE_IPV4 && return @sprintf("IPv4(%04x)", x)
    x == ETHERTYPE_ARP && return @sprintf("ARP(%0x4x)", x)
    @sprintf("Unknown(%04x)", x)
end

struct EthernetHeader
    dst_mac::MACAddress
    src_mac::MACAddress
    ethertype::UInt16
end

function Base.show(io::IO, x::EthernetHeader)
    print(io, "($(x.src_mac) -> $(x.dst_mac) $(ethertype_string(x.ethertype)))")
end

struct EthernetPacket
    header::EthernetHeader
    payload::UnsafeArray{UInt8, 1}
end

function decode_ethernet(data::DenseVector{UInt8})
    p = Base.unsafe_convert(Ptr{UInt8}, data)
    GC.@preserve data begin
        h = unsafe_load(convert(Ptr{EthernetHeader}, p))
    end
    h = EthernetHeader(h.dst_mac, h.src_mac, bswap(h.ethertype))
    EthernetPacket(
        h,
        UnsafeArray{UInt8, 1}(
            p + sizeof(EthernetHeader),
            (length(data) - sizeof(EthernetHeader),)))
end
