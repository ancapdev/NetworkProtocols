
struct TCPHeader
    src_port::UInt16
    dst_port::UInt16
    seq_num::UInt32
    ack_num::UInt32
    data_offset::UInt8
    flags::UInt8
    window_size::UInt16
    checksum::UInt16
    urgent_pointer::UInt16
end

const FIN_MASK = 0x01
const SYN_MASK = 0x01 << 1
const RST_MASK = 0x01 << 2
const PSH_MASK = 0x01 << 3
const ACK_MASK = 0x01 << 4
const URG_MASK = 0x01 << 5

function Base.getproperty(h::TCPHeader, p::Symbol)
    p == :FIN && return (h.flags & FIN_MASK) != 0
    p == :SYN && return (h.flags & SYN_MASK) != 0
    p == :RST && return (h.flags & RST_MASK) != 0
    p == :PSH && return (h.flags & PSH_MASK) != 0
    p == :ACK && return (h.flags & ACK_MASK) != 0
    p == :URG && return (h.flags & URG_MASK) != 0
    getfield(h, p)
end

struct TCPPacket
    header::TCPHeader
    payload::UnsafeArray{UInt8, 1}
end

function decode_tcp(data::DenseVector{UInt8})
    p = Base.unsafe_convert(Ptr{UInt8}, data)
    GC.@preserve data begin
        h = unsafe_load(convert(Ptr{TCPHeader}, p))
    end
    h = TCPHeader(
        ntoh(h.src_port),
        ntoh(h.dst_port),
        ntoh(h.seq_num),
        ntoh(h.ack_num),
        h.data_offset >> 4,
        h.flags,
        ntoh(h.window_size),
        ntoh(h.checksum),
        ntoh(h.urgent_pointer),
    )
    TCPPacket(h, UnsafeArray{UInt8, 1}(p + h.data_offset *4, (Int(length(data) - h.data_offset * 4),)))
end
