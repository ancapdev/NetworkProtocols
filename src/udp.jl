struct UDPHeader
    src_port::UInt16
    dst_port::UInt16
    len::UInt16
    checksum::UInt16
end

struct UDPPacket
    header::UDPHeader
    payload::UnsafeArray{UInt8, 1}
end

function decode_udp(data::DenseVector{UInt8})
    p = Base.unsafe_convert(Ptr{UInt8}, data)
    GC.@preserve data begin
        h = unsafe_load(convert(Ptr{UDPHeader}, p))
    end
    h = UDPHeader(
        ntoh(h.src_port),
        ntoh(h.dst_port),
        ntoh(h.len),
        ntoh(h.checksum))
    UDPPacket(h, UnsafeArray{UInt8, 1}(p + 8, (Int(h.len - 8),)))
end
