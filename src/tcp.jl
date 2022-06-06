
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

mutable struct TCPStreamEndpoint
    addr::Sockets.InetAddr{IPv4}
    seq::Union{Nothing, UInt32}
    ack::Union{Nothing, UInt32}
    fin_sent::Bool
end


function tcpstreamid(e1::Sockets.InetAddr{IPv4}, e2::Sockets.InetAddr{IPv4})
    h = zero(UInt)
    if e1.host < e2.host
        h = hash(Int(e1.host), h)
        h = hash(Int(e2.host), h)
    else
        h = hash(Int(e2.host), h)
        h = hash(Int(e1.host), h)
    end
    if e1.port < e2.port
        h = hash(e1.port, h)
        h = hash(e2.port, h)
    else
        h = hash(e2.port, h)
        h = hash(e1.port, h)
    end
    h
end

@enum TCPEvent begin
    TCPE_OPEN           # -> On SYN
    TCPE_CONNECTED      # -> After SYN & SYN-ACK & ACK
    TCPE_CLOSE          # -> After FIN
    TCPE_DISCONNECTED   # -> After RST | FIN & ACK & FIN & ACK
    TCPE_ERROR
    TCPE_RETRANSMIT
end

# TODO deal with ip fragmentation
const TCPHandler = FunctionWrapper{Nothing, Tuple{Sockets.InetAddr{IPv4}, Sockets.InetAddr{IPv4}, Union{TCPEvent, TCPPacket}}}
mutable struct TCPStream
    endpoint1::TCPStreamEndpoint
    endpoint2::TCPStreamEndpoint
    handler::TCPHandler

    function TCPStream(handler, src::Sockets.InetAddr{IPv4}, dst::Sockets.InetAddr{IPv4})
        new(
            TCPStreamEndpoint(src, nothing, nothing, false),
            TCPStreamEndpoint(dst, nothing, nothing, false),
            TCPHandler(handler),
        )
    end
end

function TCPStream(handler, iheader::IPv4Header, theader::TCPHeader)
    TCPStream(
        handler,
        Sockets.InetAddr(iheader.src_ip, theader.src_port),
        Sockets.InetAddr(iheader.dst_ip, theader.dst_port),
    )
end

function get_endpoint_(stream::TCPStream, ip::IPv4, port::UInt16)
    addr = Sockets.InetAddr(ip, port)
    stream.endpoint1.addr == addr && return stream.endpoint1
    stream.endpoint2.addr == addr && return stream.endpoint2
    error("Unknown endpoint $ip $port")
end

function Base.push!(stream::TCPStream, iheader::IPv4Header, packet::TCPPacket)
    theader = packet.header

    src_endpoint = get_endpoint_(stream, iheader.src_ip, theader.src_port)
    dst_endpoint = get_endpoint_(stream, iheader.dst_ip, theader.dst_port)

    if theader.RST
        @assert !theader.SYN
        stream.handler(src_endpoint.addr, dst_endpoint.addr, TCPE_DISCONNECTED)
        return
    end

    if theader.SYN
        if src_endpoint.seq !== nothing
            @error "Seq set before SYN" src_endpoint dst_endpoint iheader packet
            stream.handler(src_endpoint.addr, dst_endpoint.addr, TCPE_ERROR)
            return
        end
        src_endpoint.seq = theader.seq_num + 1
        if theader.ACK
            src_endpoint.ack !== nothing && @error "Ack set before SYN" src_endpoint dst_endpoint iheader packet
            if dst_endpoint.seq === nothing
                @error "SYN-ACK was not preceded by SYN" src_endpoint dst_endpoint iheader packet
                stream.handler(src_endpoint.addr, dst_endpoint.addr, TCPE_ERROR)
                return
            elseif dst_endpoint.seq != theader.ack_num
                @error "SYN-ACK with unexpected ack_num" src_endpoint dst_endpoint iheader packet
                stream.handler(src_endpoint.addr, dst_endpoint.addr, TCPE_ERROR)
                return
            else
                @debug "SYN-ACK received" src_endpoint dst_endpoint iheader packet
            end
            src_endpoint.ack = theader.ack_num
            stream.handler(src_endpoint.addr, dst_endpoint.addr, TCPE_CONNECTED)
        else
            @debug "SYN received" src_endpoint dst_endpoint iheader packet
            stream.handler(src_endpoint.addr, dst_endpoint.addr, TCPE_OPEN)
        end
    elseif theader.FIN
        if !isempty(packet.payload)
            @error "TCP FIN packet with non-empty payload" src_endpoint dst_endpoint iheader packet
            stream.handler(src_endpoint.addr, dst_endpoint.addr, TCPE_ERROR)
            return
        end
        if src_endpoint.fin_sent
            @error "TCP double FIN" src_endpoint dst_endpoint iheader packet
            stream.handler(src_endpoint.addr, dst_endpoint.addr, TCPE_ERROR)
            return
        end

        src_endpoint.fin_sent = true
        src_endpoint.ack = theader.ack_num
        src_endpoint.seq = theader.seq_num + 1
        if dst_endpoint.fin_sent
            stream.handler(src_endpoint.addr, dst_endpoint.addr, TCPE_DISCONNECTED)
        else
            stream.handler(src_endpoint.addr, dst_endpoint.addr, TCPE_CLOSE)
        end
    else
        @assert theader.ACK
        if src_endpoint.seq === nothing || dst_endpoint.seq === nothing || dst_endpoint.ack === nothing
            @error "TCP stream init missed" src_endpoint dst_endpoint iheader packet
            # NOTE: We've seen this connection mid-way, we don't support this at this point
            stream.handler(src_endpoint.addr, dst_endpoint.addr, TCPE_ERROR)
            return
        end

        if theader.seq_num > src_endpoint.seq
            @error "TCP stream seq gap" src_endpoint dst_endpoint iheader packet
            stream.handler(src_endpoint.addr, dst_endpoint.addr, TCPE_ERROR)
            return
        elseif theader.seq_num < src_endpoint.seq
            @warn "TCP retransmission" src_endpoint dst_endpoint iheader packet
            stream.handler(src_endpoint.addr, dst_endpoint.addr, TCPE_RETRANSMIT)
            if theader.seq_num + length(packet.payload) != src_endpoint.seq
                @error "TCP retransmission with different data length" src_endpoint dst_endpoint iheader packet
                stream.handler(src_endpoint.addr, dst_endpoint.addr, TCPE_ERROR)
            end
            return
        end

        if src_endpoint.ack === nothing
            @debug "TCP connection initialised" src_endpoint dst_endpoint
        end
        src_endpoint.ack = theader.ack_num
        src_endpoint.seq = theader.seq_num + length(packet.payload)

        if !isempty(packet.payload)
            stream.handler(src_endpoint.addr, dst_endpoint.addr, packet)
        end
    end
    nothing
end
