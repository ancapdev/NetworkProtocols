function dispatch_ethernet(visitor, data::DenseVector{UInt8})
    ep = decode_ethernet(data)
    if ep.header.ethertype == ETHERTYPE_IPV4
        ipp = decode_ipv4(ep.payload)
        if ipp.header.protocol == IPPROTOCOL_UDP
            udpp = NetworkProtocols.decode_udp(ipp.payload)
            return visitor(ep.header, ipp.header, udpp.header, udpp.payload)
        elseif ipp.header.protocol == IPPROTOCOL_TCP
        elseif ipp.header.protocol == IPPROTOCOL_IGMP
        end
    end
    nothing
end
