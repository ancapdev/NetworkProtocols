@testset "Ethernet" begin

@testset "IO" begin
    @test ethertype_string(ETHERTYPE_IPV4) == "IPv4(0800)"
    @test ethertype_string(ETHERTYPE_ARP) == "ARP(0806)"
    @test ethertype_string(0x1234) == "Unknown(1234)"

    x = EthernetHeader(
        MACAddress((0x1, 0x2, 0x3, 0x4, 0x5, 0x6)),
        MACAddress((0x6, 0x5, 0x4, 0x3, 0x2, 0x1)),
        ETHERTYPE_IPV4)
    @test string(x) == "(06:05:04:03:02:01 -> 01:02:03:04:05:06 IPv4(0800))"
end

@testset "decode" begin
    data = [
        0x1, 0x2, 0x3, 0x4, 0x5, 0x6,
        0x6, 0x5, 0x4, 0x3, 0x2, 0x1,
        0x08, 0x00,
        0xaa, 0xbb, 0xbb, 0xaa
    ]
    x = decode_ethernet(data)
    @test x.header.dst_mac == MACAddress((0x1, 0x2, 0x3, 0x4, 0x5, 0x6))
    @test x.header.src_mac == MACAddress((0x6, 0x5, 0x4, 0x3, 0x2, 0x1))
    @test x.header.ethertype == ETHERTYPE_IPV4
    @test length(x.payload) == 4
    GC.@preserve data begin
        @test x.payload[1] == 0xaa
        @test x.payload[2] == 0xbb
        @test x.payload[3] == 0xbb
        @test x.payload[4] == 0xaa
    end
end

end
