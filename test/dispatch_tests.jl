@testset "Dispatch" begin

#TODO: test TCP and IGMP when implemented
@testset "UDP" begin
    dispatch_ethernet(dns_packet) do h1, h2, h3, payload
        @test typeof(h1) == EthernetHeader
        @test typeof(h2) == IPv4Header
        @test typeof(h3) == UDPHeader
        @test typeof(payload) <: DenseVector{UInt8}
    end
end

end
