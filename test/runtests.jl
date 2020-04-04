using NetworkProtocols
using Sockets
using Test

include("test_data.jl")

@testset "NetworkProtocols.jl" begin
    include("mac_address_tests.jl")
    include("ethernet_tests.jl")
    include("ip_tests.jl")
    include("udp_tests.jl")
    include("dispatch_tests.jl")
end
