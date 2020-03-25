using NetworkProtocols
using Test

@testset "NetworkProtocols.jl" begin
    include("mac_address_tests.jl")
    include("ethernet_tests.jl")
end
