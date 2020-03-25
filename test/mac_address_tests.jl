@testset "MACAddress" begin

@testset "IO" begin
    x = MACAddress((0x01, 0x10, 0x0a, 0xa0, 0x0, 0xff))
    @test string(x) == "01:10:0a:a0:00:ff"
end

@testset "flags" begin
    x = MACAddress((0x0, 0x0, 0x0, 0x0, 0x0, 0x0))
    @test isunicast(x)
    @test !ismulticast(x)
    @test isuniversal(x)
    @test !islocal(x)
    x = MACAddress((0x01, 0x0, 0x0, 0x0, 0x0, 0x0))
    @test !isunicast(x)
    @test ismulticast(x)
    @test isuniversal(x)
    @test !islocal(x)
    x = MACAddress((0x02, 0x0, 0x0, 0x0, 0x0, 0x0))
    @test isunicast(x)
    @test !ismulticast(x)
    @test !isuniversal(x)
    @test islocal(x)
end

end
