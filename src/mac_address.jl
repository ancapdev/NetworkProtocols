struct MACAddress
    value::NTuple{6, UInt8}
end

function Base.show(io::IO, x::MACAddress)
    @printf(io, "(%02x:%02x:%02x:%02x:%02x:%02x)", x.value...)
end

isunicast(x::MACAddress) = (x.value[1] & 0x1) == 0
ismulticast(x::MACAddress) = (x.value[1] & 0x1) != 0

isuniversal(x::MACAddress) = (x.value[1] & 0x2) == 0
islocal(x::MACAddress) = (x.value[1] & 0x2) != 0
