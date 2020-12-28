package ipaddr

import (
	"math/big"
	"unsafe"
)

// TODO what will be the nil sequential range?  An unversioned range, much like with addresses
// ie it will have nil top and bottom
// a nil address has a grouping with no segments
// so a nil range will have no range boundaries, it will be empty

type ipAddressSeqRangeInternal struct {
	lower, upper *IPAddress
	cachedCount  big.Int
}

type IPAddressSeqRange struct {
	ipAddressSeqRangeInternal
}

func (rng *IPAddressSeqRange) GetLower() *IPAddress {
	return rng.lower
}

func (rng *IPAddressSeqRange) GetUpper() *IPAddress {
	return rng.upper
}

func (rng *IPAddressSeqRange) ToIPv4SequentialRange() *IPv4AddressSeqRange {
	if rng != nil && rng.lower.IsIPv4() {
		return (*IPv4AddressSeqRange)(unsafe.Pointer(rng))
	}
	return nil
}

func (rng *IPAddressSeqRange) ToIPv6SequentialRange() *IPv6AddressSeqRange {
	if rng != nil && rng.lower.IsIPv6() {
		return (*IPv6AddressSeqRange)(unsafe.Pointer(rng))
	}
	return nil
}

func NewIPv4SeqRange(one, two *IPv4Address) *IPv4AddressSeqRange {
	//TODO compare to ensure lower is the lowest one
	return &IPv4AddressSeqRange{
		ipAddressSeqRangeInternal{
			lower: one.ToIPAddress(),
			upper: two.ToIPAddress(),
		},
	}
}

type IPv4AddressSeqRange struct {
	ipAddressSeqRangeInternal
}

func (rng *IPv4AddressSeqRange) GetLower() *IPv4Address {
	return rng.lower.ToIPv4Address()
}

func (rng *IPv4AddressSeqRange) GetUpper() *IPv4Address {
	return rng.upper.ToIPv4Address()
}

func (rng *IPv4AddressSeqRange) ToIPAddressSeqRange() *IPAddressSeqRange {
	if rng != nil {
		return (*IPAddressSeqRange)(unsafe.Pointer(rng))
	}
	return nil
}

func NewIPv6SeqRange(one, two *IPv6Address) *IPv6AddressSeqRange {
	//TODO do the same as in java constructors - call a new func shared between ipv4/v6
	return nil
}

type IPv6AddressSeqRange struct {
	ipAddressSeqRangeInternal
}

func (rng *IPv6AddressSeqRange) GetLower() *IPv6Address {
	return rng.lower.ToIPv6Address()
}

func (rng *IPv6AddressSeqRange) GetUpper() *IPv6Address {
	return rng.upper.ToIPv6Address()
}

func (rng *IPv6AddressSeqRange) ToIPAddressSeqRange() *IPAddressSeqRange {
	if rng != nil {
		return (*IPAddressSeqRange)(unsafe.Pointer(rng))
	}
	return nil
}
