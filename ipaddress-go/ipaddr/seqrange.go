package ipaddr

import (
	"math/big"
	"unsafe"
)

// TODO what will be the zero IPAddressSeqRange sequential range?  An unversioned range, much like with addresses
// ie it will have nil top and bottom
// a nil address has a grouping with no segments
// so a nil range will have no range boundaries, it will be empty

// TODO The other two, what will be their zero ranges?  Do we default to 0.0.0.0 and :: again?
// But then instead of range of size 0, it has size 1.
// Still, so does the zero addresses.
// And it's safer to be handing out zero addresses and not nil pointers.

type ipAddressSeqRangeInternal struct {
	lower, upper *IPAddress
	cachedCount  big.Int //TODO like other cahces, this needs to be a pointer
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
	if rng == nil {
		return nil
	}
	if rng.lower.IsIPv4() { // returns false when lower is nil
		return (*IPv4AddressSeqRange)(unsafe.Pointer(rng))
	}
	return nil
}

func (rng *IPAddressSeqRange) ToIPv6SequentialRange() *IPv6AddressSeqRange {
	if rng == nil {
		return nil
	}
	if rng.lower.IsIPv6() { // returns false when lower is nil
		return (*IPv6AddressSeqRange)(unsafe.Pointer(rng))
	}
	return nil
}

func NewIPv4SeqRange(one, two *IPv4Address) *IPv4AddressSeqRange {
	return newSeqRange(one.ToIPAddress(), two.ToIPAddress()).ToIPv4SequentialRange()
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

func newSeqRange(one, two *IPAddress) *IPAddressSeqRange {
	//TODO compare to ensure lower is the lowest one
	return &IPAddressSeqRange{
		ipAddressSeqRangeInternal{
			lower: one,
			upper: two,
		},
	}
}

func NewIPv6SeqRange(one, two *IPv6Address) *IPv6AddressSeqRange {
	return newSeqRange(one.ToIPAddress(), two.ToIPAddress()).ToIPv6SequentialRange()
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
