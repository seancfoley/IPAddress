package ipaddr

type IPv6AddressConverter interface {
	// If the given address is IPv6, or can be converted to IPv6, returns that IPv6Address.  Otherwise, returns nil.
	ToIPv6(address *IPAddress) *IPv6Address
}

type IPv4AddressConverter interface {
	// If the given address is IPv4, or can be converted to IPv4, returns that IPv4Address.  Otherwise, returns nil.
	ToIPv4(address *IPAddress) *IPv4Address
}

type IPAddressConverter interface {
	IPv4AddressConverter

	IPv6AddressConverter

	// returns whether the address is IPv4 or can be converted to IPv4.  If true, ToIPv4(IPAddress) returns non-nil.
	IsIPv4Convertible(address *IPAddress) bool

	// returns whether the address is IPv6 or can be converted to IPv6.  If true, ToIPv6(IPAddress) returns non-nil.
	IsIPv6Convertible(address *IPAddress) bool
}

// DefaultAddressConverter converts to/from IPv4-mapped addresses, which maps IPv4 a.b.c.d to/from IPv6 ::ffff:a.b.c.d
// Converting from IPv6 to IPv4 requires that the IPV6 address have the prefix 0:0:0:0:0:ffff
// Note that with some subnets, the mapping is not possible due to the range of values in segments.
// For example, ::ffff:0-100:0 cannot be mapped to an IPv4 address because the range 0-0x100 cannot be split into two smaller ranges.
// Similarly, 1-2.0.0.0 cannot be converted to an IPv4-mapped IPv6 address,
// because the two segments 1-2.0 cannot be joined into a single IPv6 segment with the same range of values, namely the two values 0x100 and 0x200.
type DefaultAddressConverter struct{}

var _ IPAddressConverter = DefaultAddressConverter{}

// ToIPv6 converts IPv4-mapped IPv6 addresses to IPv4, or returns the original address if IPv4 already, or returns nil if the address cannot be converted.
func (converter DefaultAddressConverter) ToIPv4(address *IPAddress) *IPv4Address {
	if addr := address.ToIPv4(); addr != nil {
		return addr
	} else if addr := address.ToIPv6(); addr != nil {
		if ipv4Addr, err := addr.GetEmbeddedIPv4Address(); err == nil {
			return ipv4Addr
		}
	}
	return nil
}

// ToIPv6 converts to an IPv4-mapped IPv6 address or returns the original address if IPv6 already.
func (DefaultAddressConverter) ToIPv6(address *IPAddress) *IPv6Address {
	if addr := address.ToIPv6(); addr != nil {
		return addr
	} else if addr := address.ToIPv4(); addr != nil {
		if ipv6Addr, err := addr.GetIPv4MappedAddress(); err == nil {
			return ipv6Addr
		}
	}
	return nil
}

func (DefaultAddressConverter) IsIPv4Convertible(address *IPAddress) bool {
	if addr := address.ToIPv6(); addr != nil {
		if addr.IsIPv4Mapped() {
			if _, _, _, _, err := addr.GetSegment(IPv6SegmentCount - 1).splitSegValues(); err != nil {
				return false
			} else if _, _, _, _, err := addr.GetSegment(IPv6SegmentCount - 2).splitSegValues(); err != nil {
				return false
			}
			return true
		}
	}
	return address.IsIPv4()
}

func (DefaultAddressConverter) IsIPv6Convertible(address *IPAddress) bool {
	if addr := address.ToIPv4(); addr != nil {
		return addr.GetSegment(0).isJoinableTo(addr.GetSegment(1)) && addr.GetSegment(2).isJoinableTo(addr.GetSegment(3))
	}
	return address.isIPv6()
}
