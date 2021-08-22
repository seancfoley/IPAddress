package ipaddr

type IPv6AddressConverter interface {
	// If the given address is IPv6, or can be converted to IPv6, returns that IPv6Address.  Otherwise, returns nil.
	ToIPv6(address *IPAddress) *IPv6Address
}

type IPv4AddressConverter interface {
	//If the given address is IPv4, or can be converted to IPv4, returns that IPv4Address.  Otherwise, returns nil.
	ToIPv4(address *IPAddress) *IPv4Address
}

type IPAddressConverter interface {
	IPv4AddressConverter

	IPv6AddressConverter

	//returns whether the address is IPv4 or can be converted to IPv4.  If true, ToIPv4(IPAddress) returns non-nil.
	IsIPv4Convertible(address *IPAddress) bool

	//returns whether the address is IPv6 or can be converted to IPv6.  If true, ToIPv6(IPAddress) returns non-nil.
	IsIPv6Convertible(address *IPAddress) bool
}

//TODO add the equivalent of constant DEFAULT_ADDRESS_CONVERTER and the type DefaultAddressConverter (but that's it, since we have no auto conversion like in Java)
