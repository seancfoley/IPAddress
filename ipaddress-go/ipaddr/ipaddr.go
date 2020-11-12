package ipaddr

import "unsafe"

type IPVersion string

const (
	PrefixLenSeparator = '/'

	UNKNOWN_VERSION IPVersion = ""
	IPv4            IPVersion = "IPv4"
	IPv6            IPVersion = "IPv6"
)

func (version IPVersion) isIPv6() bool {
	return version == IPv6
}

func (version IPVersion) isIPv4() bool {
	return version == IPv4
}

func (version IPVersion) isUnknown() bool {
	return version == UNKNOWN_VERSION
}

//returns an index starting from 0 with UNKNOWN_VERSION being the highest
func (version IPVersion) index() int {
	if version.isIPv4() {
		return 0
	} else if version.isIPv6() {
		return 1
	}
	return 2
}

func (version IPVersion) String() string {
	return string(version)
}

//
//
//
type IPAddress struct {
	addressInternal
}

func (addr *IPAddress) ToAddress() *Address {
	if addr == nil {
		return nil
	}
	return &addr.Address
}

func (addr *IPAddress) ToIPAddress() *IPAddress {
	return addr
}

func (addr *IPAddress) IsIPv4() bool {
	return addr.section.matchesIPv4Address()
}

func (addr *IPAddress) IsIPv6() bool {
	return addr.section.matchesIPv6Address()
}

func (addr *IPAddress) GetIPVersion() IPVersion {
	if addr.IsIPv4() {
		return IPv4
	}
	return IPv6
}

func (addr *IPAddress) GetSection() *IPAddressSection {
	return addr.section.ToIPAddressSection()
}

func (addr *IPAddress) GetNetworkPrefixLength() PrefixLen {
	return addr.GetSection().GetNetworkPrefixLength()
}

func (addr *IPAddress) ToIPv6Address() *IPv6Address {
	if addr != nil {
		if addr.IsIPv6() {
			return (*IPv6Address)(unsafe.Pointer(addr))
			//return (*IPv6Address)unsafe.Pointer((uintptr(unsafe.Pointer(addr)) + unsafe.Offsetof(addr.addressInternal))_
			//return IPv6Address{ipAddressInternal{addr}}
		}
	}
	return nil
	//return IPv6Address{}
}

func (addr *IPAddress) ToIPv4Address() *IPv4Address {
	if addr != nil {
		if addr.IsIPv4() {
			return (*IPv4Address)(unsafe.Pointer(addr))
			//return IPv4Address{ipAddressInternal{addr}}
		}
	}
	return nil
	//return IPv4Address{}
}

// necessary to avoid direct access to IPAddress, which when a zero value, has no segments, not compatible with zero value for ivp4 or ipv6
type ipAddressInternal struct {
	IPAddress
}

// TODO make sure everything in IPv4 and IPv6 is "overridden", in the sense all methods will check for no divisions and
// create the default zero-segments if necessary, so we never expose a zero value with 0 segments
// The zero values of everythign else will have sections with no segments
