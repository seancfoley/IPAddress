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
//type IPAddress struct {
//	addressInternal
//}

// necessary to avoid direct access to IPAddress, which when a zero value, has no segments, not compatible with zero value for ivp4 or ipv6
type ipAddressInternal struct {
	addressInternal
}

func (addr *ipAddressInternal) ToAddress() *Address {
	return (*Address)(unsafe.Pointer(addr))
}

func (addr *ipAddressInternal) IsIPv4() bool {
	return addr.section.matchesIPv4Address()
}

func (addr *ipAddressInternal) IsIPv6() bool {
	return addr.section.matchesIPv6Address()
}

func (addr *ipAddressInternal) GetIPVersion() IPVersion {
	if addr.IsIPv4() {
		return IPv4
	}
	return IPv6
}

func (addr *ipAddressInternal) GetSection() *IPAddressSection {
	return addr.section.ToIPAddressSection()
}

func (addr *ipAddressInternal) GetNetworkPrefixLength() PrefixLen {
	return addr.GetSection().GetNetworkPrefixLength()
}

func (addr *ipAddressInternal) GetBlockMaskPrefixLength(network bool) PrefixLen {
	return addr.GetSection().GetBlockMaskPrefixLength(network)
}

func (addr *ipAddressInternal) GetSegment(index int) *IPAddressSegment {
	return addr.GetSection().GetSegment(index)
}

//
//
//
//
type IPAddress struct {
	ipAddressInternal
}

func (addr *IPAddress) ToIPv6Address() *IPv6Address {
	if addr != nil && addr.IsIPv6() {
		return (*IPv6Address)(unsafe.Pointer(addr))
	}
	return nil
}

func (addr *IPAddress) ToIPv4Address() *IPv4Address {
	if addr != nil && addr.IsIPv4() {
		return (*IPv4Address)(unsafe.Pointer(addr))
	}
	return nil
}

// TODO make sure everything in IPv4 and IPv6 is "overridden", in the sense all methods will check for no divisions and
// create the default zero-segments if necessary, so we never expose a zero value with 0 segments
// The zero values of everythign else will have sections with no segments

// IDEAS for replacing virtual methods:
// 1. one way around it is the use of interfaces, where you pass things down on construction of higher type,
// providing a pathway back into the higher type
// in fact, that is sort of clever, a lower type has an interface pointing to itself, but that interface can be substituted
//
// 2. it's clever but easy to get confused with that, another technique is function pointers
//
// 3. another way is a dup method of same name in higher type that calls down to the lower, so lower does not have to call up
// Kinda like overriding and works fine when calling from the higher
// Sub has x(), Base has x(), sub x calls Base x
//	This one is natural
//
// both 1,2 require "New" methods, 3 does not

//package main
//
//
//type Foo interface {
//	foo()
//	bla()
//}
//
//type B struct {
//}
//
//func (B) foo() {
//}
//
//type C struct { Works
//	B
//}
//type C struct { Also Works!
//	*B
//}
//
//func (*C) bla() {
//}
//
//func main() {
//	var f Foo = &C{}
//	f.bla()
//	f.foo()
//}
