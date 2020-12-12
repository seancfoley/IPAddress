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

func (addr *ipAddressInternal) isIPv4() bool {
	return addr.section.matchesIPv4Address()
}

func (addr *ipAddressInternal) isIPv6() bool {
	return addr.section.matchesIPv6Address()
}

func (addr *ipAddressInternal) GetIPVersion() IPVersion {
	if addr.isIPv4() {
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

func (addr *IPAddress) GetLower() *IPAddress {
	return addr.ToAddress().GetLower().ToIPAddress()
}

func (addr *IPAddress) GetUpper() *IPAddress {
	return addr.ToAddress().GetUpper().ToIPAddress()
}

func (addr *IPAddress) IsIPv4() bool {
	return addr.isIPv4()
}

func (addr *IPAddress) IsIPv6() bool {
	return addr.isIPv6()
}

// this makes no sense in the golang world, since it cannot be customized since not virtual
// gave a lot of thought to this, you cannot stick a converted object in each and every address,
// and so there really is no way to do this internally
//func (addr *IPAddress) IsIPv6Convertible() bool {
//	return addr.getConverter().IsIPv6Convertible(addr)
//}
//
//func (addr *IPAddress) IsIPv4Convertible() bool {
//	return addr.getConverter().IsIPv4Convertible(addr)
//}

func (addr *IPAddress) ToIPv6Address() *IPv6Address {
	if addr != nil {
		if addr.isIPv6() {
			return (*IPv6Address)(unsafe.Pointer(addr))
		}
		//TODO consider allowing IPv4-mapped, see waht golang does, but consider we might not be ipv4 or ipv6 if zero-valued
		//return addr.cache.network.(IPAddressNetwork).GetConverter().ToIPv6(addr)
	}
	return nil
}

func (addr *IPAddress) ToIPv4Address() *IPv4Address {
	if addr != nil {
		if addr.isIPv4() {
			return (*IPv4Address)(unsafe.Pointer(addr))
		}
		//return addr.cache.network.(IPAddressNetwork).GetConverter().ToIPv4(addr)
	}
	return nil
}

func (addr *IPAddress) SpanWithRange(other *IPAddress) *IPAddressSeqRange {
	if addr.IsIPv4() {
		if oth := other.ToIPv4Address(); oth != nil {
			return addr.ToIPv4Address().SpanWithRange(oth).ToIPAddressSeqRange()
		}
	} else if addr.IsIPv6() {
		if oth := other.ToIPv6Address(); oth != nil {
			return addr.ToIPv6Address().SpanWithRange(oth).ToIPAddressSeqRange()
		}
	}
	return nil
}

func (addr *IPAddress) Mask(other *IPAddress) *IPAddress {
	if addr.IsIPv4() {
		if oth := other.ToIPv4Address(); oth != nil {
			return addr.ToIPv4Address().Mask(oth).ToIPAddress()
		}
	} else if addr.IsIPv6() {
		if oth := other.ToIPv6Address(); oth != nil {
			return addr.ToIPv6Address().Mask(oth).ToIPAddress()
		}
	}
	return nil
}

//xxxxxxxx how to override conversion? xxxxxx
//- somehow get a converter into the cache?  But cache is per ipaddress
//- pass in a coverter func?  But do you want to do that everywhere? ie mask, span, etc?
//- put it in network obj?  But how do we customize network obj?
//- somehow like java where you can override with your type?
//- so far passing in arg seems the primary option, maybe you can pass in a single arg that encapsulates addr and converter?
//OR pass in converter with "New"
//Makes more sense to add to "New" of network
//I think perhaps user constructs their own network, then constructs addrs with that
//you really want to point to only one shared thing
//But that is tricky.  You kinda want something associated with the type and not every instance
//Maybe I do New through the network.  Which I already do really with the creators.
//	Yes.
//	I like that.
//	TODO converters: So, how bout the details?
//   User constructs an ipv4 network, wants to define ipv6 conversion,
//	calls setConverter on the network object, converted implements our converter interface, the converter must define : isIPv4Convertible(*IPAddress), isIPv6Convertible(*IPAddress), toIPv6(*IPAddress), toIPv4(*IPAddress)
//	And the network, which is an interface (probably, not sure, we need it to supply its own creator and so on), must satisfy getCreator, and the creator for that network will always associate any addresses creaed with the same network
//	This also allows you to associate the network of anything created by the converter by simply making toIPv6 to use a creator from  your own ipv6 network.
//	In other words, the converter will be aware of its associated network objects and use their creators.
//	When a creator creates an ip address, it will insert the associated network into the cache of the address.
//	When a method like mask or span has an IPAddress arg, it will grab the converter from that network obj to do the conversion.
//	So it all works.  Yay.

//TODO I need to NOT use my own ipv6/ipv4/mac converters directly!  Must use an interface.
// BUT this is a problem with the "internal" methods.  We cannot allow access to the arrays and other things intended to be "internal"
// But that is OK!  the internal methods use "New"/consructor methods accessible only to me.
// So others cannot use it.  But others must be able to implement.
// I think you expose them all and you "expect" users to obey the rules.
//
// In any case, we must allow uses to create their own creators so we must use interfaces.

func (addr *IPAddress) ToSequentialRange() *IPAddressSeqRange {
	if addr != nil {
		if addr.IsIPv4() {
			return addr.ToIPv4Address().ToSequentialRange().ToIPAddressSeqRange()
		} else if addr.IsIPv6() {
			return addr.ToIPv6Address().ToSequentialRange().ToIPAddressSeqRange()
		}
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
// 2. it's clever but easy to get confused with that. Another technique is function pointers
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
