package ipaddrold

type AddressSection interface {
	//TODO ToMacSection() *MacAddressSection

	toIPSection() *IPAddressSection

	toIPv6() *IPv6AddressSection

	toIPv4() *IPv4AddressSection
}

type values interface {
	//	-stuff that is optional or that changes with section type you might stick in this interface (stuff like zone)
	//	-common stuff, like strings cached like canonicalString, maybe you stick in addressInternal
	//
	//	-since it is embedded, stuff like GetSection can be public and we get for free

	GetSection() AddressSection

	//GetSegment(index int) No need for something like this, just use GetSection().GetSegment()
	//As with divisions, will have GetIPv4Segment, GetIPSegment(), etc as we go up and down the hierarchy

	getZone() string
}

//TODO we do need another set of values.  Why?  Because in golang we cannot stop someone from doing IPAddress{}
//which means we need a default values.
//Do we need ip address default different from address?  We did for section because we will eventually have IPAddressBitsDivisiongrouping which will need its own values.
//Since that needs divisions, we ned up with ip division values too (default with a prefix added)
//We have no such thing for address.  So no need.
//

//xxx seems we have address division grouping as zero for ipsection along with 0 length divisions xxx
//shoukd we just go with that?  Either that or single division with 1 byte.  Probably the former is better.
//TODO next NEXT NEXT
type addressValues struct {
	*AddressDivisionGrouping //TODO when assigning default values, assign &AddressDivisionGrouping{} here

	//	*IPv6AddressSection ??? xxx need to figure out what this will be, what section do we get when we do IPAddress{} and what we get when we do Address{} - I suppose AddressDivisionGrouping?
	//
	//	xxxx we do need to have a base class Address which holds all the data for subclasses
	//	xxxx so it cannot be an interface, even though you really cannot expect Address{} to mean anything, not IPAddress{}
	//	xxxx but it does need to exist for comparisons and collections of all versions and types of addresses and so on
}

func (values *addressValues) getZone() string {
	return ""
}

func (values *addressValues) GetSection() AddressSection {
	return values.AddressDivisionGrouping
}

type ipv6Values struct {
	zone string
	*IPv6AddressSection
}

func (values *ipv6Values) getZone() string {
	return values.zone
}

func (values *ipv6Values) GetSection() AddressSection {
	return values.IPv6AddressSection
}

//TODO when we do this, we do not get the "free" embedded methods, do we?  So maybe struct is better.
//

// we always use an intermediate type so as not to pollute IPv4AddressSection with getZone() and other address things
// and we always use embedded type so we get the embedded methods for free
type ipv4Values struct {
	*IPv4AddressSection //TODO pointer or not?  Unlike sections pointing to divisions, we are not caching sections.  But we do allow suppying a section when constructing.
}

func (values *ipv4Values) getZone() (zone string) {
	return
}

//func (values *ipv4Values) getIPv4Section() *IPv4AddressSection {
//	return (*IPv4AddressSection)(values)
//}

func (values *ipv4Values) GetSection() AddressSection {
	return values.IPv4AddressSection
}

//TODO this just an example of getting section first and calling method on it, so not all methods need to be in the interface "values"
//For anything IPv4, you want to go toIPv4() right away and deal with the object in pure form but really just calling any method directly on AddressSection does that
//You really only need to call toIPv4 for access to methods that are Ipv4 section only

func (values *ipv4Values) getIPv4Segment(index int) (seg *IPv4AddressSegment) {
	return values.GetSection().toIPv4().GetIPv4Segment(index)
}

type addressInternal struct {
	values //one of ipv6Values, ipv4Values, addressValues (default), ipAddressValues (default with prefix)

	//anything shared goes here, such as strings, and normally we share strings unless zone exists, so we could point to shared strings from section here
	//just try to be consistent with java
}

func (addr addressInternal) assignDefaultValues() {
	if addr.values == nil {
		addr.values = &addressValues{&AddressDivisionGrouping{}}
	}
}

func (addr addressInternal) GetSection() AddressSection {
	addr.assignDefaultValues()
	return addr.values.GetSection()
}

//TODO all of our addresses are not using pointer receivers, maybe should change that later

type Address struct {
	addressInternal
}

type IPAddress struct {
	addressInternal
}

type IPv4Address struct {
	addressInternal
}

func (addr IPv4Address) assignDefaultValues() {
	if addr.values == nil {
		addr.values = &ipv4Values{&IPv4AddressSection{}} //TODO must change this to have 4 segments.  Should that be the zero for IPv4AddressSection? I am leaning towards no and having a common zero for all groupings.
	}
}

func (addr IPv4Address) GetSection() AddressSection {
	addr.assignDefaultValues()
	return addr.values.GetSection()
}

type IPv6Address struct {
	addressInternal
}

func (addr IPv6Address) assignDefaultValues() {
	if addr.values == nil {
		addr.values = &ipv6Values{IPv6AddressSection: &IPv6AddressSection{}} //TODO must change to have 6 segments
	}
}

func (addr IPv6Address) GetSection() AddressSection {
	addr.assignDefaultValues()
	return addr.values.GetSection()
}

func (addr IPv6Address) GetZone() string {
	addr.assignDefaultValues()
	return addr.values.getZone()
}

//TODO access to values always does the nil check and assignDefaultValues()
