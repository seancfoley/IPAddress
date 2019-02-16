package ipaddr

import (
	"reflect"
)

//addressdivisiongroupingbase // prefix length, divisions
//ipaddresslargedivisiongrouping
//addressdivisiongrouping
//ipaddressdivisiongrouping
//ipaddresssection
//macaddresssection
//ipv6addressSection
//embeddedipv4addresssection
//ipv6v4mixedaddresssection

////xxxxxxxxxxxxxxxx addressDivisionValues ipAddressDivisionValues ipv4AddressSegmentValues ipv6AddressSegmentValues xxxxxxxxxxxxxxxx
////AddressDivision IPAddressDivision IPAddressSegment IPv4AddressSegment IPv6AddressSegment
////
////We have the same, also IPv6V4MixedAddressSection which has two sections but also mixes them together in one slice as it extends IPAddressDivisiongrouping
////xxxxxxxxxxxxxx

// GenericAddressDivision prevents any upcasting and downcasting
// In some cases, maybe all, the method may already be there, but we must be sure we re-implement it to avoid upcasting and downcasting of divisions as much as possible

// GenericAddressDivision is any division that can be part of the array of divisions in a division grouping
type GenericAddressDivision interface {
	ToDivision() *AddressDivision

	ToIPDivision() *IPAddressDivision

	ToIPSegment() *IPAddressSegment

	toIPv6() *IPv6AddressSegment

	toIPv4() *IPv4AddressSegment
}

type addressDivisionGroupingInternal struct {
	//TODO using divisionType has issues with mixed ipv6v4, where we can downcast, but not upcast.  But do we care?  Anyway, I guess I'd need a magic type to indicate it is ok to go up to mixed.
	//But not sure it is viable anyway, losing the mixed ipv4 section and the mixed ipv6 section.
	//for such cases, I think we would need to actually scan across the divisions to determine if mixed, and then reconstitute each section
	divisionType reflect.Type

	divisions []GenericAddressDivision //zero value is nil with len of 0
}

func (grouping *addressDivisionGroupingInternal) checkIndex(index int) bool {
	return checkIndex(index, len(grouping.divisions))
}

//TODO it is the internal values that really matter, and really we cannot interchange segments with divisions
//but we can interchange address divisions with divisions, can we not?  actually, maybe not.
//if we used ipdivisions in a division grouping,
// and then we upcasted, we could get a division and that division would claim to have a prefix, would it not?
// but the original did not.  we want to avoid groupings suddenly claiming to have something it did not when constructed.
// so maybe no change here.

var (
	addressDivisionType    = reflect.TypeOf((*AddressDivision)(nil)).Elem()
	ipaddressDivisionType  = reflect.TypeOf((*IPAddressDivision)(nil)).Elem()  //TODO rename with capital A
	ipaddressSegmentType   = reflect.TypeOf((*IPAddressSegment)(nil)).Elem()   //TODO rename with capital A
	ipv4addressSegmentType = reflect.TypeOf((*IPv4AddressSegment)(nil)).Elem() //TODO rename with capital A
	ipv6addressSegmentType = reflect.TypeOf((*IPv6AddressSegment)(nil)).Elem() //TODO rename with capital A
)

func (grouping *addressDivisionGroupingInternal) assignDefaultValues() {
	if grouping.divisionType == nil {
		grouping.divisionType = addressDivisionType
	}
}

// ToIPDivisionGrouping() converts this division grouping to an IPAddressDivisionGrouping
func (grouping *addressDivisionGroupingInternal) toIPDivisionGrouping() *IPAddressDivisionGrouping {
	grouping.assignDefaultValues()
	switch grouping.divisionType {
	case ipaddressDivisionType, ipaddressSegmentType, ipv4addressSegmentType, ipv6addressSegmentType:
		return &IPAddressDivisionGrouping{ipaddressDivisionGroupingInternal{*grouping}}
	default:
		return nil
	}
}

// ToIPSection() converts this division grouping to an IPAddressSection
func (grouping *addressDivisionGroupingInternal) toIPSection() *IPAddressSection {
	grouping.assignDefaultValues()
	switch grouping.divisionType {
	case ipaddressSegmentType, ipv4addressSegmentType, ipv6addressSegmentType:
		return &IPAddressSection{ipAddressSectionInternal{ipaddressDivisionGroupingInternal{*grouping}}}
	default:
		return nil
	}
}

// ToIPv4() converts this division grouping to an IPv4 section if it originated as an IPv4 section, otherwise it returns nil
func (grouping *addressDivisionGroupingInternal) toIPv4() *IPv4AddressSection {
	grouping.assignDefaultValues()
	if grouping.divisionType == ipv4addressSegmentType {
		return &IPv4AddressSection{ipv4AddressSectionInternal{ipAddressSectionInternal{ipaddressDivisionGroupingInternal{*grouping}}}}
	}
	return nil
}

// ToIPv6() converts this division grouping to an IPv6 section if it originated as an IPv6 section, otherwise it returns nil
func (grouping *addressDivisionGroupingInternal) toIPv6() *IPv6AddressSection {
	grouping.assignDefaultValues()
	if grouping.divisionType == ipv6addressSegmentType {
		return &IPv6AddressSection{ipv6AddressSectionInternal{ipAddressSectionInternal{ipaddressDivisionGroupingInternal{*grouping}}}}
	}
	return nil
}

type AddressDivisionGrouping struct {
	addressDivisionGroupingInternal
}

// ToIPDivisionGrouping() converts this division grouping to an IPAddressDivisionGrouping
func (grouping *AddressDivisionGrouping) ToIPDivisionGrouping() *IPAddressDivisionGrouping {
	return grouping.toIPDivisionGrouping()
}

// ToIPSection() converts this division grouping to an IPAddressSection
func (grouping *AddressDivisionGrouping) ToIPSection() *IPAddressSection {
	return grouping.toIPSection()
}

// ToIPv4() converts this division grouping to an IPv4 section if it originated as an IPv4 section, otherwise it returns nil
func (grouping *AddressDivisionGrouping) ToIPv4() *IPv4AddressSection {
	return grouping.toIPv4()
}

// ToIPv6() converts this division grouping to an IPv6 section if it originated as an IPv6 section, otherwise it returns nil
func (grouping *AddressDivisionGrouping) ToIPv6() *IPv6AddressSection {
	return grouping.toIPv6()
}

func (grouping *AddressDivisionGrouping) GetDivisionCount() int {
	return len(grouping.divisions)
}

// GetDivision returns the division at the given index, or nil if the index is out of bounds.
func (grouping *AddressDivisionGrouping) GetDivision(index int) (seg *AddressDivision) {
	if grouping.checkIndex(index) {
		seg = grouping.divisions[index].ToDivision()
	}
	return
}

// We avoid using errors when validating section/division indices.  We also avoid a bool to indicate not in bounds (like type assertion and maps).
// Errors and bools force people to do someting with them, and frankly, good programs should not have to.
// We could put a panic here, but panic is a heavy-handed result, panic should be avoided if possible.
// Now, it's true that panic results from out-of-bounds on slices, but with slices there is no associated value that you could return.
// With slices the zero-value changes from one slice to another, and not only that, a slice might even have a zero value inside it, such as with []int.
// So there is no other option but panic.
// But here, we do have another option: nil
// So we go with that instead, nil is returned when out of bounds.
func checkIndex(index, count int) bool {
	return index >= 0 && index < count
}

//func (grouping *AddressDivisionGrouping) ToDivisionGrouping() *AddressDivisionGrouping {
//	return grouping
//}

//TODO duplication of functionality in methods: it seems to make more sense that you do not expose
//A-GetSegment() and GetDivision() on the same type
//-maybe for GetValue() it is different because of interfac AddressItem which we expect to use
//B-ToDivision, ToIPDivision, ToIPSegment could potentially be in an interface, but if not, having ToIPDivision on IPAddressDivision returning the equivalent of "this" is unnecessary
//Maybe in a given interface you could add to the interface ToDivision, and then when you have the division you can access all the ToXXX() methods
//This might make more sense with sections
// That would be AddressDivisionSeries returning AddressDivision or AddressGenericDivision from GetDivision and also having ToAddressDivisionGrouping
// That would be IPAddressDivisionSeries returning IPAddressDivision or IPAddressGenericDivision from GetIPDivision and also having ToIPAddressDivisionGrouping
// That would also have AddressGenericDivision with ToAddressDivision
// That would also have IPAddressGenericDivision with ToIPAddressDivision
// However, since AddressSegmentSeries and IPAddressSegmentSeries cover both addresses and sections, a ToXXXSection seems inappropriate

//OK, we had the AddressSegmentSeries and IPAddressSegmentSeries, for commonality between addresses and sections
//AddressDivisionSeries, for what?  AddressDivisionGrouping and all other groupings covered by other interfaces
//AddressSection, for MAC and IP address sections
//AddressSegment, for MAC and IP address segments
//AddressGenericDivision, IPAddressGenericDivision, for the division types returned from the address series interfaces
//AddressComponent - bridges the segments with the segment series (address and section)
//AddressItem - a generic value
//IPAddressRange

//OK, so we have interfaces to bridge different types of thing (section vs address, or segment vs section vs address)
//We have interfaces to go across IP to MAC and other
//We have a base one in AddressItem, a base range in IPAddressRange
//Finally, the ones that could potentially represent hierarchies are IP/AddressGenericDivision and IP/AddressDivisionSeries
//those really have mostly prefix stuff and block stuff
//you're not gonna have both segment and division stuff in those such as getSegment and getDivision and getXXXCount()
//But you could have the ToXXX() in those, but is there a point in that, rather than using the struct types?  Gives a route to the struct types I guess, but for that you just need toDivisionXXX and toIPDivisionXXX
//We really don't have interfaces for things that would be done with casting
//So really, those various methods above are just not interface material and we should not really duplicate stuff
// So let's clean that up, in java mostly an artifact of the subclassing, but we can avoid it now
//Do A and B (A is no more duplicate segment - division stuff, B is not more returning "this" with a ToXXX(), which will require moving the public ToXXX from the internal stuff, they have to become private

// if we use the same name, ie getSegment, that has an impact on whether it can be added to one of our interfaces
// However, You may wish to diverge from Java and use different names when the return type is different
//That also means you want to expose the parent class GetSegments too

// you want to have just a single getSegment method per type.  You will also have the ToIPv4(), ToIPSection, ToIPDivisionGrouping, ToDivisionGrouping, just like for divisions.
//So just a single method for horizontal but then you have all the vertical methods.
