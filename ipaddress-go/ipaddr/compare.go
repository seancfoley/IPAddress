package ipaddr

// TODO on java side, all address items are comparable and implement Comparable<AddressItem>
// IPAddressString implements Comparable<IPAddressString>
// TODO the key will be to ensuring eveything implements AddressItem with: var _ AddressItem = x
//
// public int compare(AddressGenericDivision one, AddressGenericDivision two) {
// public int compare(AddressSegment one, AddressSegment two) {

// public int compare(IPAddressSeqRange one, IPAddressSeqRange two) {

// public int compare(AddressDivisionSeries one, AddressDivisionSeries two) {
// public int compare(AddressSection one, AddressSection two) {

// public int compare(Address one, Address two) {

// covers everything, including IPAddressSeqRange
// public int compare(AddressItem one, AddressItem two) {

// You need interfaces to cover everything.  YOu need methods like GetSegmentValue() SegInt to do it.
// You should also consider the type checks in Java.  Also bit counts.

/*
TODO comparators:
Start with public int compare(AddressItem one, AddressItem two) {
Port only equalsConsistent
Use the same type checks to separate (instead of instanceof use type assertion)
XXXXX how do I handle the virtual calls?  With interface inversion,
xxxxx see IDEAS for replacing virtual methods
use the interface technique

struct AddressComparator {
	typeComp TypedComparator
}

TypedComparator is interface, either ValueComparator or CountComparator

TypedComparator interface {
//	protected abstract int compareParts(AddressDivisionSeries one, AddressDivisionSeries two);
//	protected abstract int compareParts(AddressSection one, AddressSection two);
//	protected abstract int compareValues(BigInteger oneUpper, BigInteger oneLower, BigInteger twoUpper, BigInteger twoLower);
//	protected abstract int compareValues(long oneUpper, long oneLower, long twoUpper, long twoLower);
//	protected abstract int compareValues(int oneUpper, int oneLower, int twoUpper, int twoLower);
}

Need to use interfaces everywhere now for all args

	Need
AddressItem:
	CopyBytes(bytes []byte) []byte
	CopyUpperBytes(bytes []byte) []byte
	GetCount()

// TODO addressSegmentInternal, addressSectionInternal, addressInternal will all have CompareTo(AddressItem)
// which will then be inherited by everything and then you can add it to AddressItem

*/

type componentComparator interface {
	// TODO value and count versions of this interface, then have a singleton for each
	compareSectionParts(one, two *AddressSection) int

	/*
		inside will want this to check if we can use longs
		addrGroup1 := one.(AddressDivisionGroupingType)
			addrGroup2 := one.(AddressDivisionGroupingType)
			oneGrp := addrGroup1.ToAddressDivisionGrouping()
			twoGrp := addrGroup2.ToAddressDivisionGrouping()
	*/
	compareParts(one, two AddressDivisionSeries) int
}

type AddressComparator struct {
	componentComparator
}

const (
	ipv4type          = 4
	ipv6type          = 6
	mactype           = 3
	iptype            = 2
	sectype           = 1
	largegroupingtype = -2
	groupingtype      = -3
)

func mapGrouping(series AddressDivisionSeries) int {
	if grouping, ok := series.(AddressDivisionGroupingType); ok {
		group := grouping.ToAddressDivisionGrouping()
		if group.IsIPv6AddressSection() {
			return ipv6type
			//} else if(series instanceof IPv6v4MixedAddressSection) { TODO
			//		return 5;
			//	}
		} else if group.IsIPv4AddressSection() {
			return ipv4type
		} else if group.IsMACAddressSection() {
			return mactype
		} else if group.IsIPAddressSection() {
			return iptype
		} else if group.isAddressSection() {
			return sectype
		}
		return groupingtype
	} //} else if(series instanceof IPAddressLargeDivisionGrouping) { TODO
	//	return -2;
	//}
	return 0
}

func mapSection(section AddressSectionType) int {
	sect := section.ToAddressSection()
	if sect.IsIPv6AddressSection() {
		return ipv6type
		//} else if(series instanceof IPv6v4MixedAddressSection) { TODO
		//		return 5;
		//	}
	} else if sect.IsIPv4AddressSection() {
		return ipv4type
	} else if sect.IsMACAddressSection() {
		return mactype
	} else if sect.IsIPAddressSection() {
		return iptype
	}
	return sectype
}

func (comp AddressComparator) CompareAddresses(one, two AddressType) int {
	oneAddr := one.ToAddress()
	twoAddr := two.ToAddress()
	result := comp.CompareAddressSections(oneAddr.GetSection(), twoAddr.GetSection())
	if result == 0 {
		if oneIPv6 := oneAddr.ToIPv6Address(); oneIPv6 != nil {
			twoIPv6 := twoAddr.ToIPv6Address()
			oneZone := oneIPv6.zone
			twoZone := twoIPv6.zone
			if oneZone == twoZone {
				return 0
			} else if oneZone < twoZone {
				return -1
			}
			return 1
		}
	}
	return result
}

func (comp AddressComparator) CompareAddressSections(one, two AddressSectionType) int {
	result := mapSection(one) - mapSection(two)
	if result != 0 {
		return result
	}
	oneSec := one.ToAddressSection()
	twoSec := two.ToAddressSection()
	if oneIPv6 := oneSec.ToIPv6AddressSection(); oneIPv6 != nil {
		twoIPv6 := twoSec.ToIPv6AddressSection()
		result = int(oneIPv6.addressSegmentIndex) - int(twoIPv6.addressSegmentIndex)
		if result != 0 {
			return result
		}
	}
	if oneMAC := oneSec.ToMACAddressSection(); oneMAC != nil {
		twoMAC := twoSec.ToMACAddressSection()
		result = int(oneMAC.addressSegmentIndex) - int(twoMAC.addressSegmentIndex)
		if result != 0 {
			return result
		}
	}
	return comp.compareSectionParts(oneSec, twoSec)
}

func (comp AddressComparator) CompareSeries(one, two AddressDivisionSeries) int {
	if addrSeries1, ok := one.(AddressType); ok {
		if addrSeries2, ok := two.(AddressType); ok {
			return comp.CompareAddresses(addrSeries1, addrSeries2)
		}
		return -1
	} else if _, ok := two.(AddressType); ok {
		return 1
	}
	if addrSection1, ok := one.(AddressSectionType); ok {
		if addrSection2, ok := two.(AddressSectionType); ok {
			return comp.CompareAddressSections(addrSection1, addrSection2)
		}
	}
	result := mapGrouping(one) - mapGrouping(two)
	if result != 0 {
		return result
	}
	return comp.compareParts(one, two)
}

func (comp AddressComparator) CompareSegments(one, two AddressGenericSegment) int {
	//TODO
	return 0
}

func (comp AddressComparator) CompareDivisions(one, two AddressGenericDivision) int {
	if addrSeg1, ok := one.(AddressGenericSegment); ok {
		if addrSeg2, ok := two.(AddressGenericSegment); ok {
			return comp.CompareSegments(addrSeg1, addrSeg2)
		}
	}

	//if(!one.getClass().equals(two.getClass())) {
	//	int result = mapDivision(one) - mapDivision(two);
	//	if(result != 0) {
	//		return result;
	//	}
	//}
	//if(equalsConsistent) {
	//	int bitDiff = one.getBitCount() - two.getBitCount();
	//	if(bitDiff != 0) {
	//		return bitDiff;
	//	}
	//}
	//if(one instanceof AddressDivision && two instanceof AddressDivision) {
	//	AddressDivision gOne = (AddressDivision) one;
	//	AddressDivision gTwo = (AddressDivision) two;
	//	return compareValues(gOne.getUpperDivisionValue(), gOne.getDivisionValue(), gTwo.getUpperDivisionValue(), gTwo.getDivisionValue());
	//}
	//return compareValues(one.getUpperValue(), one.getValue(), two.getUpperValue(), two.getValue());

	// TODO next xxx
	//		2a check for AddressGenericSegment with type assertion
	//			then use a mapping to address types (map to type with type switch and ints, then if both same type, use genetic compare(AddressSegment one, two))
	//		2b compare division types (ie mapDivision)
	//		2c check bit diff
	//		2d check for AddressStandardDivision with type assertion
	//			// then use compareValue on all 4 u64 division values, one low/high, two low/high
	//		2e  use compareValue on all 4 bigint division values, one low/high, two low/high
	return 0
}

func (comp AddressComparator) CompareRanges(one, two *IPAddressSeqRange) int {
	//TODO
	return 0
}

func (comp AddressComparator) Compare(one, two AddressItem) int {
	//TODO NEXT the types are ready, time to code...  use same methods as in Java
	// 1. use type assertion with AddressDivisionSeries (DONE), covering all addresses and all groupings, including large
	// 		if true, you want to split off to AddressDivisionSeries
	//		1a check for addresses with AddressType(DONE) type assertion
	//			then use a mapping to address types (map to type with type switch and ints, then if both same type, use generic compare(Address one, two))
	//		1b check for addresSections, using type assertion with AddressSectionType (DONE)
	//			the use mapping to compare address sections (map to type with type switch and ints, then if both same type, use generic compare(AddressSection one, two))
	//		1c compare division series types
	//		1d compare division series for general case when 1c types the same
	//				this checks for both AddressDivisionGroupingType (DONE), so we can use longs,
	//				if either not, then we use bytes and AddressDivisionSeries
	// 2. type assertion for AddressGenericDivision (DONE), covering all divisions, including large
	//		2a check for AddressGenericSegment ( DONE) with type assertion
	//			then use a mapping to address types (map to type with type switch and ints, then if both same type, use genetic compare(AddressSegment one, two))
	//		2b compare division types (ie mapDivision)
	//		2c check bit diff
	//		2d check for AddressStandardDivision ( DONE) with type assertion
	//			// then use compareValue on all 4 u64 division values, one low/high, two low/high
	//		2e  use compareValue on all 4 bigint division values, one low/high, two low/high
	// 3. Go for IPAddressSeqRange
	// 4. compare bit counts
	//
	// So we need:
	// AddressDivisionSeries (split off all division groupings including large)
	// AddressType to convert to Address
	// AddressSectionType to convert to AddressSection
	// AddressDivisionGroupingType (all standard divisons) so we can grab longs when comparing divisions
	// AddressGenericDivision (all divisions including large)
	// AddressGenericSegment to convert to AddressSegment
	// AddressStandardDivision so we can convert to AddressDivision and grab longs when comparing division grouping or divisions
	// IPAddressSeqRangeType (split off all ranges)
	if divSeries1, ok := one.(AddressDivisionSeries); ok {
		if divSeries2, ok := two.(AddressDivisionSeries); ok {
			return comp.CompareSeries(divSeries1, divSeries2)
		} else {
			return 1
		}
	} else if div1, ok := one.(AddressGenericDivision); ok {
		if div2, ok := two.(AddressGenericDivision); ok {
			return comp.CompareDivisions(div1, div2)
		} else {
			return -1
		}
	} else if rng1, ok := one.(*IPAddressSeqRange); ok {
		if rng2, ok := two.(*IPAddressSeqRange); ok {
			return comp.CompareRanges(rng1, rng2)
		} else if _, ok := two.(AddressDivisionSeries); ok {
			return -1
		}
		return 1
	}
	// we've covered all known address items for one, so check two
	if _, ok := two.(AddressDivisionSeries); ok {
		return -1
	} else if _, ok := two.(AddressGenericDivision); ok {
		return 1
	} else if _, ok := two.(*IPAddressSeqRange); ok {
		return -1
	}
	// neither are a known AddressItem type
	return int(one.GetBitCount() - two.GetBitCount())
}
