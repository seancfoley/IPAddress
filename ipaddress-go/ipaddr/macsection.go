package ipaddr

import (
	"math/big"
	"unsafe"
)

//func (section *ipAddressSectionInternal) GetIPVersion() IPVersion (TODO need the MAC equivalent (ie EUI 64 or MAC 48, butcannot remember if there is a MAC equivalent)
//	if section.IsIPv4() {
//		return IPv4
//	}
//	return IPv6
//}

type MACAddressSection struct {
	addressSectionInternal
}

func (section *MACAddressSection) GetCount() *big.Int {
	return section.cacheCount(func() *big.Int {
		return count(func(index int) uint64 {
			return section.GetSegment(index).GetValueCount()
		}, section.GetSegmentCount(), 6, 0x7fffffffffffff)
	})
}

func (section *MACAddressSection) GetPrefixCount() *big.Int {
	return section.cachePrefixCount(func() *big.Int {
		return section.GetPrefixCountLen(*section.GetPrefixLength())
	})
}

func (section *MACAddressSection) GetPrefixCountLen(prefixLen BitCount) *big.Int {
	if prefixLen <= 0 {
		return bigOne()
	} else if bc := section.GetBitCount(); prefixLen >= bc {
		return section.GetCount()
	}
	networkSegmentIndex := getNetworkSegmentIndex(prefixLen, section.GetBytesPerSegment(), section.GetBitsPerSegment())
	hostSegmentIndex := getHostSegmentIndex(prefixLen, section.GetBytesPerSegment(), section.GetBitsPerSegment())
	return section.calcCount(func() *big.Int {
		return count(func(index int) uint64 {
			if (networkSegmentIndex == hostSegmentIndex) && index == networkSegmentIndex {
				segmentPrefixLength := getPrefixedSegmentPrefixLength(section.GetBitsPerSegment(), prefixLen, index)
				return getPrefixValueCount(section.GetSegment(index).ToAddressSegment(), *segmentPrefixLength)
			}
			return section.GetSegment(index).GetValueCount()
		}, networkSegmentIndex+1, 6, 0x7fffffffffffff)
	})
}

func (section *MACAddressSection) WithoutPrefixLength() *MACAddressSection {
	return section.withoutPrefixLength().ToMACAddressSection()
}

//func (section *MACAddressSection) IsMore(other *MACAddressSection) int {
//	return section.isMore(other.ToAddressDivisionGrouping())
//}

func (section *MACAddressSection) GetSegment(index int) *MACAddressSegment {
	return section.getDivision(index).ToMACAddressSegment()
}

func (section *MACAddressSection) ToAddressSection() *AddressSection {
	return (*AddressSection)(unsafe.Pointer(section))
}

// Gets the subsection from the series starting from the given index
// The first segment is at index 0.
func (section *MACAddressSection) GetTrailingSection(index int) *MACAddressSection {
	return section.GetSubSection(index, section.GetSegmentCount())
}

//// Gets the subsection from the series starting from the given index and ending just before the give endIndex
//// The first segment is at index 0.
func (section *MACAddressSection) GetSubSection(index, endIndex int) *MACAddressSection {
	return section.getSubSection(index, endIndex).ToMACAddressSection()
}

// CopySubSegments copies the existing segments from the given start index until but not including the segment at the given end index,
// into the given slice, as much as can be fit into the slice, returning the number of segments copied
func (section *MACAddressSection) CopySubSegments(start, end int, segs []*MACAddressSegment) (count int) {
	return section.visitSubSegments(start, end, func(index int, div *AddressDivision) bool { segs[index] = div.ToMACAddressSegment(); return false }, len(segs))
}

// CopySubSegments copies the existing segments from the given start index until but not including the segment at the given end index,
// into the given slice, as much as can be fit into the slice, returning the number of segments copied
func (section *MACAddressSection) CopySegments(segs []*MACAddressSegment) (count int) {
	return section.visitSegments(func(index int, div *AddressDivision) bool { segs[index] = div.ToMACAddressSegment(); return false }, len(segs))
}

// GetSegments returns a slice with the address segments.  The returned slice is not backed by the same array as this section.
func (section *MACAddressSection) GetSegments() (res []*MACAddressSegment) {
	res = make([]*MACAddressSegment, section.GetSegmentCount())
	section.CopySegments(res)
	return
}

func (section *MACAddressSection) GetLower() *MACAddressSection {
	return section.getLowestOrHighestSection(true).ToMACAddressSection()
}

func (section *MACAddressSection) GetUpper() *MACAddressSection {
	return section.getLowestOrHighestSection(false).ToMACAddressSection()
}

func (section *MACAddressSection) ToPrefixBlock() *MACAddressSection {
	return section.toPrefixBlock().ToMACAddressSection()
}

func (section *MACAddressSection) ToPrefixBlockLen(prefLen BitCount) *MACAddressSection {
	return section.toPrefixBlockLen(prefLen).ToMACAddressSection()
}

func (section *MACAddressSection) Iterator() MACSectionIterator {
	return macSectionIterator{section.sectionIterator(macType.getCreator(), nil)}
}

func (section *MACAddressSection) PrefixIterator() MACSectionIterator {
	return macSectionIterator{section.prefixIterator(section.getAddrType().getCreator(), false)}
}

func (section *MACAddressSection) PrefixBlockIterator() MACSectionIterator {
	return macSectionIterator{section.prefixIterator(section.getAddrType().getCreator(), true)}
}
