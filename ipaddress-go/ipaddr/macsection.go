package ipaddr

import (
	"unsafe"
)

//
//
//
//
//
//
//
type macAddressSectionInternal struct {
	addressSectionInternal
}

func (section *macAddressSectionInternal) GetSegment(index int) *MACAddressSegment {
	return section.getDivision(index).ToMACAddressSegment()
}

//func (section *ipAddressSectionInternal) GetIPVersion() IPVersion (TODO need the MAC equivalent (ie EUI 64 or MAC 48, butcannot remember if there is a MAC equivalent)
//	if section.IsIPv4() {
//		return IPv4
//	}
//	return IPv6
//}

type MACAddressSection struct {
	macAddressSectionInternal
}

func (section *MACAddressSection) GetSegment(index int) *MACAddressSegment {
	return section.getDivision(index).ToMACAddressSegment()
}

func (section *MACAddressSection) ToAddressSection() *AddressSection {
	return (*AddressSection)(unsafe.Pointer(section))
}

//// Gets the subsection from the series starting from the given index and ending just before the give endIndex
//// The first segment is at index 0.
func (section *MACAddressSection) GetSubSection(index, endIndex int) *MACAddressSection {
	return section.getSubSection(index, endIndex).ToMACAddressSection()
}

//// ForEachSegment calls the given callback for each segment, terminating early if a callback returns true
//func (section *MACAddressSection) ForEachSegment(callback func(index int, segment *MACAddressSegment) (stop bool)) {
//	section.visitSegments(
//		func(index int, div *AddressDivision) bool {
//			return callback(index, div.ToMACAddressSegment())
//		},
//		section.GetSegmentCount())
//}

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
