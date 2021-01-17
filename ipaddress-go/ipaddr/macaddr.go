package ipaddr

import "unsafe"

const (
	//IPv4SegmentSeparator             = '.'
	MACBitsPerSegment  = 8
	MACBytesPerSegment = 1
	//IPv4SegmentCount                 = 4
	//IPv4ByteCount                    = 4
	//IPv4BitCount             = 32
	MACDefaultTextualRadix      = 16
	MACMaxValuePerSegment       = 0xff
	MACMaxValuePerDottedSegment = 0xffff
	//IPv4MaxValue                 = 0xffffffff

	MediaAccessControlSegmentCount         = 6
	MediaAccessControlDottedSegmentCount   = 3
	MediaAccessControlDotted64SegmentCount = 4
	ExtendedUniqueIdentifier48SegmentCount = MediaAccessControlSegmentCount
	ExtendedUniqueIdentifier64SegmentCount = 8

	MACSegmentMaxChars = 2
)

func NewMACAddress(section *MACAddressSection) *MACAddress {
	return &MACAddress{
		//ipAddressInternal{
		addressInternal{
			section: section.ToAddressSection(),
			cache:   &addressCache{},
		},
		//},
	}
	//if addr.hasNoDivisions() {
	//	div := NewIPv4Segment(0).ToAddressDivision()
	//	addr.section = AddressSection{
	//		addressSectionInternal{
	//			addressDivisionGroupingInternal{
	//				divisions: []*AddressDivision{div, div, div, div},
	//				cache:     &valueCache{addrType: macAddrType},
	//			},
	//		},
	//	}
	//}
}

var zeroMAC *MACAddress

func init() {
	// TODO reinstate when all these methods are in place
	//div := NewMACSegment(0).ToAddressDivision()
	//segs := []*AddressDivision{div, div, div, div, div, div, div, div}
	//section, _ := newMACAddressSection(segs, false)
	//zeroMAC = NewMACAddress(section)
}

type MACAddress struct {
	addressInternal
}

func (addr *MACAddress) ToAddress() *Address {
	if addr != nil {
		addr = addr.init()
	}
	return (*Address)(unsafe.Pointer(addr))
}

func (addr *MACAddress) init() *MACAddress {
	if addr.section == nil {
		return zeroMAC
	}
	return addr
}

func (addr *MACAddress) GetSection() *MACAddressSection {
	return addr.init().section.ToMACAddressSection()
}

// Gets the subsection from the series starting from the given index
// The first segment is at index 0.
func (addr *MACAddress) GetTrailingSection(index int) *MACAddressSection {
	return addr.GetSection().GetTrailingSection(index)
}

//// Gets the subsection from the series starting from the given index and ending just before the give endIndex
//// The first segment is at index 0.
func (addr *MACAddress) GetSubSection(index, endIndex int) *MACAddressSection {
	return addr.GetSection().GetSubSection(index, endIndex)
}

// CopySubSegments copies the existing segments from the given start index until but not including the segment at the given end index,
// into the given slice, as much as can be fit into the slice, returning the number of segments copied
func (addr *MACAddress) CopySubSegments(start, end int, segs []*MACAddressSegment) (count int) {
	return addr.GetSection().CopySubSegments(start, end, segs)
}

// CopySubSegments copies the existing segments from the given start index until but not including the segment at the given end index,
// into the given slice, as much as can be fit into the slice, returning the number of segments copied
func (addr *MACAddress) CopySegments(segs []*MACAddressSegment) (count int) {
	return addr.GetSection().CopySegments(segs)
}

// GetSegments returns a slice with the address segments.  The returned slice is not backed by the same array as this address.
func (addr *MACAddress) GetSegments() []*MACAddressSegment {
	return addr.GetSection().GetSegments()
}

func (addr *MACAddress) GetSegment(index int) *MACAddressSegment {
	return addr.init().getSegment(index).ToMACAddressSegment()
}

func (addr *MACAddress) ToPrefixBlock() *MACAddress {
	return addr.init().toPrefixBlock().ToMACAddress()
}
