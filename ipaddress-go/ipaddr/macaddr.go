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
	// TODO reinstate
	//div := NewMACSegment(0).ToAddressDivision()
	//segs := []*AddressDivision{div, div, div, div, div, div, div, div}
	//section, _ := newMACAddressSection(segs, false)
	//zeroMAC = NewMACAddress(section)
}

type MACAddress struct {
	addressInternal
}

func (addr *MACAddress) ToAddress() *Address {
	if addr == nil {
		return nil
	}
	addr = addr.init()
	return (*Address)(unsafe.Pointer(addr))
}

func (addr *MACAddress) init() *MACAddress {
	if addr.section == nil {
		return zeroMAC
	}
	return addr

}

//func (addr *MACAddress) IsSequential() bool {
//	addr = addr.init()
//	return addr.addressInternal.IsSequential()
//}

func (addr *MACAddress) GetSegment(index int) *MACAddressSegment {
	addr = addr.init()
	return addr.getSegment(index).ToMACAddressSegment()
}
