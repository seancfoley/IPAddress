package ipaddr

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

type MACAddress struct {
	addressInternal
}

func (addr *MACAddress) init() {
	if addr.hasNoDivisions() {
		div := NewIPv4Segment(0).ToAddressDivision()
		addr.section = AddressSection{
			addressSectionInternal{
				addressDivisionGroupingInternal{
					divisions: []*AddressDivision{div, div, div, div},
				},
			},
		}
	}
}

func (addr *MACAddress) GetSegment(index int) *MACAddressSegment {
	addr.init()
	return addr.addressInternal.GetSegment(index).ToMACAddressSegment()
}
