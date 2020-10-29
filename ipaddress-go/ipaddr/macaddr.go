package ipaddr

const (
	//IPv4SegmentSeparator             = '.'
	MACBitsPerSegment = 8
	//IPv4BytesPerSegment              = 1
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
