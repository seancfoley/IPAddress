package ipaddr

type AddressSegmentCreator interface {
	//createSegmentArray(length int) []*addressDivisionInternal

	createSegment(lower, upper SegInt, segmentPrefixLength PrefixLen) *AddressDivision

	createSegmentInternal(value SegInt, segmentPrefixLength PrefixLen, addressStr string,
		originalVal SegInt, isStandardString bool, lowerStringStartIndex, lowerStringEndIndex int) *AddressDivision

	createRangeSegmentInternal(lower, upper SegInt, segmentPrefixLength PrefixLen, addressStr string,
		originalLower, originalUpper SegInt, isStandardString, isStandardRangeString bool,
		lowerStringStartIndex, lowerStringEndIndex, upperStringEndIndex int) *AddressDivision

	// We are using more exact int types, so you might as well avoid these methods down here if you can
	//createSegment(value SegInt) *AddressDivision
	//
	//createRangeSegment(lower, upper SegInt) *AddressDivision

	createPrefixSegment(value SegInt, segmentPrefixLength PrefixLen) *AddressDivision
	//
	//createRangePrefixSegment(lower, upper SegInt, segmentPrefixLength PrefixLen) *AddressDivision

	getMaxValuePerSegment() SegInt
}

type ParsedAddressCreator interface {
	AddressSegmentCreator
}

type ParsedIPAddressCreator interface {
	createAddressInternalFromSection(*IPAddressSection, Zone, HostIdentifierString) *IPAddress
}
