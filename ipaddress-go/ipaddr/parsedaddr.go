package ipaddr

// TODO note that the way that you save substrings for segments in Java is perfect for go, so your address creator interfaces will keep it

type ParsedIPAddress struct {
	IPAddressParseData

	ipAddrProvider

	//TODO ParsedIPAddress

	options    IPAddressStringParameters
	originator HostIdentifierString
	//values TranslatedResult<?,?>  //TODO
	skipContains *bool
	//maskers, mixedMaskers []Masker//TODO
}

func (parseData *ParsedIPAddress) getType() IPType {
	return fromVersion(parseData.getProviderIPVersion())
}

func (parseData *ParsedIPAddress) getIPAddressParseData() *IPAddressParseData {
	return &parseData.IPAddressParseData
}
