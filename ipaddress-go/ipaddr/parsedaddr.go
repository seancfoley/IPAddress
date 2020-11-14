package ipaddr

// TODO note that the way that you save substrings for segments in Java is perfect for go, so your address creator interfaces will keep it

type ParsedIPAddress struct {
	IPAddressParseData

	ipAddrProvider

	//TODO ParsedIPAddress

	options    IPAddressStringParameters
	originator HostIdentifierString
	//values TranslatedResult<?,?>  //TODO
	//skipContains *bool
	//maskers, mixedMaskers []Masker//TODO
}

func (parseData *ParsedIPAddress) providerCompare(other IPAddressProvider) (int, IncompatibleAddressException) {
	return providerCompare(parseData, other)
}

func (parseData *ParsedIPAddress) providerEquals(other IPAddressProvider) (bool, IncompatibleAddressException) {
	return providerEquals(parseData, other)
}

func (parseData *ParsedIPAddress) isProvidingMixedIPv6() bool {
	return parseData.IPAddressParseData.isProvidingMixedIPv6()
}

func (parseData *ParsedIPAddress) isProvidingIPv6() bool {
	return parseData.IPAddressParseData.isProvidingIPv6()
}

func (parseData *ParsedIPAddress) isProvidingIPv4() bool {
	return parseData.IPAddressParseData.isProvidingIPv4()
}

func (parseData *ParsedIPAddress) isProvidingBase85IPv6() bool {
	return parseData.IPAddressParseData.isProvidingBase85IPv6()
}

func (parseData *ParsedIPAddress) getProviderIPVersion() IPVersion {
	return parseData.IPAddressParseData.getProviderIPVersion()
}

func (parseData *ParsedIPAddress) getType() IPType {
	return fromVersion(parseData.getProviderIPVersion())
}

func (parseData *ParsedIPAddress) getIPAddressParseData() *IPAddressParseData {
	return &parseData.IPAddressParseData
}

func createAllAddress(
	version IPVersion,
	qualifier *ParsedHostIdentifierStringQualifier,
	originator HostIdentifierString,
	options IPAddressStringParameters) *IPAddress {
	//TODO
	return nil
}
