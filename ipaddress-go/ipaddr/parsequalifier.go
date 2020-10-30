package ipaddr

type IPAddressProvider interface {
	//TODO IPAddressProvider
}

type MACAddressProvider interface {
	//TODO MACAddressProvider
}

// TODO note that the way that you save substrings for segments in Java is perfect for go, so your address creator interfaces will keep it

type ParsedIPAddress struct {
	IPAddressParseData

	//TODO ParsedIPAddress

	options    IPAddressStringParameters
	originator HostIdentifierString
	//values TranslatedResult<?,?>  //TODO
	skipContains *bool
	//maskers, mixedMaskers []Masker//TODO
}

func (parseData *ParsedIPAddress) getIPAddressParseData() *IPAddressParseData {
	return &parseData.IPAddressParseData
}

type EmbeddedAddress struct {
	isUNCIPv6Literal, isReverseDNS bool

	addressStringException AddressStringException

	addressProvider IPAddressProvider
}

var (
	NO_EMBEDDED_ADDRESS *EmbeddedAddress                     = &EmbeddedAddress{}
	NO_QUALIFIER        *ParsedHostIdentifierStringQualifier = &ParsedHostIdentifierStringQualifier{}
)

type ParsedHost struct { //TODO this needs its own file
	normalizedLabels []string
	separatorIndices []int
	normalizedFlags  []bool

	labelsQualifier *ParsedHostIdentifierStringQualifier
	service         string

	embeddedAddress *EmbeddedAddress

	host, originalStr string
}

type ParsedMACAddress struct {
	MACAddressParseData

	//TODO ParsedMACAddress

	originator HostIdentifierString
	//address *MACAddress //TODO
}

func cachePorts(i int) Port {
	//TODO caching
	return Port(&i)
}

func cacheBits(i int) PrefixLen {
	//TODO caching
	bits := BitCount(i)
	return PrefixLen(&bits)
}

type ParsedHostIdentifierStringQualifier struct {
	//if there is a prefix length for the address, this will be its numeric value
	networkPrefixLength PrefixLen //non-nil for a prefix-only address, sometimes non-nil for IPv4, IPv6

	//if there is a port for the host, this will be its numeric value
	port    Port    //non-nil for a host with port
	service Service //non-nil for host with a service instead of a port

	// If instead of a prefix length a mask was provided, this is the mask.
	// We can also have both a prefix length and mask if one is added when merging qualifiers  */'
	mask *ParsedIPAddress

	// overrides the parsed mask if present
	mergedMask *IPAddress

	// this is the IPv6 scope id or network interface name
	zone Zone
}

func (parsedQual *ParsedHostIdentifierStringQualifier) overrideMask(other *ParsedHostIdentifierStringQualifier) {
	if other.mask != nil {
		parsedQual.mask = other.mask
	}

}

//TODO make these types private later
func (parsedQual *ParsedHostIdentifierStringQualifier) overridePrefixLength(other *ParsedHostIdentifierStringQualifier) {
	if other.networkPrefixLength != nil {
		parsedQual.networkPrefixLength = other.networkPrefixLength
	}

}

func (parsedQual *ParsedHostIdentifierStringQualifier) overridePrefix(other *ParsedHostIdentifierStringQualifier) {
	parsedQual.overridePrefixLength(other)
	parsedQual.overrideMask(other)
}

func (parsedQual *ParsedHostIdentifierStringQualifier) merge(other *ParsedHostIdentifierStringQualifier) {
	if parsedQual.networkPrefixLength == nil ||
		(other.networkPrefixLength != nil && *other.networkPrefixLength < *parsedQual.networkPrefixLength) {
		parsedQual.networkPrefixLength = other.networkPrefixLength
	}
	if parsedQual.mask == nil {
		parsedQual.mask = other.mask
	}
	//else {
	//TODO mask
	//mergedMask = getMaskLower().mask(other.getMaskLower());
	//}
}

func (parsedQual *ParsedHostIdentifierStringQualifier) getMaskLower() *IPAddress {
	if parsedQual.mergedMask != nil {
		return parsedQual.mergedMask
	}
	//if parsedQual.mask != nil {
	//TODO parsedQual.mask != nil
	//return parsedQual.mask.getValForMask();
	//}
	return nil
}

func (parsedQual *ParsedHostIdentifierStringQualifier) getNetworkPrefixLength() PrefixLen {
	return parsedQual.networkPrefixLength
}

func (parsedQual *ParsedHostIdentifierStringQualifier) getEquivalentPrefixLength() PrefixLen {
	pref := parsedQual.getNetworkPrefixLength()
	if pref == nil {
		mask := parsedQual.getMaskLower()
		_ = mask
		//if mask != nil {
		//	// TODO this too
		//	//pref = mask.getBlockMaskPrefixLength(true)
		//}
	}
	return pref
}

func (parsedQual *ParsedHostIdentifierStringQualifier) getZone() Zone {
	return parsedQual.zone
}

func (parsedQual *ParsedHostIdentifierStringQualifier) getPort() Port {
	return parsedQual.port
}

func (parsedQual *ParsedHostIdentifierStringQualifier) getService() Service {
	return parsedQual.service
}

func (parsedQual *ParsedHostIdentifierStringQualifier) inferVersion(validationOptions IPAddressStringParameters) IPVersion {
	if parsedQual.networkPrefixLength != nil {
		if *parsedQual.networkPrefixLength > IPv4BitCount &&
			!validationOptions.GetIPv4Parameters().AllowsPrefixesBeyondAddressSize() {
			return IPv6
		}
	}
	//else if parsedQual.mask != nil {
	//TODO
	//			if mask.isProvidingIPv6() {
	//				return IPV6;
	//			} else if mask.isProvidingIPv4() {
	//				return IPV4;
	//			}
	//}
	if parsedQual.zone != "" {
		return IPv6
	}
	return UNKNOWN_VERSION
}
