package ipaddr

type ParsedHostIdentifierStringQualifier struct { //TODO rename to non-public

	// if there is a port for the host, this will be its numeric value
	port    Port   // non-nil for a host with port
	service string // non-empty for host with a service instead of a port

	// if there is a prefix length for the address, this will be its numeric value
	networkPrefixLength PrefixLen //non-nil for a prefix-only address, sometimes non-nil for IPv4, IPv6

	// If instead of a prefix length a mask was provided, this is the mask.
	// We can also have both a prefix length and mask if one is added when merging qualifiers  */'
	mask *ParsedIPAddress

	// overrides the parsed mask if present
	mergedMask *IPAddress

	// this is the IPv6 scope id or network interface name
	zone Zone
}

func (parsedQual *ParsedHostIdentifierStringQualifier) clearPortOrService() {
	parsedQual.port = nil
	parsedQual.service = ""
}

//TODO this might end up not being used (I think it might not be needed)
//func (parsedQual *ParsedHostIdentifierStringQualifier) overrideMask(other *ParsedHostIdentifierStringQualifier) {
//	if other.mask != nil {
//		parsedQual.mask = other.mask
//	}
//}
//
////TODO make these types private later - this might end up not being used (I think it might not be needed)
//func (parsedQual *ParsedHostIdentifierStringQualifier) overridePrefixLength(other *ParsedHostIdentifierStringQualifier) {
//	if other.networkPrefixLength != nil {
//		parsedQual.networkPrefixLength = other.networkPrefixLength
//	}
//
//}
//
//TODO this might end up not being used (I think it might not be needed)
//func (parsedQual *ParsedHostIdentifierStringQualifier) overridePrefix(other *ParsedHostIdentifierStringQualifier) {
//	parsedQual.overridePrefixLength(other)
//	parsedQual.overrideMask(other)
//}

func (parsedQual *ParsedHostIdentifierStringQualifier) clearPrefixOrMask() {
	parsedQual.networkPrefixLength = nil
	parsedQual.mask = nil
}

func (parsedQual *ParsedHostIdentifierStringQualifier) merge(other *ParsedHostIdentifierStringQualifier) (err IncompatibleAddressException) {
	if parsedQual.networkPrefixLength == nil ||
		(other.networkPrefixLength != nil && *other.networkPrefixLength < *parsedQual.networkPrefixLength) {
		parsedQual.networkPrefixLength = other.networkPrefixLength
	}
	if parsedQual.mask == nil {
		parsedQual.mask = other.mask
	} else {
		parsedQual.mergedMask, err = parsedQual.getMaskLower().Mask(other.getMaskLower())
	}
	return
}

func (parsedQual *ParsedHostIdentifierStringQualifier) getMaskLower() *IPAddress {
	if mask := parsedQual.mergedMask; mask != nil {
		return mask
	}
	if mask := parsedQual.mask; mask != nil {
		return mask.getValForMask()
	}
	return nil
}

func (parsedQual *ParsedHostIdentifierStringQualifier) getNetworkPrefixLength() PrefixLen {
	return parsedQual.networkPrefixLength
}

func (parsedQual *ParsedHostIdentifierStringQualifier) getEquivalentPrefixLength() PrefixLen {
	pref := parsedQual.getNetworkPrefixLength()
	if pref == nil {
		mask := parsedQual.getMaskLower()
		if mask != nil {
			pref = mask.GetBlockMaskPrefixLength(true)
		}
	}
	return pref
}

func (parsedQual *ParsedHostIdentifierStringQualifier) getZone() Zone {
	return parsedQual.zone
}

func (parsedQual *ParsedHostIdentifierStringQualifier) getPort() Port {
	return parsedQual.port
}

func (parsedQual *ParsedHostIdentifierStringQualifier) getService() string {
	return parsedQual.service
}

func (parsedQual *ParsedHostIdentifierStringQualifier) inferVersion(validationOptions IPAddressStringParameters) IPVersion {
	if parsedQual.networkPrefixLength != nil {
		if *parsedQual.networkPrefixLength > IPv4BitCount &&
			!validationOptions.GetIPv4Parameters().AllowsPrefixesBeyondAddressSize() {
			return IPv6
		}
	} else if mask := parsedQual.mask; mask != nil {
		if mask.isProvidingIPv6() {
			return IPv6
		} else if mask.isProvidingIPv4() {
			return IPv4
		}
	}
	if parsedQual.zone != "" {
		return IPv6
	}
	return INDETERMINATE_VERSION
}
