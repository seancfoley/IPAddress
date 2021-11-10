package ipaddr

type parsedHostIdentifierStringQualifier struct {

	// if there is a port for the host, this will be its numeric value
	port    Port   // non-nil for a host with port
	service string // non-empty for host with a service instead of a port

	// if there is a prefix length for the address, this will be its numeric value
	networkPrefixLength PrefixLen //non-nil for a prefix-only address, sometimes non-nil for IPv4, IPv6

	// If instead of a prefix length a mask was provided, this is the mask.
	// We can also have both a prefix length and mask if one is added when merging qualifiers  */'
	mask *parsedIPAddress

	// overrides the parsed mask if present
	mergedMask *IPAddress

	// this is the IPv6 scope id or network interface name
	zone    Zone
	isZoned bool
}

func (parsedQual *parsedHostIdentifierStringQualifier) clearPortOrService() {
	parsedQual.port = nil
	parsedQual.service = ""
}

func (parsedQual *parsedHostIdentifierStringQualifier) clearPrefixOrMask() {
	parsedQual.networkPrefixLength = nil
	parsedQual.mask = nil
}

func (parsedQual *parsedHostIdentifierStringQualifier) merge(other *parsedHostIdentifierStringQualifier) (err IncompatibleAddressError) {
	if parsedQual.networkPrefixLength == nil ||
		(other.networkPrefixLength != nil && *other.networkPrefixLength < *parsedQual.networkPrefixLength) {
		parsedQual.networkPrefixLength = other.networkPrefixLength
	}
	if parsedQual.mask == nil {
		parsedQual.mask = other.mask
	} else {
		otherMask := other.getMaskLower()
		if otherMask != nil {
			parsedQual.mergedMask, err = parsedQual.getMaskLower().Mask(otherMask)
		}
	}
	return
}

func (parsedQual *parsedHostIdentifierStringQualifier) getMaskLower() *IPAddress {
	if mask := parsedQual.mergedMask; mask != nil {
		return mask
	}
	if mask := parsedQual.mask; mask != nil {
		return mask.getValForMask()
	}
	return nil
}

func (parsedQual *parsedHostIdentifierStringQualifier) getNetworkPrefixLen() PrefixLen {
	return parsedQual.networkPrefixLength
}

func (parsedQual *parsedHostIdentifierStringQualifier) getEquivalentPrefixLen() PrefixLen {
	pref := parsedQual.getNetworkPrefixLen()
	if pref == nil {
		mask := parsedQual.getMaskLower()
		if mask != nil {
			pref = mask.GetBlockMaskPrefixLen(true)
		}
	}
	return pref
}

func (parsedQual *parsedHostIdentifierStringQualifier) setZone(z *Zone) {
	//xxxx we must distinguish callers with empty zones vs callers in which there was no zone indicator
	//former: parseEncodedZone, parseZone
	//xxxx parsePrefix is the culprit, some callers have zones, some have none
	//xxxx we never actually encounter zones when parsing prefixes and ports and so on
	//xxxx isZoned in parseData can tell us
	//xxxx this issue unique to golang because no null string, just empty
	//xxxxx so how do we distonguish?  pointers?  that should work

	if z != nil {
		parsedQual.zone = *z
		//parsedQual.isZoned = !z.IsEmpty()
		parsedQual.isZoned = true // parseValidatedPrefix call is our issue
	}
}

func (parsedQual *parsedHostIdentifierStringQualifier) getZone() Zone {
	return parsedQual.zone
}

func (parsedQual *parsedHostIdentifierStringQualifier) getPort() Port {
	return parsedQual.port
}

func (parsedQual *parsedHostIdentifierStringQualifier) getService() string {
	return parsedQual.service
}

func (parsedQual *parsedHostIdentifierStringQualifier) inferVersion(validationOptions IPAddressStringParameters) IPVersion {
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
	if parsedQual.isZoned {
		//if parsedQual.zone != "" {
		return IPv6
	}
	return IndeterminateIPVersion
}
