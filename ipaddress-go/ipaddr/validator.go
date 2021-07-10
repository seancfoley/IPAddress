package ipaddr

const ( //TODO mvove upwards and rename
	MAX_PREFIX = IPv6BitCount //the largest allowed value x for a /x prefix following an address or host name
	//public static final int MAX_PREFIX_CHARS = Integer.toString(MAX_PREFIX).length();
	SMTP_IPV6_IDENTIFIER = "IPv6:"
	IPvFUTURE            = 'v'
)

// Interface for validation and parsing of host identifier strings
type HostIdentifierStringValidator interface {
	validateHostName(fromHost *HostName) (*ParsedHost, HostNameError)

	validateIPAddressStr(fromString *IPAddressString) (IPAddressProvider, AddressStringError)

	validateMACAddressStr(fromString *MACAddressString) (macAddressProvider, AddressStringError)

	validatePrefixLenStr(fullAddr string, version IPVersion) (PrefixLen, AddressStringError)
}

var _ HostIdentifierStringValidator = strValidator{}