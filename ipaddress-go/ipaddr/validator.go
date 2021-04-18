package ipaddr

const ( //TODO mvove upwards and rename
	MAX_PREFIX = IPv6BitCount //the largest allowed value x for a /x prefix following an address or host name
	//public static final int MAX_PREFIX_CHARS = Integer.toString(MAX_PREFIX).length();
	SMTP_IPV6_IDENTIFIER = "IPv6:"
	IPvFUTURE            = 'v'
)

// Interface for validation and parsing of host identifier strings
type HostIdentifierStringValidator interface {
	validateHostName(fromHost *HostName) (*ParsedHost, HostNameException)

	validateIPAddressStr(fromString *IPAddressString) (IPAddressProvider, AddressStringException)

	validateMACAddressStr(fromString *MACAddressString) (macAddressProvider, AddressStringException)

	validatePrefixLenStr(fullAddr string, version IPVersion) (PrefixLen, AddressStringException)
}

var _ HostIdentifierStringValidator = strValidator{}
