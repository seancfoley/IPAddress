package ipaddr

import "github.com/seancfoley/ipaddress/ipaddress-go/ipaddr/addrerr"

const (
	//MAX_PREFIX = IPv6BitCount //the largest allowed value x for a /x prefix following an address or host name
	//public static final int MAX_PREFIX_CHARS = Integer.toString(MAX_PREFIX).length();
	SmtpIPv6Identifier = "IPv6:"
	IPvFuture          = 'v'
)

// Interface for validation and parsing of host identifier strings
type HostIdentifierStringValidator interface {
	validateHostName(fromHost *HostName) (*parsedHost, addrerr.HostNameError)

	validateIPAddressStr(fromString *IPAddressString) (ipAddressProvider, addrerr.AddressStringError)

	validateMACAddressStr(fromString *MACAddressString) (macAddressProvider, addrerr.AddressStringError)

	validatePrefixLenStr(fullAddr string, version IPVersion) (PrefixLen, addrerr.AddressStringError)
}

var _ HostIdentifierStringValidator = strValidator{}
