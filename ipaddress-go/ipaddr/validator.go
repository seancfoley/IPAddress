package ipaddr

import "github.com/seancfoley/ipaddress/ipaddress-go/ipaddr/addrerr"

const (
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
