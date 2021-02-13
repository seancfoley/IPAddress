package ipaddr

import (
	"sync/atomic"
	"unsafe"
)

// NewIPAddressString constructs an IPAddressString that will parse the given string according to the given parameters
func NewIPAddressString(str string, params IPAddressStringParameters) *IPAddressString {
	var p *ipAddressStringParameters
	if params == nil {
		p = defaultIPAddrParameters
	} else {
		p = getPrivateParams(params)
	}
	return &IPAddressString{str: str, params: p, ipStringCache: new(ipStringCache)}
}

var defaultIPAddrParameters = &ipAddressStringParameters{}

var zeroIPAddressString = NewIPAddressString("", defaultIPAddrParameters)

type addrData struct {
	addressProvider   IPAddressProvider
	validateException AddressStringException
}

type ipStringCache struct {
	*addrData
}

type IPAddressString struct {
	str    string
	params *ipAddressStringParameters // when nil, default parameters is used, never access this field directly
	*ipStringCache
}

func (ipAddrStr *IPAddressString) init() *IPAddressString {
	if ipAddrStr.ipStringCache == nil {
		return zeroIPAddressString
	}
	return ipAddrStr
}

func (ipAddrStr *IPAddressString) getParams() *ipAddressStringParameters {
	return ipAddrStr.init().params
}

func (ipAddrStr *IPAddressString) GetValidationOptions() IPAddressStringParameters {
	return ipAddrStr.getParams()
}

func (ipAddrStr *IPAddressString) String() string {
	return ipAddrStr.str
}

func (addrStr *IPAddressString) ToNormalizedString() string {
	//TODO IPAddressString
	return ""
}

// IsValid returns whether this is a valid address string format.
// The accepted IP address formats are:
// an IPv4 address, an IPv6 address, the address representing all addresses of all types, or an empty string.
// If this method returns false, and you want more details, call validate() and examine the thrown exception.
func (addrStr *IPAddressString) IsValid() bool {
	return addrStr.ipStringCache == nil /* zero address is valid */ ||
		!addrStr.getAddressProvider().isInvalid()
}

func (addrStr *IPAddressString) GetAddress() *IPAddress {
	addr, _ := addrStr.getAddressProvider().getProviderAddress()
	return addr
}

// error can be AddressStringException or IncompatibleAddressException
func (addrStr *IPAddressString) ToAddress() (*IPAddress, error) {
	return addrStr.getAddressProvider().getProviderAddress()
}

func (addrStr *IPAddressString) GetHostAddress() *IPAddress {
	addr, _ := addrStr.getAddressProvider().getProviderHostAddress()
	return addr
}

// error can be AddressStringException or IncompatibleAddressException
func (addrStr *IPAddressString) ToHostAddress() (*IPAddress, error) {
	return addrStr.getAddressProvider().getProviderHostAddress()
}

// Validates that this string is a valid IPv4 address, and if not, returns an error with a descriptive message indicating why it is not.
func (addrStr *IPAddressString) ValidateIPv4() AddressStringException {
	return addrStr.ValidateVersion(IPv4)
}

// Validates that this string is a valid IPv6 address, and if not, returns an error with a descriptive message indicating why it is not.
func (addrStr *IPAddressString) ValidateIPv6() AddressStringException {
	return addrStr.ValidateVersion(IPv6)
}

var validator strValidator

func (addrStr *IPAddressString) getAddressProvider() IPAddressProvider {
	addrStr = addrStr.init()
	addrStr.Validate()
	return addrStr.addressProvider
}

// Validate validates that this string is a valid address, and if not, throws an exception with a descriptive message indicating why it is not.
func (addrStr *IPAddressString) Validate() AddressStringException {
	addrStr = addrStr.init()
	data := addrStr.addrData
	if data == nil {
		addressProvider, err := validator.validateIPAddressStr(addrStr)
		data = &addrData{addressProvider, err}
		if err != nil {
			data.addressProvider = INVALID_PROVIDER
		}
		dataLoc := (*unsafe.Pointer)(unsafe.Pointer(&addrStr.addrData))
		atomic.StorePointer(dataLoc, unsafe.Pointer(data))
	}
	return data.validateException
}

func (addrStr *IPAddressString) ValidateVersion(version IPVersion) AddressStringException {
	err := addrStr.Validate()
	if version == INDETERMINATE_VERSION {
		return err
	} else {
		addrVersion := addrStr.addressProvider.getProviderIPVersion()
		if version.isIPv4() {
			if !addrVersion.isIPv4() {
				return &addressStringException{str: addrStr.str, key: "ipaddress.error.address.is.ipv6"}
			}
		} else if version.isIPv6() {
			if !addrVersion.isIPv6() {
				return &addressStringException{str: addrStr.str, key: "ipaddress.error.address.is.ipv4"}
			}
		}
	}
	return nil
}

// Contains returns whether the address subnet identified by this address string contains the address identified by the given string.
// If this address string or the given address string is invalid then returns false.
func (addrStr *IPAddressString) Contains(other *IPAddressString) bool {
	if addrStr.IsValid() {
		if other == addrStr {
			return true
		}
		if other.addrData == nil { // other not yet validated - if other is validated no need for this quick contains
			//do the quick check that uses only the String of the other
			//Boolean directResult = addressProvider.contains(other.fullAddr);
			//if(directResult != null) { TODO fast track
			//	return directResult.booleanValue();
			//}
		}
		if other.IsValid() {
			// note the quick result also handles the case of "all addresses"
			//Boolean directResult = addressProvider.contains(other.addressProvider);
			//if(directResult != null) { TODO fast track
			//	return directResult.booleanValue();
			//}
			addr := addrStr.GetAddress()
			if addr != nil {
				otherAddress := other.GetAddress()
				if otherAddress != nil {
					return addr.Contains(otherAddress)
				}
			}
		}
	}
	return false
}

// Two IPAddressString objects are equal if they represent the same set of addresses.
// Whether one or the other has an associated network prefix length is not considered.
//
// If an IPAddressString is invalid, it is equal to another address only if the other address was constructed from the same string.
func (addrStr *IPAddressString) Equals(other *IPAddressString) bool {
	if other == addrStr {
		return true
	}

	// if they have the same string, they must be the same,
	// but the converse is not true, if they have different strings, they can
	// still be the same because IPv6 addresses have many representations
	// and additional things like leading zeros can have an effect for IPv4

	// Also note that we do not call equals() on the validation options, this is intended as an optimization,
	// and probably better to avoid going through all the validation objects here
	stringsMatch := addrStr.String() == other.String()
	if stringsMatch && addrStr.params == other.params {
		return true
	}
	if addrStr.IsValid() {
		if other.IsValid() {
			//Boolean directResult = addressProvider.parsedEquals(other.addressProvider); TODO fast track
			//if(directResult != null) {
			//	return directResult.booleanValue();
			//}

			// When a value provider produces no value, equality and comparison are based on the enum IPType,
			// which can be null.
			addrProvider := addrStr.getAddressProvider()
			equals, err := addrProvider.providerEquals(other.addressProvider)
			if err != nil {
				return stringsMatch
			}
			return equals
		}
	} else if !other.IsValid() {
		return stringsMatch // Two invalid addresses are not equal unless strings match, regardless of validation options
	}
	return false
}

func getPrivateParams(orig IPAddressStringParameters) *ipAddressStringParameters {
	if p, ok := orig.(*ipAddressStringParameters); ok {
		return p
	}
	return ToIPAddressStringParamsBuilder(orig).ToParams().(*ipAddressStringParameters)
}
