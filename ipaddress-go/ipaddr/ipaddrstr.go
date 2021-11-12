package ipaddr

import (
	"strings"
	"sync/atomic"
	"unsafe"
)

// NewIPAddressStringParams constructs an IPAddressString that will parse the given string according to the given parameters
func NewIPAddressStringParams(str string, params IPAddressStringParameters) *IPAddressString {
	var p *ipAddressStringParameters
	if params == nil {
		p = defaultIPAddrParameters
	} else {
		p = getPrivateParams(params)
	}
	return &IPAddressString{str: str, params: p, ipAddrStringCache: new(ipAddrStringCache)}
}

// NewIPAddressString constructs an IPAddressString
func NewIPAddressString(str string) *IPAddressString {
	return &IPAddressString{str: str, params: defaultIPAddrParameters, ipAddrStringCache: new(ipAddrStringCache)}
}

func newIPAddressStringFromAddr(str string, addr *IPAddress) *IPAddressString {
	return &IPAddressString{
		str:    str,
		params: defaultIPAddrParameters,
		ipAddrStringCache: &ipAddrStringCache{
			&addrData{
				addressProvider: addr.getProvider(),
			},
		},
	}
}

var validator strValidator

var defaultIPAddrParameters = &ipAddressStringParameters{}

var zeroIPAddressString = NewIPAddressString("")

type addrData struct {
	addressProvider   ipAddressProvider
	validateException AddressStringError
}

type ipAddrStringCache struct {
	*addrData
}

type IPAddressString struct {
	str    string
	params *ipAddressStringParameters // when nil, default parameters is used, never access this field directly
	*ipAddrStringCache
}

func (addrStr *IPAddressString) init() *IPAddressString {
	if addrStr.ipAddrStringCache == nil {
		return zeroIPAddressString
	}
	return addrStr
}

func (addrStr *IPAddressString) getParams() *ipAddressStringParameters {
	return addrStr.init().params
}

func (addrStr *IPAddressString) GetValidationOptions() IPAddressStringParameters {
	return addrStr.getParams()
}

// IsPrefixed returns whether this address string has an associated prefix length.
// If so, the prefix length is given by GetNetworkPrefixLen()
func (addrStr *IPAddressString) IsPrefixed() bool {
	return addrStr.GetNetworkPrefixLen() != nil
}

// If this address is a valid address with an associated network prefix length then this returns that prefix length, otherwise returns null.
// The prefix length may be expressed explicitly with the notation "\xx" where xx is a decimal value, or it may be expressed implicitly as a network mask such as /255.255.0.0
func (addrStr *IPAddressString) GetNetworkPrefixLen() PrefixLen { //TODO rename to GetNetworkPrefixLen
	addrStr = addrStr.init()
	if addrStr.IsValid() {
		return addrStr.addressProvider.getProviderNetworkPrefixLen()
	}
	return nil
}

// GetMask returns the mask, if any, that was provided with this address string
func (addrStr *IPAddressString) GetMask() *IPAddress {
	addrStr = addrStr.init()
	if addrStr.IsValid() {
		return addrStr.addressProvider.getProviderMask()
	}
	return nil
}

// IsAllAddresses returns true if the string represents all IP addresses, such as the string "*"
// You can denote all IPv4 addresses with *.*, or all IPv6 addresses with *:*
func (addrStr *IPAddressString) IsAllAddresses() bool {
	addrStr = addrStr.init()
	return addrStr.IsValid() && addrStr.addressProvider.isProvidingAllAddresses()
}

// IsEmpty() returns true if the address string is empty (zero-length).
func (addrStr *IPAddressString) IsEmpty() bool {
	addrStr = addrStr.init()
	return addrStr.IsValid() && addrStr.addressProvider.isProvidingEmpty()
}

// IsIPv4() returns true if the address is IPv4
func (addrStr *IPAddressString) IsIPv4() bool {
	addrStr = addrStr.init()
	return addrStr.IsValid() && addrStr.addressProvider.isProvidingIPv4()
}

// IsIPv6() returns true if the address is IPv6
func (addrStr *IPAddressString) IsIPv6() bool {
	addrStr = addrStr.init()
	return addrStr.IsValid() && addrStr.addressProvider.isProvidingIPv6()
}

// If this address string represents an IPv6 address, returns whether the lower 4 bytes were represented as IPv4
func (addrStr *IPAddressString) IsMixedIPv6() bool {
	addrStr = addrStr.init()
	return addrStr.IsIPv6() && addrStr.addressProvider.isProvidingMixedIPv6()
}

/* TODO LATER IsBase85IPv6
// IsBase85IPv6 returns whether this address string represents an IPv6 address, returns whether the string was base 85
	func (addrStr *IPAddressString) IsBase85IPv6() bool {
		return addrStr.IsIPv6() && addrStr.addressProvider.isProvidingBase85IPv6()
	}
*/

// GetIPVersion returns the IP address version if {@link #isIPAddress()} returns true, otherwise returns null
func (addrStr *IPAddressString) GetIPVersion() IPVersion {
	if addrStr.IsValid() {
		return addrStr.addressProvider.getProviderIPVersion()
	}
	return IndeterminateIPVersion
}

// Returns whether this string represents a loopback IP address.
func (addrStr *IPAddressString) IsLoopback() bool {
	val := addrStr.GetAddress()
	return val != nil && val.IsLoopback()
}

// Returns whether this string represents an IP address whose value is zero.
func (addrStr *IPAddressString) IsZero() bool {
	value := addrStr.GetAddress()
	return value != nil && value.IsZero()
}

func (addrStr *IPAddressString) String() string {
	return addrStr.str
}

func (addrStr *IPAddressString) ToNormalizedString() string {
	addrStr = addrStr.init()
	if addrStr.IsValid() {
		if str, err := addrStr.toNormalizedString(addrStr.addressProvider); err == nil {
			return str
		}
	}
	return addrStr.String()
}

func (addrStr *IPAddressString) toNormalizedString(addressProvider ipAddressProvider) (result string, err IncompatibleAddressError) {
	if addressProvider.isProvidingAllAddresses() {
		result = SegmentWildcardStr
	} else if addressProvider.isProvidingEmpty() {
		result = ""
	} else if addressProvider.isProvidingIPAddress() {
		var addr *IPAddress
		if addr, err = addressProvider.getProviderAddress(); err == nil {
			result = addr.ToNormalizedString()
		}
	}
	return
}

// IsValid returns whether this is a valid address string format.
// The accepted IP address formats are:
// an IPv4 address, an IPv6 address, the address representing all addresses of all types, or an empty string.
// If this method returns false, and you want more details, call Validate() and examine the thrown exception.
func (addrStr *IPAddressString) IsValid() bool {
	if addrStr.ipAddrStringCache == nil /* zero address is valid */ {
		return true
	}
	provider, err := addrStr.getAddressProvider()
	if err != nil {
		return false
	}
	return !provider.isInvalid()
}

func (addrStr *IPAddressString) GetAddress() *IPAddress {
	provider, err := addrStr.getAddressProvider()
	if err != nil {
		return nil
	}
	addr, _ := provider.getProviderAddress()
	return addr
}

// error can be AddressStringError or IncompatibleAddressError
func (addrStr *IPAddressString) ToAddress() (*IPAddress, AddressError) {
	provider, err := addrStr.getAddressProvider()
	if err != nil {
		return nil, err
	}
	return provider.getProviderAddress()
}

// GetVersionedAddress is similar to ToVersionedAddress, but returns nil rather than an error when the address is invalid or does not match the supplied version.
func (addrStr *IPAddressString) GetVersionedAddress(version IPVersion) *IPAddress {
	provider, err := addrStr.getAddressProvider()
	if err != nil {
		return nil
	}
	addr, _ := provider.getVersionedAddress(version)
	return addr
}

// ToVersionedAddress Produces the IPAddress of the specified address version corresponding to this IPAddressString.
//
// In most cases the string indicates the address version and calling {@link #toAddress()} is sufficient, with a few exceptions.
//
// When this object represents only a network prefix length,
// specifying the address version allows the conversion to take place to the associated mask for that prefix length.
//
// When this object represents all addresses, specifying the address version allows the conversion to take place
// to the associated representation of all IPv4 or all IPv6 addresses.
//
// When this object represents the empty string and that string is interpreted as a loopback or zero address, then it returns
// the corresponding address for the given version.
//
// When this object represents an ipv4 or ipv6 address, it returns that address if and only if that address matches the provided version.
//
// If the string used to construct this object is an invalid format,
// or a format that does not match the provided version, then an error is returned
func (addrStr *IPAddressString) ToVersionedAddress(version IPVersion) (*IPAddress, AddressError) {
	provider, err := addrStr.getAddressProvider()
	if err != nil {
		return nil, err
	}
	return provider.getVersionedAddress(version)
}

func (addrStr *IPAddressString) GetHostAddress() *IPAddress {
	provider, err := addrStr.getAddressProvider()
	if err != nil {
		return nil
	}
	addr, _ := provider.getProviderHostAddress()
	return addr
}

// ToHostAddress parses the address will ignoring the prefix length or mask.  The error can be AddressStringError or IncompatibleAddressError
func (addrStr *IPAddressString) ToHostAddress() (*IPAddress, AddressError) {
	provider, err := addrStr.getAddressProvider()
	if err != nil {
		return nil, err
	}
	return provider.getProviderHostAddress()
}

// IsSequential returns whether the addresses returned by this IPAddressString are sequential,
// meaning that if any address has a numerical value that lies in between the numerical values of two addresses represented by this IPAddressString,
// then that address is also represented by this IPAddressString.  In other words, the represented range of address values is sequential.
//
// When the IPAddressString is sequential, it can be represented exactly by the IPAddressSeqRange returned from {@link #getSequentialRange()}.
// In some cases, no IPAddress instance can be obtained from {@link #getAddress()} or {@link #toAddress()}, in the cases where {@link #toAddress()} throws IncompatibleAddressException,
// but if the IPAddressString is sequential, you can obtain a IPAddressSeqRange to represent the IPAddressString instead.
//func (addrStr *IPAddressString) IsSequential() bool {
//	addrStr = addrStr.init()
//	return addrStr.IsValid() && addrStr.addressProvider.isSequential()
//} // TODO LATER this needs ToAddressDivisionGrouping which we have delayed til later
// Also restore this part of the godoc below:
//
// The sequential range matches the same set of addresses as the address string or the address when {@link #isSequential()} is true.
// Otherwise, the range includes addresses not specified by the address string.
//

// GetSequentialRange returns the range of sequential addresses from the lowest address specified in this address string to the highest.
//
// Since not all IPAddressString instances describe a sequential series of addresses,
// this does not necessarily match the exact set of addresses specified by the string.
// For example, 1-2.3.4.1-2 produces the sequential range 1.3.4.1 to 2.3.4.2 that includes the address 1.255.255.2 not specified by the string.
//
// This method can also produce a range for a string for which no IPAddress instance can be created,
// those cases where IsValid() returns true but ToAddress() returns IncompatibleAddressError and GetAddress() returns null.
// The range cannot be produced for the other cases where GetAddress() returns null
//
// This is similar to ToSequentialRange() except that nil is returned when there is an error.
func (addrStr *IPAddressString) GetSequentialRange() (res *IPAddressSeqRange) {
	res, _ = addrStr.ToSequentialRange()
	return
}

func (addrStr *IPAddressString) ToSequentialRange() (res *IPAddressSeqRange, err AddressStringError) {
	addrStr = addrStr.init()
	if err = addrStr.Validate(); err == nil {
		res = addrStr.addressProvider.getProviderSeqRange()
	}
	return
}

// Validates that this string is a valid IPv4 address, and if not, returns an error with a descriptive message indicating why it is not.
func (addrStr *IPAddressString) ValidateIPv4() AddressStringError {
	return addrStr.ValidateVersion(IPv4)
}

// Validates that this string is a valid IPv6 address, and if not, returns an error with a descriptive message indicating why it is not.
func (addrStr *IPAddressString) ValidateIPv6() AddressStringError {
	return addrStr.ValidateVersion(IPv6)
}

func (addrStr *IPAddressString) getAddressProvider() (ipAddressProvider, AddressStringError) {
	addrStr = addrStr.init()
	err := addrStr.Validate()
	return addrStr.addressProvider, err
}

// Validate validates that this string is a valid address, and if not, returns an error with a descriptive message indicating why it is not.
func (addrStr *IPAddressString) Validate() AddressStringError {
	addrStr = addrStr.init()
	data := addrStr.addrData
	if data == nil {
		addressProvider, err := validator.validateIPAddressStr(addrStr)
		data = &addrData{addressProvider, err}
		if err != nil {
			data.addressProvider = invalidProvider
		}
		dataLoc := (*unsafe.Pointer)(unsafe.Pointer(&addrStr.addrData))
		atomic.StorePointer(dataLoc, unsafe.Pointer(data))
	}
	return data.validateException
}

func (addrStr *IPAddressString) ValidateVersion(version IPVersion) AddressStringError {
	addrStr = addrStr.init()
	err := addrStr.Validate()
	if err != nil {
		return err
	} else if version.IsIndeterminate() {
		return &addressStringError{addressError{str: addrStr.str, key: "ipaddress.error.ipVersionIndeterminate"}}
	} else {
		//addrStr = addrStr.init()
		addrVersion := addrStr.addressProvider.getProviderIPVersion()
		if version.IsIPv4() {
			if addrVersion.IsIPv6() {
				//if !addrVersion.IsIPv4() {
				return &addressStringError{addressError{str: addrStr.str, key: "ipaddress.error.address.is.ipv6"}}
			} else if addrStr.validateException != nil {
				return addrStr.validateException
			}
		} else if version.IsIPv6() {
			if addrVersion.IsIPv4() {
				//if !addrVersion.IsIPv6() {
				return &addressStringError{addressError{str: addrStr.str, key: "ipaddress.error.address.is.ipv4"}}
			} else if addrStr.validateException != nil {
				return addrStr.validateException
			}
		}
	}
	return nil
}

// All address strings are comparable.  If two address strings are invalid, their strings are compared.
// Otherwise, address strings are compared according to which type or version of string, and then within each type or version
// they are compared using the comparison rules for addresses.
func (addrStr *IPAddressString) CompareTo(other *IPAddressString) int {
	//if addrStr == other { //TODO equals nil: consider putting this back https://github.com/google/go-cmp/issues/61 I think I may have stopped because in segments I had to add Equals and CompareTo everywhere
	//	return 0
	//} else if addrStr == nil {
	//	return -1
	//} else if other == nil {
	//	return 1
	//}
	addrStr = addrStr.init()
	other = other.init()
	if addrStr == other {
		return 0
	}

	if addrStr.IsValid() {
		if other.IsValid() {
			if res, err := addrStr.addressProvider.providerCompare(other.addressProvider); err == nil {
				return res
			}
			//addr := addrStr.GetAddress()
			//if addr != nil {
			//	otherAddr := other.GetAddress()
			//	if otherAddr != nil {
			//		return addr.CompareTo(otherAddr)
			//	}
			//}
			// one or the other is null, either empty or IncompatibleAddressException
			return strings.Compare(addrStr.String(), other.String())
		}
		return 1
	} else if other.IsValid() {
		return -1
	}
	return strings.Compare(addrStr.String(), other.String())

	//isValid, otherIsValid := addrStr.IsValid(), other.IsValid()
	//if isValid || otherIsValid {xxx both need to be valid to have addressProviders see mac xxxx
	//	if res, err := addrStr.addressProvider.providerCompare(other.addressProvider); err == nil {
	//		return res
	//	}
	//}
	//return strings.Compare(addrStr.String(), other.String())
}

// Similar to {@link #equals(Object)}, but instead returns whether the prefix of this address matches the same of the given address,
// using the prefix length of this address.
//
// In other words, determines if the other address is in the same prefix subnet using the prefix length of this address.
//
// If an address has no prefix length, the whole address is used as the prefix.
//
// If this address string or the given address string is invalid, returns false.
func (addrStr *IPAddressString) PrefixEquals(other *IPAddressString) bool {
	// getting the prefix
	addrStr = addrStr.init()
	other = other.init()
	if other == addrStr {
		return true
	}
	if !addrStr.IsValid() {
		return false
	}
	if other.isUninitialized() { // other not yet validated - if other is validated no need for this quick contains
		// do the quick check that uses only the String of the other, matching til the end of the prefix length, for performance
		directResult := addrStr.addressProvider.prefixEquals(other.str)
		if directResult.isSet {
			return directResult.val
		}
	}
	if other.IsValid() {
		directResult := addrStr.addressProvider.prefixEqualsProvider(other.addressProvider)
		if directResult.isSet {
			return directResult.val
		}
		thisAddress := addrStr.GetAddress()
		if thisAddress != nil {
			otherAddress := other.GetAddress()
			if otherAddress != nil {
				return thisAddress.prefixEquals(otherAddress)
			}
		}
		// one or both addresses are null, so there is no prefix to speak of
	}
	return false
}

// Similar to {@link #prefixEquals(IPAddressString)}, but instead returns whether the prefix of this address contains the same of the given address,
// using the prefix length of this address.
//
// In other words, determines if the other address is in one of the same prefix subnets using the prefix length of this address.
//
// If an address has no prefix length, the whole address is used as the prefix.
//
// If this address string or the given address string is invalid, returns false.
func (addrStr *IPAddressString) PrefixContains(other *IPAddressString) bool {
	addrStr = addrStr.init()
	other = other.init()
	if other == addrStr {
		return true
	} else if !addrStr.IsValid() {
		return false
	} else if other.isUninitialized() { // other not yet validated - if other is validated no need for this quick contains
		// do the quick check that uses only the String of the other, matching til the end of the prefix length, for performance
		directResult := addrStr.addressProvider.prefixContains(other.str)
		if directResult.isSet {
			return directResult.val
		}
	}
	if other.IsValid() {
		directResult := addrStr.addressProvider.prefixContainsProvider(other.addressProvider)
		if directResult.isSet {
			return directResult.val
		}
		thisAddress := addrStr.GetAddress()
		if thisAddress != nil {
			otherAddress := other.GetAddress()
			if otherAddress != nil {
				return thisAddress.prefixContains(otherAddress)
			}
		}
		// one or both addresses are null, so there is no prefix to speak of
	}
	return false
}

func (addrStr *IPAddressString) isUninitialized() bool {
	return addrStr.init().addrData == nil
}

// Contains returns whether the address subnet identified by this address string contains the address identified by the given string.
// If this address string or the given address string is invalid then returns false.
func (addrStr *IPAddressString) Contains(other *IPAddressString) bool {
	addrStr = addrStr.init()
	other = other.init()
	if addrStr.IsValid() {
		if other == addrStr {
			return true
		}
		if other.isUninitialized() { // other not yet validated - if other is validated no need for this quick contains
			//do the quick check that uses only the string of the other
			directResult := addrStr.addressProvider.contains(other.str)
			if directResult.isSet {
				return directResult.val
			}
		}
		if other.IsValid() {
			// note the quick result also handles the case of "all addresses"
			directResult := addrStr.addressProvider.containsProvider(other.addressProvider)
			if directResult.isSet {
				return directResult.val
			}
			// defer to the constructed addresses
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
	//if addrStr == nil {
	//	return other == nil
	//} else if other == nil {
	//	return false
	//}
	addrStr = addrStr.init()
	other = other.init()
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
			directResult := addrStr.addressProvider.parsedEquals(other.addressProvider)
			if directResult.isSet {
				return directResult.val
			}
			// When a value provider produces no value, equality and comparison are based on the enum ipType,
			// which can be null.
			var err AddressError
			addrProvider, err := addrStr.getAddressProvider()
			if err != nil {
				return stringsMatch
			}
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

//Increases or decreases prefix length by the given increment.
//
//If the address string has prefix length 0 and represents all addresses of the same version,
//and the prefix length is being decreased, then the address representing all addresses of any version is returned.
//
//When there is an associated address value and the prefix length is increased, the bits moved within the prefix become zero,
//and if prefix length is extended beyond the segment series boundary, it is removed.
//When there is an associated address value
//and the prefix length is decreased, the bits moved outside the prefix become zero.
//
// If the address string represents a prefix block, then the result will also represent a prefix block.
func (addrStr *IPAddressString) AdjustPrefixLen(adjustment BitCount) (*IPAddressString, IncompatibleAddressError) {
	address := addrStr.GetAddress()
	if address == nil {
		return nil, nil
	}
	if adjustment == 0 && addrStr.IsPrefixed() {
		return addrStr, nil
	}
	prefix := address.GetNetworkPrefixLen()
	isPrefBlock := address.IsPrefixBlock()
	var addr *IPAddress
	var err IncompatibleAddressError
	if adjustment < 0 && isPrefBlock {
		if prefix != nil && *prefix+adjustment < 0 {
			return NewIPAddressStringParams(SegmentWildcardStr, addrStr.params), nil
		}
		addr, err = address.AdjustPrefixLenZeroed(adjustment)
		if err != nil {
			return nil, err
		}
		addr = addr.ToPrefixBlock()
	} else {
		addr, err = address.AdjustPrefixLenZeroed(adjustment)
		if err != nil {
			return nil, err
		}
	}
	return addr.ToAddressString(), nil
}

func (addrStr *IPAddressString) Wrap() ExtendedIdentifierString {
	return WrappedIPAddressString{addrStr}
}

func ValidatePrefixLenStr(str string, version IPVersion) (prefixLen PrefixLen, err AddressStringError) {
	return validator.validatePrefixLenStr(str, version)
}

func getPrivateParams(orig IPAddressStringParameters) *ipAddressStringParameters {
	if p, ok := orig.(*ipAddressStringParameters); ok {
		return p
	}
	return new(IPAddressStringParametersBuilder).Set(orig).ToParams().(*ipAddressStringParameters)
	//return ToIPAddressStringParamsBuilder(orig).ToParams().(*ipAddressStringParameters)
}
