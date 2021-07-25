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
// If so, the prefix length is given by GetNetworkPrefixLength()
func (addrStr *IPAddressString) IsPrefixed() bool {
	return addrStr.GetNetworkPrefixLength() != nil
}

// If this address is a valid address with an associated network prefix length then this returns that prefix length, otherwise returns null.
// The prefix length may be expressed explicitly with the notation "\xx" where xx is a decimal value, or it may be expressed implicitly as a network mask such as /255.255.0.0
func (addrStr *IPAddressString) GetNetworkPrefixLength() PrefixLen {
	if addrStr.IsValid() {
		return addrStr.addressProvider.getProviderNetworkPrefixLength()
	}
	return nil
}

// GetMask returns the mask, if any, that was provided with this address string
func (addrStr *IPAddressString) GetMask() *IPAddress {
	if addrStr.IsValid() {
		return addrStr.addressProvider.getProviderMask()
	}
	return nil
}

// IsAllAddresses returns true if the string represents all IP addresses, such as the string "*"
// You can denote all IPv4 addresses with *.*, or all IPv6 addresses with *:*
func (addrStr *IPAddressString) IsAllAddresses() bool {
	return addrStr.IsValid() && addrStr.addressProvider.isProvidingAllAddresses()
}

// IsEmpty() returns true if the address string is empty (zero-length).
func (addrStr *IPAddressString) IsEmpty() bool {
	return addrStr.IsValid() && addrStr.addressProvider.isProvidingEmpty()
}

// IsIPv4() returns true if the address is IPv4
func (addrStr *IPAddressString) IsIPv4() bool {
	return addrStr.IsValid() && addrStr.addressProvider.isProvidingIPv4()
}

// IsIPv6() returns true if the address is IPv6
func (addrStr *IPAddressString) IsIPv6() bool {
	return addrStr.IsValid() && addrStr.addressProvider.isProvidingIPv6()
}

// If this address string represents an IPv6 address, returns whether the lower 4 bytes were represented as IPv4
func (addrStr *IPAddressString) IsMixedIPv6() bool {
	return addrStr.IsIPv6() && addrStr.addressProvider.isProvidingMixedIPv6()
}

/* TODO later IsBase85IPv6
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

func (addrStr *IPAddressString) String() string {
	return addrStr.str
}

func (addrStr *IPAddressString) ToNormalizedString() string {
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
	return provider.isInvalid()
}

func (addrStr *IPAddressString) GetAddress() *IPAddress {
	provider, _ := addrStr.getAddressProvider()
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

func (addrStr *IPAddressString) GetHostAddress() *IPAddress {
	provider, _ := addrStr.getAddressProvider()
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
func (addrStr *IPAddressString) IsSequential() bool {
	return addrStr.IsValid() && addrStr.addressProvider.isSequential()
}

// GetSequentialRange returns the range of sequential addresses from the lowest address specified in this address string to the highest.
//
// Since not all IPAddressString instances describe a sequential series of addresses,
// this does not necessarily match the exact set of addresses specified by the string.
// For example, 1-2.3.4.1-2 produces the sequential range 1.3.4.1 to 2.3.4.2 that includes the address 1.255.255.2 not specified by the string.
//
// The sequential range matches the same set of addresses as the address string or the address when {@link #isSequential()} is true.
// Otherwise, the range includes addresses not specified by the address string.
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
	err := addrStr.Validate()
	if err != nil {
		return err
	} else if version != IndeterminateIPVersion {
		addrStr = addrStr.init()
		addrVersion := addrStr.addressProvider.getProviderIPVersion()
		if version.isIPv4() {
			if !addrVersion.isIPv4() {
				return &addressStringError{addressError{str: addrStr.str, key: "ipaddress.error.address.is.ipv6"}}
			}
		} else if version.isIPv6() {
			if !addrVersion.isIPv6() {
				return &addressStringError{addressError{str: addrStr.str, key: "ipaddress.error.address.is.ipv4"}}
			}
		}
	}
	return nil
}

// All address strings are comparable.  If two address strings are invalid, their strings are compared.
// Otherwise, address strings are compared according to which type or version of string, and then within each type or version
// they are compared using the comparison rules for addresses.
func (addrStr *IPAddressString) CompareTo(other *IPAddressString) int {
	if addrStr == other {
		return 0
	}
	isValid, otherIsValid := addrStr.IsValid(), other.IsValid()
	if isValid || otherIsValid {
		if res, err := addrStr.addressProvider.providerCompare(other.addressProvider); err == nil {
			return res
		}
	}
	return strings.Compare(addrStr.String(), other.String())
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
	return addrStr.addrData == nil
}

// Contains returns whether the address subnet identified by this address string contains the address identified by the given string.
// If this address string or the given address string is invalid then returns false.
func (addrStr *IPAddressString) Contains(other *IPAddressString) bool {
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

// TODO adjustPrefixLength
// Increases or decreases prefix length by the given increment.
//
// This acts on address strings with an associated prefix length, whether or not there is also an associated address value.
//
// If the address string has prefix length 0 and represents all addresses of the same version,
// and the prefix length is being decreased, then the address representing all addresses of any version is returned.
//
// When there is an associated address value and the prefix length is increased, the bits moved within the prefix become zero,
// and if prefix length is extended beyond the segment series boundary, it is removed.
// When there is an associated address value
// and the prefix length is decreased, the bits moved outside the prefix become zero.
//	public IPAddressString adjustPrefixLength(int adjustment) {
//		if(isPrefixOnly()) {
//			int newBits = adjustment > 0 ? Math.min(IPv6Address.BIT_COUNT, getNetworkPrefixLength() + adjustment) : Math.max(0, getNetworkPrefixLength() + adjustment);
//			return new IPAddressString(IPAddressNetwork.getPrefixString(newBits), validationOptions);
//		}
//		IPAddress address = getAddress();
//		if(address == null) {
//			return null;
//		}
//		if(adjustment == 0 && isPrefixed()) {
//			return this;
//		}
//		Integer prefix = address.getNetworkPrefixLength();
//		if(prefix != null && prefix + adjustment < 0 && address.isPrefixBlock()) {
//			return new IPAddressString(IPAddress.SEGMENT_WILDCARD_STR, validationOptions);
//		}
//		return address.adjustPrefixLength(adjustment).toAddressString();
//	}

//TODO xxx was I planning to use Get/ToAddress(IPVersion)?  That applies to what, masks, all, and empty?
// Is it worth it?  Probably I guess, it can allow you to specify the mask you want and the all address you want and the loopback you want
// There is no other way to do that in the ambiguous cases.  even with preferred versions, you might want to get the other version.

func getPrivateParams(orig IPAddressStringParameters) *ipAddressStringParameters {
	if p, ok := orig.(*ipAddressStringParameters); ok {
		return p
	}
	return ToIPAddressStringParamsBuilder(orig).ToParams().(*ipAddressStringParameters)
}
