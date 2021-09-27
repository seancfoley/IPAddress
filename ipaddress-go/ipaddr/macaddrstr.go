package ipaddr

import (
	"strings"
	"sync/atomic"
	"unsafe"
)

var defaultMACAddrParameters *macAddressStringParameters = &macAddressStringParameters{}

// NewMACAddressStringParams constructs a MACAddressString that will parse the given string according to the given parameters
func NewMACAddressStringParams(str string, params MACAddressStringParameters) *MACAddressString {
	var p *macAddressStringParameters
	if params == nil {
		p = defaultMACAddrParameters
	} else {
		p = getPrivateMACParams(params)
	}
	return &MACAddressString{str: str, params: p, macAddrStringCache: new(macAddrStringCache)}
}

// NewMACAddressString constructs a MACAddressString that will parse the given string according to the default parameters
func NewMACAddressString(str string) *MACAddressString {
	return &MACAddressString{str: str, params: defaultMACAddrParameters, macAddrStringCache: new(macAddrStringCache)}
}

func newMACAddressStringFromAddr(str string, addr *MACAddress) *MACAddressString {
	return &MACAddressString{
		str:    str,
		params: defaultMACAddrParameters,
		macAddrStringCache: &macAddrStringCache{
			&macAddrData{
				addressProvider: wrappedMACAddressProvider{addr},
			},
		},
	}
}

var zeroMACAddressString = NewMACAddressString("")

type macAddrData struct {
	addressProvider   macAddressProvider
	validateException AddressStringError
}

type macAddrStringCache struct {
	*macAddrData
}

type MACAddressString struct {
	str    string
	params *macAddressStringParameters // when nil, defaultParameters is used
	*macAddrStringCache
}

func (addrStr *MACAddressString) init() *MACAddressString {
	if addrStr.macAddrStringCache == nil {
		//if addrStr != nil && addrStr.macAddrStringCache == nil {TODO init() nil
		return zeroMACAddressString
	}
	return addrStr
}

func (addrStr *MACAddressString) getParams() *macAddressStringParameters {
	return addrStr.init().params
}

func (addrStr *MACAddressString) GetValidationOptions() MACAddressStringParameters {
	return addrStr.getParams()
}

func (addrStr *MACAddressString) String() string {
	return addrStr.str
}

func (addrStr *MACAddressString) ToNormalizedString() string {
	addr := addrStr.GetAddress()
	if addr != nil {
		return addr.toNormalizedString()
	}
	return addrStr.String()
}

func (addrStr *MACAddressString) GetAddress() *MACAddress {
	provider, err := addrStr.getAddressProvider()
	if err != nil {
		return nil
	}
	addr, _ := provider.getAddress()
	return addr
}

func (addrStr *MACAddressString) ToAddress() (*MACAddress, AddressError) {
	provider, err := addrStr.getAddressProvider()
	if err != nil {
		return nil, err
	}
	return provider.getAddress()
}

// IsPrefixed returns whether this address represents the set of all addresses with the same prefix
func (addrStr *MACAddressString) IsPrefixed() bool {
	return addrStr.GetPrefixLen() != nil
}

// GetPrefixLen returns the prefix length if this address is a valid prefixed address, otherwise returns null
func (addrStr *MACAddressString) GetPrefixLen() PrefixLen {
	addr := addrStr.GetAddress()
	if addr != nil {
		return addr.GetPrefixLen()
	}
	return nil
}

// IsFullRange returns whether the address represents the set all all valid MAC addresses for its address length
func (addrStr *MACAddressString) IsFullRange() bool {
	addr := addrStr.GetAddress()
	return addr != nil && addr.IsFullRange()
}

//IsEmpty returns true if the address is empty (zero-length).
func (addrStr *MACAddressString) IsEmpty() bool {
	addr, err := addrStr.ToAddress()
	return err == nil && addr == nil
}

func (addrStr *MACAddressString) IsZero() bool {
	addr := addrStr.GetAddress()
	return addr != nil && addr.IsZero()
}

func (addrStr *MACAddressString) IsValid() bool {
	return addrStr.Validate() == nil
}

func (addrStr *MACAddressString) getAddressProvider() (macAddressProvider, AddressStringError) {
	addrStr = addrStr.init()
	err := addrStr.Validate()
	return addrStr.addressProvider, err
}

// Validate validates that this string is a valid address, and if not, throws an exception with a descriptive message indicating why it is not.
func (addrStr *MACAddressString) Validate() AddressStringError {
	addrStr = addrStr.init()
	data := addrStr.macAddrData
	if data == nil {
		addressProvider, err := validator.validateMACAddressStr(addrStr)
		data = &macAddrData{addressProvider, err}
		dataLoc := (*unsafe.Pointer)(unsafe.Pointer(&addrStr.macAddrData))
		atomic.StorePointer(dataLoc, unsafe.Pointer(data))
	}
	return data.validateException
}

func (addrStr *MACAddressString) CompareTo(other *MACAddressString) int {
	//if addrStr == other {
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
			addr := addrStr.GetAddress()
			if addr != nil {
				otherAddr := other.GetAddress()
				if otherAddr != nil {
					return addr.CompareTo(otherAddr)
				}
			}
			// one or the other is null, either empty or IncompatibleAddressException
			return strings.Compare(addrStr.String(), other.String())
		}
		return 1
	} else if other.IsValid() {
		return -1
	}
	return strings.Compare(addrStr.String(), other.String())
}

// Two MACAddressString objects are equal if they represent the same set of addresses.
//
// If a MACAddressString is invalid, it is equal to another address only if the other address was constructed from the same string.
func (addrStr *MACAddressString) Equals(other *MACAddressString) bool {
	//if addrStr == nil {
	//	return other == nil
	//} else if other == nil {
	//	return false
	//}
	//addrStr = addrStr.init()
	//other = other.init()
	if addrStr == other {
		return true
	}

	//if they have the same string, they must be the same,
	//but the converse is not true, if they have different strings, they can still be the same

	// Also note that we do not call equals() on the validation options, this is intended as an optimization,
	// and probably better to avoid going through all the validation objects here
	stringsMatch := addrStr.String() == other.String()
	if stringsMatch && addrStr.params == other.params {
		return true
	}
	if addrStr.IsValid() {
		if other.IsValid() {
			value := addrStr.GetAddress()
			if value != nil {
				otherValue := other.GetAddress()
				if otherValue != nil {
					return value.equals(otherValue)
				} else {
					return false
				}
			} else if other.GetAddress() != nil {
				return false
			}
			// both are null, either empty or IncompatibleAddressError
			return stringsMatch
		}
	} else if !other.IsValid() { // both are invalid
		return stringsMatch // Two invalid addresses are not equal unless strings match, regardless of validation options
	}
	return false
}

func getPrivateMACParams(orig MACAddressStringParameters) *macAddressStringParameters {
	if p, ok := orig.(*macAddressStringParameters); ok {
		return p
	}
	return new(MACAddressStringParametersBuilder).Set(orig).ToParams().(*macAddressStringParameters)
	//return ToMACAddressStringParamsBuilder(orig).ToParams().(*macAddressStringParameters)
}
