package ipaddr

import (
	"sync/atomic"
	"unsafe"
)

var defaultMACAddrParameters *macAddressStringParameters = &macAddressStringParameters{}

// NewMACAddressString constructs a MACAddressString that will parse the given string according to the given parameters
func NewMACAddressString(str string, params MACAddressStringParameters) *MACAddressString {
	var p *macAddressStringParameters
	if params == nil {
		p = defaultMACAddrParameters
	} else {
		p = getPrivateMACParams(params)
	}
	return &MACAddressString{str: str, params: p, macAddrStringCache: new(macAddrStringCache)}
	//return &MACAddressString{str: str, params: convertMACParams(params)}
}

var zeroMACAddressString = NewMACAddressString("", defaultMACAddrParameters)

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

//func (addrStr *MACAddressString) getParams() *macAddressStringParameters {
//	params := addrStr.params
//	if params == nil {
//		params = defaultMACAddrParameters
//		//addrStr.params = params
//	}
//	return params
//}

func (addrStr *MACAddressString) String() string {
	return addrStr.str
}

func (addrStr *MACAddressString) ToNormalizedString() string {
	//TODO MACAddressString
	return ""
}

func (addrStr *MACAddressString) GetAddress() *MACAddress {
	provider, _ := addrStr.getAddressProvider()
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

// error can be AddressStringError or IncompatibleAddressError
func (addrStr *MACAddressString) ToHostAddress() (*Address, AddressError) {
	addr, err := addrStr.ToAddress()
	return addr.ToAddress(), err
}

func (addrStr *MACAddressString) IsValid() bool {
	return addrStr.macAddrStringCache == nil /* zero address is valid */ /* TODO || !addrStr.getAddressProvider().isInvalid() */
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

// Two MACAddressString objects are equal if they represent the same set of addresses.
//
// If a MACAddressString is invalid, it is equal to another address only if the other address was constructed from the same string.
func (addrStr *MACAddressString) Equals(other *MACAddressString) bool {
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
	return ToMACAddressStringParamsBuilder(orig).ToParams().(*macAddressStringParameters)
}
