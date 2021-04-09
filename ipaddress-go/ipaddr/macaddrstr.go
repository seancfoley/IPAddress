package ipaddr

var defaultMACAddrParameters *macAddressStringParameters = &macAddressStringParameters{}

// NewMACAddressString constructs a MACAddressString that will parse the given string according to the given parameters
func NewMACAddressString(str string, params MACAddressStringParameters) *MACAddressString {
	return &MACAddressString{str: str, params: convertMACParams(params)}
}

var zeroMACAddressString = NewMACAddressString("", defaultMACAddrParameters)

type macAddrData struct {
	addressProvider   MACAddressProvider
	validateException AddressStringException
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
	//TODO MACAddressString
	return nil
}

func (addrStr *MACAddressString) ToAddress() (*MACAddress, error) {
	//TODO MACAddressString
	return nil, nil
}

// error can be AddressStringException or IncompatibleAddressException
func (addrStr *MACAddressString) ToHostAddress() (*Address, error) {
	addr, err := addrStr.ToAddress()
	return addr.ToAddress(), err
}

func (addrStr *MACAddressString) IsValid() bool {
	return addrStr.macAddrStringCache == nil /* zero address is valid */ /* TODO || !addrStr.getAddressProvider().isInvalid() */
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
			// both are null, either empty or IncompatibleAddressException
			return stringsMatch
		}
	} else if !other.IsValid() { // both are invalid
		return stringsMatch // Two invalid addresses are not equal unless strings match, regardless of validation options
	}
	return false
}
