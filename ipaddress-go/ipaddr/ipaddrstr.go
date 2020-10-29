package ipaddr

var defaultParameters ipAddressStringParameters

// A string that is used to identify a network host.

type HostIdentifierString interface {

	//static final char SEGMENT_VALUE_DELIMITER = ',';

	// provides a normalized String representation for the host identified by this HostIdentifierString instance
	ToNormalizedString() string

	//Validate() HostIdentifierException

	//GetAddress() *Address

	ToAddress() (*Address, HostIdentifierException)
}

type MACAddressString struct { //TODO needs its own file
	str    string
	params *macAddressStringParameters // when nil, defaultParameters is used
}

func (addrStr *MACAddressString) ToNormalizedString() string {
	//TODO MACAddressString
	return ""
}

func (addrStr *MACAddressString) ToAddress() (*Address, HostIdentifierException) {
	//TODO MACAddressString
	return nil, nil
}

type IPAddressString struct {
	str    string
	params *ipAddressStringParameters // when nil, defaultParameters is used
}

func (addrStr *IPAddressString) ToNormalizedString() string {
	//TODO IPAddressString
	return ""
}

//func (addrStr *IPAddressString) Validate() HostIdentifierException {
//	return nil
//}

//func (addrStr *IPAddressString) GetAddress() *Address {
//	return nil
//}

func (addrStr *IPAddressString) ToAddress() (*Address, HostIdentifierException) {
	//TODO IPAddressString
	return nil, nil
}

// TODO you need this to ensure that users do not use their own IPAddressStringParameters impl they can manipulate
// TODO you will assign the ipAddressStringParameters whenever you use the params, which is only in a couple of places
// that allows you to make IPAddresString public for a nil IPAddressString
// But you will also want to have an NewIPAddressString method

func getPrivateParams(orig IPAddressStringParameters) IPAddressStringParameters {
	if _, ok := orig.(*ipAddressStringParameters); ok {
		return orig
	}
	return ToIPAddressStringParamsBuilder(orig).ToParams()
}
