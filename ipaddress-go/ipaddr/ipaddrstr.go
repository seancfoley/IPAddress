package ipaddr

// A string that is used to identify a network host.

type HostIdentifierString interface {

	//static final char SEGMENT_VALUE_DELIMITER = ',';

	// provides a normalized String representation for the host identified by this HostIdentifierString instance
	ToNormalizedString() string

	//Validate() HostIdentifierException

	GetAddress() *Address

	ToAddress() (*Address, error)
}

var (
	_ HostIdentifierString = &IPAddressString{}
	_ HostIdentifierString = &MACAddressString{}
)

var defaultMACAddrParameters *macAddressStringParameters = &macAddressStringParameters{}

// NewIPAddressString constructs an IPAddressString that will parse the given string according to the given parameters
func NewMACAddressString(str string, params MACAddressStringParameters) *MACAddressString {
	return &MACAddressString{str: str, params: convertMACParams(params)}
}

type MACAddressString struct { //TODO needs its own file
	str    string
	params *macAddressStringParameters // when nil, defaultParameters is used
}

func (addrStr *MACAddressString) getParams() *macAddressStringParameters {
	params := addrStr.params
	if params == nil {
		params = defaultMACAddrParameters
		addrStr.params = params
	}
	return params
}

func (addrStr *MACAddressString) ToNormalizedString() string {
	//TODO MACAddressString
	return ""
}

func (addrStr *MACAddressString) GetAddress() *Address {
	//TODO MACAddressString
	return nil
}

func (addrStr *MACAddressString) ToAddress() (*Address, error) {
	//TODO MACAddressString
	return nil, nil
}

// NewIPAddressString constructs an IPAddressString that will parse the given string according to the given parameters
func NewIPAddressString(str string, params IPAddressStringParameters) *IPAddressString {
	// TODO you could make the conversion lazy, only done when needed, but not so sure it's worth it, the conversion should be  fast
	// but I am tempted.  you would need to stop passing params around so much and get it when needed in the parsing code.
	// But consider that few use them, and even fewer would not use the builder,
	////and even for those, they could convert to the builder-based one on their own
	return &IPAddressString{str: str, params: convertIPAddrParams(params)}
}

var defaultIPAddrParameters *ipAddressStringParameters = &ipAddressStringParameters{}

type IPAddressString struct {
	str    string
	params *ipAddressStringParameters // when nil, default parameters is used, never access this field directly
}

func (ipAddrStr *IPAddressString) getParams() *ipAddressStringParameters {
	params := ipAddrStr.params
	if params == nil {
		params = defaultIPAddrParameters
		ipAddrStr.params = params
	}
	return params
}

func (addrStr *IPAddressString) ToNormalizedString() string {
	//TODO IPAddressString
	return ""
}

//TODO we do want the three validate functions, they allow validation without address object creation
//func (addrStr *IPAddressString) Validate() HostIdentifierException {
//	return nil
//}

func (addrStr *IPAddressString) GetAddress() *Address {
	return nil
}

//
// error can be AddressStringException or IncompatibleAddressException
func (addrStr *IPAddressString) ToAddress() (*Address, error) {
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
