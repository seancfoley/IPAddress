package ipaddr

var defaultMACAddrParameters *macAddressStringParameters = &macAddressStringParameters{}

// NewMACAddressString constructs a MACAddressString that will parse the given string according to the given parameters
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
