package ipaddr

const (
	PortSeparator    = ':'
	LabelSeparator   = '.'
	IPv6StartBracket = '['
	IPv6EndBracket   = '['
)

// NewHostName constructs an HostName that will parse the given string according to the given parameters
func NewHostName(str string, params HostNameParameters) *HostName {
	return &HostName{str: str, params: convertHostParams(params)}
}

var defaultHostParameters *hostNameParameters = &hostNameParameters{}

type HostName struct {
	str    string
	params *hostNameParameters // when nil, default parameters is used, never access this field directly
}

func (host *HostName) getParams() *hostNameParameters {
	params := host.params
	if params == nil {
		params = defaultHostParameters
		host.params = params
	}
	return params
}

func (host *HostName) GetValidationOptions() HostNameParameters {
	return host.getParams()
}

func (host *HostName) ToNormalizedString() string {
	//TODO HostName
	return ""
}

//TODO we do want the three validate functions, they allow validation without address object creation
//func (host *HostName) Validate() HostIdentifierException {
//	return nil
//}

func (host *HostName) GetAddress() *IPAddress {
	return nil
}

//
// error can be AddressStringException or IncompatibleAddressException
func (host *HostName) ToAddress() (*IPAddress, error) {
	//TODO HostName
	return nil, nil
}

func (host *HostName) ToHostAddress() (*Address, error) {
	addr, err := host.ToAddress()
	return addr.ToAddress(), err
}
