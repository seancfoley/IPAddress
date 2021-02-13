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

// Equals returns true if the given host name matches this one.
func (host *HostName) Equals(other *HostName) bool {
	// TODO xxxx
	return false
}

///*
///**
//	 *
//*/
//@Override
//public boolean equals(Object o) {
//return o instanceof HostName && matches((HostName) o);
//}
// */

///**
//	 * Returns whether the given host matches this one.  For hosts to match, they must represent the same addresses or have the same host names.
//	 * Hosts are not resolved when matching.  Also, hosts must have the same port and service.  They must have the same masks if they are host names.
//	 * Even if two hosts are invalid, they match if they have the same invalid string.
//	 *
//	 * @param host
//	 * @return
//	 */
//	public boolean matches(HostName host) {
//		if(this == host) {
//			return true;
//		}
//		if(isValid()) {
//			if(host.isValid()) {
//				if(isAddressString()) {
//					return host.isAddressString()
//							&& asAddressString().equals(host.asAddressString())
//							&& Objects.equals(getPort(), host.getPort())
//							&& Objects.equals(getService(), host.getService());
//				}
//				if(host.isAddressString()) {
//					return false;
//				}
//				String thisHost = parsedHost.getHost();
//				String otherHost = host.parsedHost.getHost();
//				if(!thisHost.equals(otherHost)) {
//					return false;
//				}
//				return Objects.equals(parsedHost.getEquivalentPrefixLength(), host.parsedHost.getEquivalentPrefixLength()) &&
//						Objects.equals(parsedHost.getMask(), host.parsedHost.getMask()) &&
//						Objects.equals(parsedHost.getPort(), host.parsedHost.getPort()) &&
//						Objects.equals(parsedHost.getService(), host.parsedHost.getService());
//			}
//			return false;
//		}
//		return !host.isValid() && toString().equals(host.toString());
//	}
