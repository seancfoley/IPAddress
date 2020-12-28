package ipaddr

import "sync"

// NewIPAddressString constructs an IPAddressString that will parse the given string according to the given parameters
func NewIPAddressString(str string, params IPAddressStringParameters) *IPAddressString {
	// TODO you could make the conversion lazy, only done when needed, but not so sure it's worth it, the conversion should be  fast
	// but I am tempted.  you would need to stop passing params around so much and get it when needed in the parsing code.
	// But consider that few use them, and even fewer would not use the builder,
	////and even for those, they could convert to the builder-based one on their own
	// and even with lazy conversion, you might end up converting all the time
	var p *ipAddressStringParameters
	if params == nil {
		p = defaultIPAddrParameters
	} else {
		p = getPrivateParams(params)
	}
	return &IPAddressString{str: str, params: p}
}

var defaultIPAddrParameters *ipAddressStringParameters = &ipAddressStringParameters{}

type IPAddressString struct {
	str    string
	params *ipAddressStringParameters // when nil, default parameters is used, never access this field directly
	lock   *CreationLock              // when nil, default lock is used, never access this field directly

	addressProvider   IPAddressProvider
	validateException AddressStringException
}

func (ipAddrStr *IPAddressString) getParams() *ipAddressStringParameters {
	params := ipAddrStr.params
	if params == nil {
		params = defaultIPAddrParameters
	}
	return params
}

func (ipAddrStr *IPAddressString) GetValidationOptions() IPAddressStringParameters {
	return ipAddrStr.getParams()
}

func (addrStr *IPAddressString) ToNormalizedString() string {
	//TODO IPAddressString
	return ""
}

func (addrStr *IPAddressString) GetAddress() *IPAddress {
	if addrStr.addressProvider == nil || !addrStr.addressProvider.isInvalid() {
		addr, _ := addrStr.ToAddress() /* note the exception is cached, it is not lost forever */
		return addr
	}
	return nil
}

//
// error can be AddressStringException or IncompatibleAddressException
func (addrStr *IPAddressString) ToAddress() (addr *IPAddress, err error) {
	//call validate for consistent error, cover type == INVALID, and ensure the addressProvider exists
	err = addrStr.validate(INDETERMINATE_VERSION)
	if err == nil {
		addr, err = addrStr.addressProvider.getProviderAddress()
	}
	return
}

// error can be AddressStringException or IncompatibleAddressException
func (addrStr *IPAddressString) ToHostAddress() (*Address, error) {
	addr, err := addrStr.ToAddress()
	return addr.ToAddress(), err
}

//TODO we do want the three validate functions, they allow validation without address object creation
//func (addrStr *IPAddressString) Validate() HostIdentifierException {
//	return nil
//}

///**
//	 * Validates that this string is a valid IPv4 address, and if not, throws an exception with a descriptive message indicating why it is not.
//	 * @throws AddressStringException
//	 */
//	public void validateIPv4() throws AddressStringException {
//		validate(IPVersion.IPV4);
//		checkIPv4Exception();
//	}
//
//	/**
//	 * Validates that this string is a valid IPv6 address, and if not, throws an exception with a descriptive message indicating why it is not.
//	 * @throws AddressStringException
//	 */
//	public void validateIPv6() throws AddressStringException {
//		validate(IPVersion.IPV6);
//		checkIPv6Exception();
//	}
//
//	/**
//	 * Validates that this string is a valid address, and if not, throws an exception with a descriptive message indicating why it is not.
//	 * @throws AddressStringException
//	 */
//	@Override
//	public void validate() throws AddressStringException {
//		validate(null);
//	}
//
//	private void checkIPv4Exception() throws AddressStringException {
//		IPVersion version = addressProvider.getProviderIPVersion();
//		if(version != null && version.isIPv6()) {
//			throw new AddressStringException("ipaddress.error.address.is.ipv6");
//		} else if(validateException != null) {
//			throw validateException;
//		}
//	}
//
//	private void checkIPv6Exception() throws AddressStringException {
//		IPVersion version = addressProvider.getProviderIPVersion();
//		if(version != null && version.isIPv4()) {
//			throw new AddressStringException("ipaddress.error.address.is.ipv4");
//		} else if(validateException != null) {
//			throw validateException;
//		}
//	}
//
//	private boolean isValidated(IPVersion version) throws AddressStringException {
//		if(!addressProvider.isUninitialized()) {
//			if(version == null) {
//				if(validateException != null) {
//					throw validateException; // the two exceptions are the same, so we can choose either one
//				}
//			} else if(version.isIPv4()) {
//				checkIPv4Exception();
//			} else if(version.isIPv6()) {
//				checkIPv6Exception();
//			}
//			return true;
//		}
//		return false;
//	}
//

var (
	validator  strValidator
	globalLock sync.Mutex
)

func (addrStr *IPAddressString) validate(version IPVersion) AddressStringException {
	lock := addrStr.lock // nil for zero-value IPAddressString
	if lock == nil || !lock.isItemCreated() {
		creationFunc := func() {
			addressProvider, err := validator.validateIPAddressStr(addrStr) //strValidator and HostIdentifierStringValidator
			if err != nil {
				addrStr.addressProvider = INVALID_PROVIDER
				addrStr.validateException = err
			} else {
				addrStr.addressProvider = addressProvider
			}
		}
		if lock == nil {
			globalLock.Lock()
			creationFunc()
			globalLock.Unlock()
		} else {
			lock.create(creationFunc)
		}
	}
	return addrStr.validateException
}

func getPrivateParams(orig IPAddressStringParameters) *ipAddressStringParameters {
	if p, ok := orig.(*ipAddressStringParameters); ok {
		return p
	}
	return ToIPAddressStringParamsBuilder(orig).ToParams().(*ipAddressStringParameters)
}
