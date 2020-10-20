package ipaddr

var defaultParameters ipAddressStringParameters

type IPAddressString struct {
	str    string
	params *ipAddressStringParameters // when nil, defaultParameters is used
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
