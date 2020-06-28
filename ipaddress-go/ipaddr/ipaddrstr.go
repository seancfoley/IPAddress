package ipaddr

var defaultParameters IPAddressStringParameters

type IPAddressString struct {
	str    string
	params *IPAddressStringParameters // when nil, defaultParameters is used
}
