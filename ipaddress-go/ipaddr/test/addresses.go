package test

import (
	"github.com/seancfoley/ipaddress/ipaddress-go/ipaddr"
	"github.com/seancfoley/ipaddress/ipaddress-go/ipaddr/addrformat"
	"net"
)

var (
	hostOptions = new(addrformat.HostNameParametersBuilder).
			AllowEmpty(false).
		//ParseEmptyStrAs(ipaddr.NoAddressOption).
		NormalizeToLowercase(true).
		AllowPort(true).
		AllowService(true).
		AllowBracketedIPv6(true).
		AllowBracketedIPv4(true).
		GetIPAddressParametersBuilder(). //GetAddressOptionsBuilder().
		AllowPrefix(true).
		AllowMask(true).
		SetRangeParameters(addrformat.NoRange).
		Allow_inet_aton(false).
		AllowEmpty(false).
		//ParseEmptyStrAs(ipaddr.NoAddressOption).
		AllowAll(false). //allowPrefixOnly(true).
		AllowSingleSegment(false).
		GetIPv4AddressParametersBuilder().
		AllowLeadingZeros(true).
		AllowUnlimitedLeadingZeros(false).
		AllowPrefixLenLeadingZeros(true).
		AllowPrefixesBeyondAddressSize(false).
		AllowWildcardedSeparator(true).
		AllowBinary(true).
		GetParentBuilder().
		GetIPv6AddressParametersBuilder().
		AllowLeadingZeros(true).
		AllowUnlimitedLeadingZeros(false).
		AllowPrefixLenLeadingZeros(true).
		AllowPrefixesBeyondAddressSize(false).
		AllowWildcardedSeparator(true).
		AllowMixed(true).
		AllowZone(true).
		AllowBinary(true).
		GetParentBuilder().GetParentBuilder().ToParams()

	hostInetAtonOptions = new(addrformat.HostNameParametersBuilder).Set(hostOptions).GetIPAddressParametersBuilder().Allow_inet_aton(true).AllowSingleSegment(true).GetParentBuilder().ToParams()

	//var addressOptions = ipaddr.ToIPAddressParametersBuilder(hostOptions).ToParams()
	addressOptions = new(addrformat.IPAddressStringParametersBuilder).Set(hostOptions.GetIPAddressParameters()).ToParams()

	macAddressOptions = new(addrformat.MACAddressStringParametersBuilder).
				AllowEmpty(false).
				AllowAll(false).
				GetFormatParametersBuilder().
				SetRangeParameters(addrformat.NoRange).
				AllowLeadingZeros(true).
				AllowUnlimitedLeadingZeros(false).
				AllowWildcardedSeparator(true).
				AllowShortSegments(true).
				GetParentBuilder().
				ToParams()
)

type testAddresses interface {
	createAddress(string) *ipaddr.IPAddressString

	createInetAtonAddress(string) *ipaddr.IPAddressString

	createParametrizedAddress(string, addrformat.RangeParameters) *ipaddr.IPAddressString

	createParamsAddress(string, addrformat.IPAddressStringParameters) *ipaddr.IPAddressString

	createAddressFromIP(ip net.IP) *ipaddr.IPAddress

	createIPv4Address(uint32) *ipaddr.IPv4Address

	createIPv6Address(high, low uint64) *ipaddr.IPv6Address

	createDoubleParametrizedAddress(str string, ipv4Params, ipv6Params addrformat.RangeParameters) *ipaddr.IPAddressString

	createHost(string) *ipaddr.HostName

	createInetAtonHost(string) *ipaddr.HostName

	createParamsHost(string, addrformat.HostNameParameters) *ipaddr.HostName

	createMACAddress(string) *ipaddr.MACAddressString

	createMACAddressFromBytes(bytes net.HardwareAddr) *ipaddr.MACAddress

	createMACAddressFromUint64(bytes uint64, extended bool) *ipaddr.MACAddress

	createMACParamsAddress(string, addrformat.MACAddressStringParameters) *ipaddr.MACAddressString

	isLenient() bool

	allowsRange() bool
}

type addresses struct {
	// eventually we could have caching in here
}

func (t *addresses) createParametrizedAddress(str string, params addrformat.RangeParameters) *ipaddr.IPAddressString {
	var opts addrformat.IPAddressStringParameters
	if params == addrformat.NoRange {
		opts = noRangeAddressOptions
	} else if params == addrformat.WildcardOnly {
		opts = wildcardOnlyAddressOptions
	} else if params == addrformat.WildcardAndRange {
		opts = wildcardAndRangeAddressOptions
	} else {
		opts = new(addrformat.IPAddressStringParametersBuilder).Set(wildcardAndRangeAddressOptions).
			SetRangeParameters(params).ToParams()
	}
	return ipaddr.NewIPAddressStringParams(str, opts)

}

func (t *addresses) createParamsAddress(str string, opts addrformat.IPAddressStringParameters) *ipaddr.IPAddressString {
	return ipaddr.NewIPAddressStringParams(str, opts)
}

func (t *addresses) createDoubleParametrizedAddress(str string, ipv4Params, ipv6Params addrformat.RangeParameters) *ipaddr.IPAddressString {
	var opts addrformat.IPAddressStringParameters
	if ipv4Params == ipv6Params {
		if ipv4Params == addrformat.NoRange {
			opts = noRangeAddressOptions
		} else if ipv4Params == addrformat.WildcardOnly {
			opts = wildcardOnlyAddressOptions
		} else if ipv4Params == addrformat.WildcardAndRange {
			opts = wildcardAndRangeAddressOptions
		}
	}
	if opts == nil {
		opts = new(addrformat.IPAddressStringParametersBuilder).Set(wildcardAndRangeAddressOptions).
			GetIPv4AddressParametersBuilder().SetRangeParameters(ipv4Params).GetParentBuilder().
			GetIPv6AddressParametersBuilder().SetRangeParameters(ipv6Params).GetParentBuilder().ToParams()
	}
	return ipaddr.NewIPAddressStringParams(str, opts)
}

func (t *addresses) createAddress(str string) *ipaddr.IPAddressString {
	return ipaddr.NewIPAddressStringParams(str, addressOptions)
}

func (t *addresses) createInetAtonAddress(str string) *ipaddr.IPAddressString {
	return ipaddr.NewIPAddressStringParams(str, inetAtonwildcardAndRangeOptions)
}

func (t *addresses) createAddressFromIP(ip net.IP) *ipaddr.IPAddress {
	return ipaddr.NewIPAddressFromNetIP(ip)
}

func (t *addresses) createIPv4Address(val uint32) *ipaddr.IPv4Address {
	return ipaddr.NewIPv4AddressFromUint32(val)
}

func (t *addresses) createIPv6Address(high, low uint64) *ipaddr.IPv6Address {
	return ipaddr.NewIPv6AddressFromUint64(high, low)
}

func (t *addresses) createMACAddress(str string) *ipaddr.MACAddressString {
	return ipaddr.NewMACAddressStringParams(str, macAddressOptions)
}

func (t *addresses) createMACAddressFromBytes(bytes net.HardwareAddr) *ipaddr.MACAddress {
	addr, _ := ipaddr.NewMACAddressFromBytes(bytes)
	return addr
}

func (t *addresses) createMACAddressFromUint64(bytes uint64, extended bool) *ipaddr.MACAddress {
	addr := ipaddr.NewMACAddressFromUint64Ext(bytes, extended)
	return addr
}

func (t *addresses) createMACParamsAddress(str string, opts addrformat.MACAddressStringParameters) *ipaddr.MACAddressString {
	return ipaddr.NewMACAddressStringParams(str, opts)
}

func (t *addresses) createHost(str string) *ipaddr.HostName {
	return ipaddr.NewHostNameParams(str, hostOptions)
}

func (t *addresses) createInetAtonHost(str string) *ipaddr.HostName {
	return ipaddr.NewHostNameParams(str, hostInetAtonOptions)
}

func (t *addresses) createParamsHost(str string, params addrformat.HostNameParameters) *ipaddr.HostName {
	return ipaddr.NewHostNameParams(str, params)
}

func (t *addresses) isLenient() bool {
	return false
}

func (t *addresses) allowsRange() bool {
	return false
}

type rangedAddresses struct {
	addresses
}

var (
	wildcardAndRangeAddressOptions = new(addrformat.IPAddressStringParametersBuilder).Set(addressOptions).AllowAll(true).SetRangeParameters(addrformat.WildcardAndRange).ToParams()
	wildcardOnlyAddressOptions     = new(addrformat.IPAddressStringParametersBuilder).Set(wildcardAndRangeAddressOptions).SetRangeParameters(addrformat.WildcardOnly).ToParams()
	noRangeAddressOptions          = new(addrformat.IPAddressStringParametersBuilder).Set(wildcardAndRangeAddressOptions).SetRangeParameters(addrformat.NoRange).ToParams()

	wildcardAndRangeMACAddressOptions = new(addrformat.MACAddressStringParametersBuilder).Set(macAddressOptions).AllowAll(true).GetFormatParametersBuilder().SetRangeParameters(addrformat.WildcardAndRange).GetParentBuilder().ToParams()
	wildcardOnlyMACAddressOptions     = new(addrformat.MACAddressStringParametersBuilder).Set(wildcardAndRangeMACAddressOptions).GetFormatParametersBuilder().SetRangeParameters(addrformat.WildcardOnly).GetParentBuilder().ToParams()
	noRangeMACAddressOptions          = new(addrformat.MACAddressStringParametersBuilder).Set(wildcardAndRangeMACAddressOptions).GetFormatParametersBuilder().SetRangeParameters(addrformat.NoRange).GetParentBuilder().ToParams()

	hostInetAtonwildcardAndRangeOptions = new(addrformat.HostNameParametersBuilder).
						AllowEmpty(false).
		//ParseEmptyStrAs(ipaddr.NoAddressOption).
		NormalizeToLowercase(true).
		AllowBracketedIPv6(true).
		AllowBracketedIPv4(true).GetIPAddressParametersBuilder().
		AllowPrefix(true).
		AllowMask(true).
		SetRangeParameters(addrformat.WildcardAndRange).
		Allow_inet_aton(true).
		AllowEmpty(false).
		//ParseEmptyStrAs(ipaddr.NoAddressOption).
		AllowAll(true). //AllowPrefixOnly(false).
		GetIPv4AddressParametersBuilder().
		AllowPrefixLenLeadingZeros(true).
		AllowPrefixesBeyondAddressSize(false).
		AllowWildcardedSeparator(true).
		GetParentBuilder().GetParentBuilder().ToParams()

	inetAtonwildcardAndRangeOptions = new(addrformat.IPAddressStringParametersBuilder).Set(hostInetAtonwildcardAndRangeOptions.GetIPAddressParameters()).ToParams()

	hostWildcardOptions = new(addrformat.HostNameParametersBuilder).Set(hostOptions).GetIPAddressParametersBuilder().
				AllowAll(true).SetRangeParameters(addrformat.WildcardOnly).GetParentBuilder().ToParams()

	hostOnlyOptions = new(addrformat.HostNameParametersBuilder).Set(hostOptions).AllowIPAddress(false).ToParams()

	//hostWildcardOptions = new(ipaddr.HostNameParametersBuilder).AllowEmpty(false).GetIPAddressParametersBuilder().Set(wildcardOnlyAddressOptions).GetParentBuilder().ToParams()

	hostWildcardAndRangeOptions = new(addrformat.HostNameParametersBuilder).Set(hostWildcardOptions).GetIPAddressParametersBuilder().SetRangeParameters(addrformat.WildcardAndRange).GetParentBuilder().ToParams()

	hostWildcardAndRangeInetAtonOptions = new(addrformat.HostNameParametersBuilder).Set(hostWildcardOptions).GetIPAddressParametersBuilder().SetRangeParameters(addrformat.WildcardAndRange).Allow_inet_aton(true).GetParentBuilder().ToParams()

	//addressWildcardOptions = wildcardAndRangeAddressOptions
)

func (t *rangedAddresses) createAddress(str string) *ipaddr.IPAddressString {
	return ipaddr.NewIPAddressStringParams(str, wildcardAndRangeAddressOptions)
}

func (t *rangedAddresses) createMACAddress(str string) *ipaddr.MACAddressString {
	return ipaddr.NewMACAddressStringParams(str, wildcardAndRangeMACAddressOptions)
}

func (t *rangedAddresses) createHost(str string) *ipaddr.HostName {
	return ipaddr.NewHostNameParams(str, hostWildcardOptions)
}

func (t *rangedAddresses) createInetAtonHost(str string) *ipaddr.HostName {
	return ipaddr.NewHostNameParams(str, hostInetAtonwildcardAndRangeOptions)
}

func (t *rangedAddresses) allowsRange() bool {
	return true
}

//
//func (t *rangedAddresses) createHost(str string) *ipaddr.HostName {
//	return ipaddr.NewHostNameParams(str, xxhostOptionsxx)
//}

var (
	defaultOptions     = new(addrformat.IPAddressStringParametersBuilder).ToParams()
	defaultHostOptions = new(addrformat.HostNameParametersBuilder).ToParams()
)

type allAddresses struct {
	rangedAddresses
}

func (t *allAddresses) createAddress(str string) *ipaddr.IPAddressString {
	return ipaddr.NewIPAddressStringParams(str, defaultOptions)
}

func (t *allAddresses) createInetAtonAddress(str string) *ipaddr.IPAddressString {
	return t.createAddress(str)
}

func (t *allAddresses) createHost(str string) *ipaddr.HostName {
	return ipaddr.NewHostNameParams(str, defaultHostOptions)
}

func (t *allAddresses) createInetAtonHost(str string) *ipaddr.HostName {
	return ipaddr.NewHostNameParams(str, defaultHostOptions)
}

func (t *allAddresses) isLenient() bool {
	return true
}

var _, _, _ testAddresses = &addresses{}, &rangedAddresses{}, &allAddresses{}
