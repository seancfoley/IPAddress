package test

import (
	"github.com/seancfoley/ipaddress/ipaddress-go/ipaddr"
	"net"
)

var (
	hostOptions = new(ipaddr.HostNameParametersBuilder).
			AllowEmpty(false).
			ParseEmptyStrAs(ipaddr.NoAddress).
			NormalizeToLowercase(true).
			AllowPort(true).
			AllowService(true).
			AllowBracketedIPv6(true).
			AllowBracketedIPv4(true).
			GetIPAddressParametersBuilder(). //GetAddressOptionsBuilder().
			AllowPrefix(true).
			AllowMask(true).
			SetRangeParameters(ipaddr.NoRange).
			Allow_inet_aton(false).
			AllowEmpty(false).
			ParseEmptyStrAs(ipaddr.NoAddress).
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

	//var addressOptions = ipaddr.ToIPAddressParametersBuilder(hostOptions).ToParams()
	addressOptions = new(ipaddr.IPAddressStringParametersBuilder).Set(hostOptions.GetIPAddressParameters()).ToParams()

	macAddressOptions = new(ipaddr.MACAddressStringParametersBuilder).
				AllowEmpty(false).
				AllowAll(false).
				GetFormatParametersBuilder().
				SetRangeParameters(ipaddr.NoRange).
				AllowLeadingZeros(true).
				AllowUnlimitedLeadingZeros(false).
				AllowWildcardedSeparator(true).
				AllowShortSegments(true).
				GetParentBuilder().
				ToParams()

	hostInetAtonwildcardAndRangeOptions = new(ipaddr.HostNameParametersBuilder).
						AllowEmpty(false).
						ParseEmptyStrAs(ipaddr.NoAddress).
						NormalizeToLowercase(true).
						AllowBracketedIPv6(true).
						AllowBracketedIPv4(true).GetIPAddressParametersBuilder().
						AllowPrefix(true).
						AllowMask(true).
						SetRangeParameters(ipaddr.WildcardAndRange).
						Allow_inet_aton(true).
						AllowEmpty(false).
						ParseEmptyStrAs(ipaddr.NoAddress).
						AllowAll(true). //AllowPrefixOnly(false).
						GetIPv4AddressParametersBuilder().
						AllowPrefixLenLeadingZeros(true).
						AllowPrefixesBeyondAddressSize(false).
						AllowWildcardedSeparator(true).
						GetParentBuilder().GetParentBuilder().ToParams()

	inetAtonwildcardAndRangeOptions = new(ipaddr.IPAddressStringParametersBuilder).Set(hostInetAtonwildcardAndRangeOptions.GetIPAddressParameters()).ToParams()
)

type testAddresses interface {
	createAddress(string) *ipaddr.IPAddressString

	createInetAtonAddress(string) *ipaddr.IPAddressString

	createParametrizedAddress(string, ipaddr.RangeParameters) *ipaddr.IPAddressString

	createParamsAddress(string, ipaddr.IPAddressStringParameters) *ipaddr.IPAddressString

	createAddressFromIP(ip net.IP) *ipaddr.IPAddress

	createIPv4Address(uint32) *ipaddr.IPv4Address

	createIPv6Address(high, low uint64) *ipaddr.IPv6Address

	createDoubleParametrizedAddress(str string, ipv4Params, ipv6Params ipaddr.RangeParameters) *ipaddr.IPAddressString

	createHost(string) *ipaddr.HostName

	createMACAddress(string) *ipaddr.MACAddressString

	createMACAddressFromBytes(bytes net.HardwareAddr) *ipaddr.MACAddress

	createMACAddressFromUint64(bytes uint64, extended bool) *ipaddr.MACAddress

	createMACParamsAddress(string, ipaddr.MACAddressStringParameters) *ipaddr.MACAddressString

	isLenient() bool

	allowsRange() bool
}

type addresses struct {
	// eventually we could have caching in here
}

func (t *addresses) createParametrizedAddress(str string, params ipaddr.RangeParameters) *ipaddr.IPAddressString {
	var opts ipaddr.IPAddressStringParameters
	if params == ipaddr.NoRange {
		opts = noRangeAddressOptions
	} else if params == ipaddr.WildcardOnly {
		opts = wildcardOnlyAddressOptions
	} else if params == ipaddr.WildcardAndRange {
		opts = wildcardAndRangeAddressOptions
	} else {
		opts = new(ipaddr.IPAddressStringParametersBuilder).Set(wildcardAndRangeAddressOptions).
			SetRangeParameters(params).ToParams()
	}
	return ipaddr.NewIPAddressStringParams(str, opts)

}

func (t *addresses) createParamsAddress(str string, opts ipaddr.IPAddressStringParameters) *ipaddr.IPAddressString {
	return ipaddr.NewIPAddressStringParams(str, opts)
}

func (t *addresses) createDoubleParametrizedAddress(str string, ipv4Params, ipv6Params ipaddr.RangeParameters) *ipaddr.IPAddressString {
	var opts ipaddr.IPAddressStringParameters
	if ipv4Params == ipv6Params {
		if ipv4Params == ipaddr.NoRange {
			opts = noRangeAddressOptions
		} else if ipv4Params == ipaddr.WildcardOnly {
			opts = wildcardOnlyAddressOptions
		} else if ipv4Params == ipaddr.WildcardAndRange {
			opts = wildcardAndRangeAddressOptions
		}
	}
	if opts == nil {
		opts = new(ipaddr.IPAddressStringParametersBuilder).Set(wildcardAndRangeAddressOptions).
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
	return ipaddr.FromIP(ip)
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

func (t *addresses) createMACParamsAddress(str string, opts ipaddr.MACAddressStringParameters) *ipaddr.MACAddressString {
	return ipaddr.NewMACAddressStringParams(str, opts)
}

func (t *addresses) createHost(str string) *ipaddr.HostName {
	return ipaddr.NewHostNameParams(str, hostOptions)
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
	wildcardAndRangeAddressOptions = new(ipaddr.IPAddressStringParametersBuilder).Set(addressOptions).AllowAll(true).SetRangeParameters(ipaddr.WildcardAndRange).ToParams()
	wildcardOnlyAddressOptions     = new(ipaddr.IPAddressStringParametersBuilder).Set(wildcardAndRangeAddressOptions).SetRangeParameters(ipaddr.WildcardOnly).ToParams()
	noRangeAddressOptions          = new(ipaddr.IPAddressStringParametersBuilder).Set(wildcardAndRangeAddressOptions).SetRangeParameters(ipaddr.NoRange).ToParams()

	wildcardAndRangeMACAddressOptions = new(ipaddr.MACAddressStringParametersBuilder).Set(macAddressOptions).AllowAll(true).GetFormatParametersBuilder().SetRangeParameters(ipaddr.WildcardAndRange).GetParentBuilder().ToParams()
	wildcardOnlyMACAddressOptions     = new(ipaddr.MACAddressStringParametersBuilder).Set(wildcardAndRangeMACAddressOptions).GetFormatParametersBuilder().SetRangeParameters(ipaddr.WildcardOnly).GetParentBuilder().ToParams()
	noRangeMACAddressOptions          = new(ipaddr.MACAddressStringParametersBuilder).Set(wildcardAndRangeMACAddressOptions).GetFormatParametersBuilder().SetRangeParameters(ipaddr.NoRange).GetParentBuilder().ToParams()
)

func (t *rangedAddresses) createAddress(str string) *ipaddr.IPAddressString {
	return ipaddr.NewIPAddressStringParams(str, wildcardAndRangeAddressOptions)
}

func (t *rangedAddresses) createMACAddress(str string) *ipaddr.MACAddressString {
	return ipaddr.NewMACAddressStringParams(str, wildcardAndRangeMACAddressOptions)
}

func (t *rangedAddresses) allowsRange() bool {
	return true
}

//
//func (t *rangedAddresses) createHost(str string) *ipaddr.HostName {
//	return ipaddr.NewHostNameParams(str, xxhostOptionsxx)
//}

var defaultOptions = new(ipaddr.IPAddressStringParametersBuilder).ToParams()

type allAddresses struct {
	rangedAddresses
}

func (t *allAddresses) createAddress(str string) *ipaddr.IPAddressString {
	return ipaddr.NewIPAddressStringParams(str, defaultOptions)
}

func (t *allAddresses) createInetAtonAddress(str string) *ipaddr.IPAddressString {
	return t.createAddress(str)
}

func (t *allAddresses) isLenient() bool {
	return true
}

var _, _, _ testAddresses = &addresses{}, &rangedAddresses{}, &allAddresses{}
