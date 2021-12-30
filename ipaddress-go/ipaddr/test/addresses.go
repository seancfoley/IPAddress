package test

import (
	"github.com/seancfoley/ipaddress/ipaddress-go/ipaddr"
	"github.com/seancfoley/ipaddress/ipaddress-go/ipaddr/addrparam"
	"net"
)

var (
	hostOptions = new(addrparam.HostNameParamsBuilder).
			AllowEmpty(false).
		//ParseEmptyStrAs(ipaddr.NoAddressOption).
		NormalizeToLowercase(true).
		AllowPort(true).
		AllowService(true).
		AllowBracketedIPv6(true).
		AllowBracketedIPv4(true).
		GetIPAddressParamsBuilder(). //GetAddressOptionsBuilder().
		AllowPrefix(true).
		AllowMask(true).
		SetRangeParams(addrparam.NoRange).
		Allow_inet_aton(false).
		AllowEmpty(false).
		//ParseEmptyStrAs(ipaddr.NoAddressOption).
		AllowAll(false). //allowPrefixOnly(true).
		AllowSingleSegment(false).
		GetIPv4AddressParamsBuilder().
		AllowLeadingZeros(true).
		AllowUnlimitedLeadingZeros(false).
		AllowPrefixLenLeadingZeros(true).
		AllowPrefixesBeyondAddressSize(false).
		AllowWildcardedSeparator(true).
		AllowBinary(true).
		GetParentBuilder().
		GetIPv6AddressParamsBuilder().
		AllowLeadingZeros(true).
		AllowUnlimitedLeadingZeros(false).
		AllowPrefixLenLeadingZeros(true).
		AllowPrefixesBeyondAddressSize(false).
		AllowWildcardedSeparator(true).
		AllowMixed(true).
		AllowZone(true).
		AllowBinary(true).
		GetParentBuilder().GetParentBuilder().ToParams()

	hostInetAtonOptions = new(addrparam.HostNameParamsBuilder).Set(hostOptions).GetIPAddressParamsBuilder().Allow_inet_aton(true).AllowSingleSegment(true).GetParentBuilder().ToParams()

	//var addressOptions = ipaddr.ToIPAddressParametersBuilder(hostOptions).ToParams()
	addressOptions = new(addrparam.IPAddressStringParamsBuilder).Set(hostOptions.GetIPAddressParams()).ToParams()

	macAddressOptions = new(addrparam.MACAddressStringParamsBuilder).
				AllowEmpty(false).
				AllowAll(false).
				GetFormatParamsBuilder().
				SetRangeParams(addrparam.NoRange).
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

	createParametrizedAddress(string, addrparam.RangeParams) *ipaddr.IPAddressString

	createParamsAddress(string, addrparam.IPAddressStringParams) *ipaddr.IPAddressString

	createAddressFromIP(ip net.IP) *ipaddr.IPAddress

	createIPv4Address(uint32) *ipaddr.IPv4Address

	createIPv6Address(high, low uint64) *ipaddr.IPv6Address

	createDoubleParametrizedAddress(str string, ipv4Params, ipv6Params addrparam.RangeParams) *ipaddr.IPAddressString

	createHost(string) *ipaddr.HostName

	createInetAtonHost(string) *ipaddr.HostName

	createParamsHost(string, addrparam.HostNameParams) *ipaddr.HostName

	createMACAddress(string) *ipaddr.MACAddressString

	createMACAddressFromBytes(bytes net.HardwareAddr) *ipaddr.MACAddress

	createMACAddressFromUint64(bytes uint64, extended bool) *ipaddr.MACAddress

	createMACParamsAddress(string, addrparam.MACAddressStringParams) *ipaddr.MACAddressString

	isLenient() bool

	allowsRange() bool
}

type addresses struct {
	// eventually we could have caching in here
}

func (t *addresses) createParametrizedAddress(str string, params addrparam.RangeParams) *ipaddr.IPAddressString {
	var opts addrparam.IPAddressStringParams
	if params == addrparam.NoRange {
		opts = noRangeAddressOptions
	} else if params == addrparam.WildcardOnly {
		opts = wildcardOnlyAddressOptions
	} else if params == addrparam.WildcardAndRange {
		opts = wildcardAndRangeAddressOptions
	} else {
		opts = new(addrparam.IPAddressStringParamsBuilder).Set(wildcardAndRangeAddressOptions).
			SetRangeParams(params).ToParams()
	}
	return ipaddr.NewIPAddressStringParams(str, opts)

}

func (t *addresses) createParamsAddress(str string, opts addrparam.IPAddressStringParams) *ipaddr.IPAddressString {
	return ipaddr.NewIPAddressStringParams(str, opts)
}

func (t *addresses) createDoubleParametrizedAddress(str string, ipv4Params, ipv6Params addrparam.RangeParams) *ipaddr.IPAddressString {
	var opts addrparam.IPAddressStringParams
	if ipv4Params == ipv6Params {
		if ipv4Params == addrparam.NoRange {
			opts = noRangeAddressOptions
		} else if ipv4Params == addrparam.WildcardOnly {
			opts = wildcardOnlyAddressOptions
		} else if ipv4Params == addrparam.WildcardAndRange {
			opts = wildcardAndRangeAddressOptions
		}
	}
	if opts == nil {
		opts = new(addrparam.IPAddressStringParamsBuilder).Set(wildcardAndRangeAddressOptions).
			GetIPv4AddressParamsBuilder().SetRangeParams(ipv4Params).GetParentBuilder().
			GetIPv6AddressParamsBuilder().SetRangeParams(ipv6Params).GetParentBuilder().ToParams()
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

func (t *addresses) createMACParamsAddress(str string, opts addrparam.MACAddressStringParams) *ipaddr.MACAddressString {
	return ipaddr.NewMACAddressStringParams(str, opts)
}

func (t *addresses) createHost(str string) *ipaddr.HostName {
	return ipaddr.NewHostNameParams(str, hostOptions)
}

func (t *addresses) createInetAtonHost(str string) *ipaddr.HostName {
	return ipaddr.NewHostNameParams(str, hostInetAtonOptions)
}

func (t *addresses) createParamsHost(str string, params addrparam.HostNameParams) *ipaddr.HostName {
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
	wildcardAndRangeAddressOptions = new(addrparam.IPAddressStringParamsBuilder).Set(addressOptions).AllowAll(true).SetRangeParams(addrparam.WildcardAndRange).ToParams()
	wildcardOnlyAddressOptions     = new(addrparam.IPAddressStringParamsBuilder).Set(wildcardAndRangeAddressOptions).SetRangeParams(addrparam.WildcardOnly).ToParams()
	noRangeAddressOptions          = new(addrparam.IPAddressStringParamsBuilder).Set(wildcardAndRangeAddressOptions).SetRangeParams(addrparam.NoRange).ToParams()

	wildcardAndRangeMACAddressOptions = new(addrparam.MACAddressStringParamsBuilder).Set(macAddressOptions).AllowAll(true).GetFormatParamsBuilder().SetRangeParams(addrparam.WildcardAndRange).GetParentBuilder().ToParams()
	wildcardOnlyMACAddressOptions     = new(addrparam.MACAddressStringParamsBuilder).Set(wildcardAndRangeMACAddressOptions).GetFormatParamsBuilder().SetRangeParams(addrparam.WildcardOnly).GetParentBuilder().ToParams()
	noRangeMACAddressOptions          = new(addrparam.MACAddressStringParamsBuilder).Set(wildcardAndRangeMACAddressOptions).GetFormatParamsBuilder().SetRangeParams(addrparam.NoRange).GetParentBuilder().ToParams()

	hostInetAtonwildcardAndRangeOptions = new(addrparam.HostNameParamsBuilder).
						AllowEmpty(false).
		//ParseEmptyStrAs(ipaddr.NoAddressOption).
		NormalizeToLowercase(true).
		AllowBracketedIPv6(true).
		AllowBracketedIPv4(true).GetIPAddressParamsBuilder().
		AllowPrefix(true).
		AllowMask(true).
		SetRangeParams(addrparam.WildcardAndRange).
		Allow_inet_aton(true).
		AllowEmpty(false).
		//ParseEmptyStrAs(ipaddr.NoAddressOption).
		AllowAll(true). //AllowPrefixOnly(false).
		GetIPv4AddressParamsBuilder().
		AllowPrefixLenLeadingZeros(true).
		AllowPrefixesBeyondAddressSize(false).
		AllowWildcardedSeparator(true).
		GetParentBuilder().GetParentBuilder().ToParams()

	inetAtonwildcardAndRangeOptions = new(addrparam.IPAddressStringParamsBuilder).Set(hostInetAtonwildcardAndRangeOptions.GetIPAddressParams()).ToParams()

	hostWildcardOptions = new(addrparam.HostNameParamsBuilder).Set(hostOptions).GetIPAddressParamsBuilder().
				AllowAll(true).SetRangeParams(addrparam.WildcardOnly).GetParentBuilder().ToParams()

	hostOnlyOptions = new(addrparam.HostNameParamsBuilder).Set(hostOptions).AllowIPAddress(false).ToParams()

	//hostWildcardOptions = new(ipaddr.HostNameParamsBuilder).AllowEmpty(false).GetIPAddressParamsBuilder().Set(wildcardOnlyAddressOptions).GetParentBuilder().ToParams()

	hostWildcardAndRangeOptions = new(addrparam.HostNameParamsBuilder).Set(hostWildcardOptions).GetIPAddressParamsBuilder().SetRangeParams(addrparam.WildcardAndRange).GetParentBuilder().ToParams()

	hostWildcardAndRangeInetAtonOptions = new(addrparam.HostNameParamsBuilder).Set(hostWildcardOptions).GetIPAddressParamsBuilder().SetRangeParams(addrparam.WildcardAndRange).Allow_inet_aton(true).GetParentBuilder().ToParams()

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
	defaultOptions     = new(addrparam.IPAddressStringParamsBuilder).ToParams()
	defaultHostOptions = new(addrparam.HostNameParamsBuilder).ToParams()
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
