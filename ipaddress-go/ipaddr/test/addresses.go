package test

import (
	"github.com/seancfoley/ipaddress/ipaddress-go/ipaddr"
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
			AllowAll(false).
		//allowPrefixOnly(true).
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
)

type testAddresses interface {
	createAddress(string) *ipaddr.IPAddressString

	//createInetAtonAddress(string) *ipaddr.IPAddressString

	createHost(string) *ipaddr.HostName

	createMACAddress(string) *ipaddr.MACAddressString
}

type addresses struct {
	//testAccumulator
}

func (t *addresses) createAddress(str string) *ipaddr.IPAddressString {
	return ipaddr.NewIPAddressStringParams(str, addressOptions)
}

func (t *addresses) createMACAddress(str string) *ipaddr.MACAddressString {
	return ipaddr.NewMACAddressStringParams(str, macAddressOptions)
}

func (t *addresses) createHost(str string) *ipaddr.HostName {
	return ipaddr.NewHostNameParams(str, hostOptions)
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

//func (t *allAddresses) createMACAddress(str string) *ipaddr.MACAddressString {
//	return ipaddr.NewMACAddressStringParams(str, xxxmacAddressOptions)
//}
//
//func (t *allAddresses) createHost(str string) *ipaddr.HostName {
//	return ipaddr.NewHostNameParams(str, xxhostOptionsxx)
//}
