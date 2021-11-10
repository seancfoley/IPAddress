package test

import "github.com/seancfoley/ipaddress/ipaddress-go/ipaddr"

type specialTypesTester struct {
	testBase
}

//TODO addressordertest and finish off this specialtypes test

var (
	hostOptionsSpecial            = new(ipaddr.HostNameParametersBuilder).AllowEmpty(true).ParseEmptyStrAs(ipaddr.LoopbackOption).GetIPAddressParametersBuilder().AllowEmpty(false).SetRangeParameters(ipaddr.WildcardOnly).AllowAll(true).GetParentBuilder().ToParams()
	addressOptionsSpecial         = new(ipaddr.IPAddressStringParametersBuilder).Set(hostOptionsSpecial.GetIPAddressParameters()).AllowEmpty(true).ParseEmptyStrAs(ipaddr.LoopbackOption).ToParams()
	macOptionsSpecial             = new(ipaddr.MACAddressStringParametersBuilder).Set(macAddressOptions).AllowEmpty(true).SetRangeParameters(ipaddr.WildcardOnly).AllowAll(true).ToParams()
	emptyAddressOptions           = new(ipaddr.HostNameParametersBuilder).Set(hostOptions).GetIPAddressParametersBuilder().AllowEmpty(true).ParseEmptyStrAs(ipaddr.LoopbackOption).GetParentBuilder().ToParams()
	emptyAddressNoLoopbackOptions = new(ipaddr.HostNameParametersBuilder).Set(emptyAddressOptions).GetIPAddressParametersBuilder().ParseEmptyStrAs(ipaddr.NoAddressOption).GetParentBuilder().ToParams()
)

func (t specialTypesTester) run() {
	allSingleHex := "0x00000000-0xffffffff"
	allSingleOctal := "000000000000-037777777777"

	t.testIPv4Strings("*", true, "*.*.*.*", "*.*.*.*", "%.%.%.%", "000-255.000-255.000-255.000-255", "*.*.*.*.in-addr.arpa", allSingleHex, allSingleOctal)
	t.testIPv4Strings("***.***.***.***", true, "*.*.*.*", "*.*.*.*", "%.%.%.%", "000-255.000-255.000-255.000-255", "*.*.*.*.in-addr.arpa", allSingleHex, allSingleOctal)
	t.testIPv4Strings("*.*", false, "*.*.*.*", "*.*.*.*", "%.%.%.%", "000-255.000-255.000-255.000-255", "*.*.*.*.in-addr.arpa", allSingleHex, allSingleOctal)
	t.testIPv4Strings("*.*/16", false, "*.*.0.0/16", "*.*.*.*", "%.%.%.%", "000-255.000-255.000.000/16", "*.*.*.*.in-addr.arpa", allSingleHex, allSingleOctal)
	t.testIPv4Strings("*.*/16", true, "*.*.0.0/16", "*.*.*.*", "%.%.%.%", "000-255.000-255.000.000/16", "*.*.*.*.in-addr.arpa", allSingleHex, allSingleOctal)
	t.testIPv4Strings("*/16", true, "*.*.0.0/16", "*.*.*.*", "%.%.%.%", "000-255.000-255.000.000/16", "*.*.*.*.in-addr.arpa", allSingleHex, allSingleOctal)
	t.testIPv4Strings("*/255.255.0.0", false, "*.*.0.0/16", "*.*.*.*", "%.%.%.%", "000-255.000-255.000.000/16", "*.*.*.*.in-addr.arpa", allSingleHex, allSingleOctal)
	t.testIPv4Strings("*/255.255.0.0", true, "*.*.0.0/16", "*.*.*.*", "%.%.%.%", "000-255.000-255.000.000/16", "*.*.*.*.in-addr.arpa", allSingleHex, allSingleOctal)
	t.testIPv4Strings("", false, "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.000.000.001", "1.0.0.127.in-addr.arpa", "0x7f000001", "017700000001")
	t.testIPv4Strings("", true, "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.000.000.001", "1.0.0.127.in-addr.arpa", "0x7f000001", "017700000001")

	base85All := "00000000000000000000" + ipaddr.ExtendedDigitsRangeSeparatorStr + "=r54lj&NUUO~Hi%c2ym0"
	//base85AllPrefixed := base85All + "/16"
	//base85AllPrefixed64 := base85All + "/64"
	base8516 := "00000000000000000000" + ipaddr.ExtendedDigitsRangeSeparatorStr + "=q{+M|w0(OeO5^EGP660" + "/16"
	base8564 := "00000000000000000000" + ipaddr.ExtendedDigitsRangeSeparatorStr + "=r54lj&NUTUTif>jH#O0" + "/64"
	allSingleHexIPv6 := "0x00000000000000000000000000000000-0xffffffffffffffffffffffffffffffff"
	allSingleOctalIPv6 := "00000000000000000000000000000000000000000000-03777777777777777777777777777777777777777777"

	t.testIPv6Strings("*", true, "*:*:*:*:*:*:*:*", "*:*:*:*:*:*:*:*", "*:*:*:*:*:*:*:*", "%:%:%:%:%:%:%:%", "0000-ffff:0000-ffff:0000-ffff:0000-ffff:0000-ffff:0000-ffff:0000-ffff:0000-ffff", "*:*:*:*:*:*:*:*", "*:*:*:*:*:*:*:*", "*:*:*:*:*:*:*:*", "*:*:*:*:*:*:*:*", "*:*:*:*:*:*:*.*.*.*", "*:*:*:*:*:*:*.*.*.*", "*:*:*:*:*:*:*.*.*.*", "*:*:*:*:*:*:*.*.*.*", "*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.ip6.arpa", "*-*-*-*-*-*-*-*.ipv6-literal.net", base85All, allSingleHexIPv6, allSingleOctalIPv6)
	t.testIPv6Strings("*:*", false, "*:*:*:*:*:*:*:*", "*:*:*:*:*:*:*:*", "*:*:*:*:*:*:*:*", "%:%:%:%:%:%:%:%", "0000-ffff:0000-ffff:0000-ffff:0000-ffff:0000-ffff:0000-ffff:0000-ffff:0000-ffff", "*:*:*:*:*:*:*:*", "*:*:*:*:*:*:*:*", "*:*:*:*:*:*:*:*", "*:*:*:*:*:*:*:*", "*:*:*:*:*:*:*.*.*.*", "*:*:*:*:*:*:*.*.*.*", "*:*:*:*:*:*:*.*.*.*", "*:*:*:*:*:*:*.*.*.*", "*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.ip6.arpa", "*-*-*-*-*-*-*-*.ipv6-literal.net", base85All, allSingleHexIPv6, allSingleOctalIPv6)
	t.testIPv6Strings("*:*", true, "*:*:*:*:*:*:*:*", "*:*:*:*:*:*:*:*", "*:*:*:*:*:*:*:*", "%:%:%:%:%:%:%:%", "0000-ffff:0000-ffff:0000-ffff:0000-ffff:0000-ffff:0000-ffff:0000-ffff:0000-ffff", "*:*:*:*:*:*:*:*", "*:*:*:*:*:*:*:*", "*:*:*:*:*:*:*:*", "*:*:*:*:*:*:*:*", "*:*:*:*:*:*:*.*.*.*", "*:*:*:*:*:*:*.*.*.*", "*:*:*:*:*:*:*.*.*.*", "*:*:*:*:*:*:*.*.*.*", "*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.ip6.arpa", "*-*-*-*-*-*-*-*.ipv6-literal.net", base85All, allSingleHexIPv6, allSingleOctalIPv6)

	t.testIPv6Strings("*/16", true,
		"*:0:0:0:0:0:0:0/16",
		"*:*:*:*:*:*:*:*",
		"*:*:*:*:*:*:*:*",
		"%:%:%:%:%:%:%:%",
		"0000-ffff:0000:0000:0000:0000:0000:0000:0000/16",
		"*::/16",
		"*::/16",
		"*::/16",
		"*:*:*:*:*:*:*:*",
		"*::0.0.0.0/16",
		"*::0.0.0.0/16",
		"*::/16",
		"*::/16",
		"*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.ip6.arpa",
		"*-0-0-0-0-0-0-0.ipv6-literal.net/16",
		base8516, allSingleHexIPv6, allSingleOctalIPv6)
	t.testIPv6Strings("*:*/16", false,
		"*:0:0:0:0:0:0:0/16", "*:*:*:*:*:*:*:*", "*:*:*:*:*:*:*:*", "%:%:%:%:%:%:%:%", "0000-ffff:0000:0000:0000:0000:0000:0000:0000/16", "*::/16", "*::/16", "*::/16", "*:*:*:*:*:*:*:*", "*::0.0.0.0/16", "*::0.0.0.0/16", "*::/16", "*::/16", "*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.ip6.arpa", "*-0-0-0-0-0-0-0.ipv6-literal.net/16", base8516, allSingleHexIPv6, allSingleOctalIPv6)
	t.testIPv6Strings("*:*/16", true, "*:0:0:0:0:0:0:0/16", "*:*:*:*:*:*:*:*", "*:*:*:*:*:*:*:*", "%:%:%:%:%:%:%:%", "0000-ffff:0000:0000:0000:0000:0000:0000:0000/16", "*::/16", "*::/16", "*::/16", "*:*:*:*:*:*:*:*", "*::0.0.0.0/16", "*::0.0.0.0/16", "*::/16", "*::/16", "*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.ip6.arpa", "*-0-0-0-0-0-0-0.ipv6-literal.net/16", base8516, allSingleHexIPv6, allSingleOctalIPv6)
	t.testIPv6Strings("*/64", false, "*:*:*:*:0:0:0:0/64", "*:*:*:*:*:*:*:*", "*:*:*:*:*:*:*:*", "%:%:%:%:%:%:%:%", "0000-ffff:0000-ffff:0000-ffff:0000-ffff:0000:0000:0000:0000/64", "*:*:*:*::/64", "*:*:*:*::/64", "*:*:*:*::/64", "*:*:*:*:*:*:*:*", "*:*:*:*::0.0.0.0/64", "*:*:*:*::0.0.0.0/64", "*:*:*:*::/64", "*:*:*:*::/64", "*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.ip6.arpa", "*-*-*-*-0-0-0-0.ipv6-literal.net/64", base8564, allSingleHexIPv6, allSingleOctalIPv6)
	t.testIPv6Strings("*/64", true, "*:*:*:*:0:0:0:0/64", "*:*:*:*:*:*:*:*", "*:*:*:*:*:*:*:*", "%:%:%:%:%:%:%:%", "0000-ffff:0000-ffff:0000-ffff:0000-ffff:0000:0000:0000:0000/64", "*:*:*:*::/64", "*:*:*:*::/64", "*:*:*:*::/64", "*:*:*:*:*:*:*:*", "*:*:*:*::0.0.0.0/64", "*:*:*:*::0.0.0.0/64", "*:*:*:*::/64", "*:*:*:*::/64", "*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.ip6.arpa", "*-*-*-*-0-0-0-0.ipv6-literal.net/64", base8564, allSingleHexIPv6, allSingleOctalIPv6)
	t.testIPv6Strings("*:*/64", false, "*:*:*:*:0:0:0:0/64", "*:*:*:*:*:*:*:*", "*:*:*:*:*:*:*:*", "%:%:%:%:%:%:%:%", "0000-ffff:0000-ffff:0000-ffff:0000-ffff:0000:0000:0000:0000/64", "*:*:*:*::/64", "*:*:*:*::/64", "*:*:*:*::/64", "*:*:*:*:*:*:*:*", "*:*:*:*::0.0.0.0/64", "*:*:*:*::0.0.0.0/64", "*:*:*:*::/64", "*:*:*:*::/64", "*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.ip6.arpa", "*-*-*-*-0-0-0-0.ipv6-literal.net/64", base8564, allSingleHexIPv6, allSingleOctalIPv6)
	t.testIPv6Strings("*:*/64", true, "*:*:*:*:0:0:0:0/64", "*:*:*:*:*:*:*:*", "*:*:*:*:*:*:*:*", "%:%:%:%:%:%:%:%", "0000-ffff:0000-ffff:0000-ffff:0000-ffff:0000:0000:0000:0000/64", "*:*:*:*::/64", "*:*:*:*::/64", "*:*:*:*::/64", "*:*:*:*:*:*:*:*", "*:*:*:*::0.0.0.0/64", "*:*:*:*::0.0.0.0/64", "*:*:*:*::/64", "*:*:*:*::/64", "*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.ip6.arpa", "*-*-*-*-0-0-0-0.ipv6-literal.net/64", base8564, allSingleHexIPv6, allSingleOctalIPv6)
	t.testIPv6Strings("*/ffff::", false, "*:0:0:0:0:0:0:0/16", "*:*:*:*:*:*:*:*", "*:*:*:*:*:*:*:*", "%:%:%:%:%:%:%:%", "0000-ffff:0000:0000:0000:0000:0000:0000:0000/16", "*::/16", "*::/16", "*::/16", "*:*:*:*:*:*:*:*", "*::0.0.0.0/16", "*::0.0.0.0/16", "*::/16", "*::/16", "*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.ip6.arpa", "*-0-0-0-0-0-0-0.ipv6-literal.net/16", base8516, allSingleHexIPv6, allSingleOctalIPv6)
	t.testIPv6Strings("*/ffff::", true, "*:0:0:0:0:0:0:0/16", "*:*:*:*:*:*:*:*", "*:*:*:*:*:*:*:*", "%:%:%:%:%:%:%:%", "0000-ffff:0000:0000:0000:0000:0000:0000:0000/16", "*::/16", "*::/16", "*::/16", "*:*:*:*:*:*:*:*", "*::0.0.0.0/16", "*::0.0.0.0/16", "*::/16", "*::/16", "*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.ip6.arpa", "*-0-0-0-0-0-0-0.ipv6-literal.net/16", base8516, allSingleHexIPv6, allSingleOctalIPv6)

	t.testIPv6Strings("", true, "0:0:0:0:0:0:0:1", "0:0:0:0:0:0:0:1", "::1", "0:0:0:0:0:0:0:1", "0000:0000:0000:0000:0000:0000:0000:0001", "::1", "::1", "::1", "::1", "::0.0.0.1", "::0.0.0.1", "::0.0.0.1", "::0.0.0.1", "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa", "0-0-0-0-0-0-0-1.ipv6-literal.net", "00000000000000000001", "0x00000000000000000000000000000001", "00000000000000000000000000000000000000000001")

	addressEmpty := t.createParamsHost("", emptyAddressOptions)
	t.hostLabelsHostTest(addressEmpty, []string{"127", "0", "0", "1"})
	addressEmpty2 := t.createParamsHost("", emptyAddressNoLoopbackOptions)
	t.hostLabelsHostTest(addressEmpty2, []string{})
	hostEmpty := t.createParamsHost("", hostOptionsSpecial)
	t.hostLabelsHostTest(hostEmpty, []string{})
}

func (t specialTypesTester) testIPv4Strings(addr string, explicit bool, normalizedString, normalizedWildcardString, sqlString, fullString, reverseDNSString, singleHex, singleOctal string) {
	w := t.createParamsAddress(addr, addressOptionsSpecial)
	var ipAddr *ipaddr.IPAddress
	if explicit {
		ipAddr = w.GetVersionedAddress(ipaddr.IPv4)
	} else {
		ipAddr = w.GetAddress()
	}
	t.testStrings(w, ipAddr, normalizedString, normalizedWildcardString, normalizedWildcardString, sqlString, fullString,
		normalizedString, normalizedString, normalizedWildcardString, normalizedString, normalizedWildcardString, reverseDNSString, normalizedString,
		singleHex, singleOctal)
}

func (t specialTypesTester) testIPv6Strings(addr string,
	explicit bool,
	normalizedString,
	normalizedWildcardString,
	canonicalWildcardString,
	sqlString,
	fullString,
	compressedString,
	canonicalString,
	subnetString,
	compressedWildcardString,
	mixedStringNoCompressMixed,
	mixedStringNoCompressHost,
	mixedStringCompressCoveredHost,
	mixedString,
	reverseDNSString,
	uncHostString,
	base85String,
	singleHex,
	singleOctal string) {
	w := t.createParamsAddress(addr, addressOptionsSpecial)
	var ipAddr *ipaddr.IPAddress
	if explicit {
		ipAddr = w.GetVersionedAddress(ipaddr.IPv6)
	} else {
		ipAddr = w.GetAddress()
	}
	t.testBase.testIPv6Strings(w,
		ipAddr,
		normalizedString,
		normalizedWildcardString,
		canonicalWildcardString,
		sqlString,
		fullString,
		compressedString,
		canonicalString,
		subnetString,
		compressedWildcardString,
		mixedStringNoCompressMixed,
		mixedStringNoCompressHost,
		mixedStringCompressCoveredHost,
		mixedString,
		reverseDNSString,
		uncHostString,
		base85String,
		singleHex,
		singleOctal)
}
