package test

type ipAddressRangeTester struct {
	ipAddressTester
}

func (t ipAddressRangeTester) run() {
	t.testEquivalentPrefix("*.*.*.*", 0)
	t.testEquivalentPrefix("0-127.*.*.*", 1)
	t.testEquivalentPrefix("128-255.*.*.*", 1)
	t.testEquivalentPrefix("*.*.*.*/1", 0)
	//t.testEquivalentPrefix("0.*.*.*/1", 1)
	t.testEquivalentPrefix("0.*.*.*/1", 8)
	t.testEquivalentPrefix("128-255.*.*.*/1", 1)
	t.testEquivalentPrefix("1.2.*.*", 16)
	t.testEquivalentPrefix("1.2.*.*/24", 16)
	t.testEquivalentMinPrefix("1.2.*.0/24", cacheTestBits(16), 16)
	t.testEquivalentMinPrefix("1.2.0-255.0/24", cacheTestBits(16), 16)
	t.testEquivalentPrefix("1.2.1.0/24", 24)
	t.testEquivalentPrefix("1.2.1.*/24", 24)
	t.testEquivalentPrefix("1.2.1.*", 24)
	t.testEquivalentMinPrefix("1.2.*.4", nil, 32)
	t.testEquivalentPrefix("1.2.252-255.*", 22)
	t.testEquivalentPrefix("1.2.252-255.0-255", 22)
	t.testEquivalentPrefix("1.2.0-3.0-255", 22)
	t.testEquivalentPrefix("1.2.128-131.0-255", 22)
	t.testEquivalentMinPrefix("1.2.253-255.0-255", nil, 24)
	t.testEquivalentMinPrefix("1.2.252-255.0-254", nil, 32)
	t.testEquivalentMinPrefix("1.2.251-255.0-254", nil, 32)
	t.testEquivalentMinPrefix("1.2.251-255.0-255", nil, 24)

	t.testEquivalentMinPrefix("1.2.1-3.*", nil, 24)
	t.testEquivalentPrefix("1.2.0-3.*", 22)

	t.testEquivalentPrefix("*:*", 0)
	t.testEquivalentPrefix("::/0", 0)
	t.testEquivalentMinPrefix("0-1::/0", nil, 128)
	t.testEquivalentPrefix("::/1", 1)
	t.testEquivalentMinPrefix("0-1::/1", nil, 128)
	t.testEquivalentMinPrefix("8000-ffff::/1", nil, 128)
	t.testEquivalentPrefix("8000-ffff:*", 1)
	t.testEquivalentMinPrefix("7fff-ffff:*", nil, 16)
	t.testEquivalentMinPrefix("7fff-ffff:*/1", nil, 16)
	t.testEquivalentPrefix("11:8000-ffff:*/1", 17)
	t.testEquivalentPrefix("11:8000-ffff:*", 17)
	t.testEquivalentPrefix("1:2:*", 32)
	t.testEquivalentMinPrefix("1:2:*:*::/64", cacheTestBits(32), 32)
	t.testEquivalentPrefix("1:2:*:*/64", 32)
	t.testEquivalentPrefix("1:2:3:4:5:*:*/64", 80)
	t.testEquivalentMinPrefix("1:2:*::/64", nil, 64)
	t.testEquivalentMinPrefix("1:2:*::", nil, 128)
	t.testEquivalentPrefix("1:2:8000-ffff:*", 33)
	t.testEquivalentPrefix("1:2:0000-7fff:*", 33)
	t.testEquivalentPrefix("1:2:c000-ffff:*", 34)
	t.testEquivalentPrefix("1:2:0000-3fff:*", 34)
	t.testEquivalentPrefix("1:2:8000-bfff:*", 34)
	t.testEquivalentPrefix("1:2:4000-7fff:*", 34)
	t.testEquivalentPrefix("1:2:fffc-ffff:*", 46)
	t.testEquivalentPrefix("1:2:fffc-ffff:0-ffff:*", 46)
	t.testEquivalentMinPrefix("1:2:fffd-ffff:0-ffff:*", nil, 48)
	t.testEquivalentMinPrefix("1:2:fffc-ffff:0-fffe:*", nil, 64)
	t.testEquivalentMinPrefix("1:2:fffb-ffff:0-fffe:*", nil, 64)
	t.testEquivalentMinPrefix("1:2:fffb-ffff:0-ffff:*", nil, 48)

	t.testReverse("1:2:*:4:5:6:a:b", false, false)
	t.testReverse("1:1:1:1-fffe:2:3:3:3", false, false)                                   // 0x1-0xfffe reverseBitsPerByte throws
	t.testReverse("1-fffe:0-ffff:0-ffff:0-fffe:1-ffff:1-ffff:1-fffe:1-ffff", false, true) // all reversible
	t.testReverse("1-fffe:0-ffff:1-ffff:0-fffe:0-fffe:1-ffff:0-ffff:1-fffe", true, true)  // all reversible
	t.testReverse("1:1:1:0-fffe:1-fffe:*:1:1", false, false)                              // 100-feff or aa01-aafe are byte reversible becoming 100-feff and xx01-xxfe where x is reverse of a
	t.testReverse("ffff:80:*:ff:01:ffff", false, false)
	t.testReverse("ffff:8000:fffe::7fff:0001:ffff", true, false)
	t.testReverse("ffff:8000:*:8000:1:*:01:ffff", true, false)
	t.testReverse("ffff:8118:ffff:*:1-fffe:ffff", false, true)
	t.testReverse("ffff:8181:c3c3::4224:2400:0-fffe", false, true)
	t.testReverse("ffff:1:ff:ff:*:*", false, false)

	t.testPrefixes("255.127.0.0/16",
		16, -5,
		"255.127.0.0/24",
		"255.0.0.0/8",
		"255.96.*.*/11",
		//"255.96.0.0/11",
		"255.127.0.0/16",
		"255.127.0.0/16")

	t.testPrefixes("255.127.0.0/17",
		16, -17,
		"255.127.0.0/24",
		"255.127.0.0/16",
		//"0.0.0.0/0",
		"0.0.0-127.*/0",
		"255.127.0-127.*/16",
		//"255.127.0.0/16",
		"255.127.0.0/16")

	t.testPrefixes("ffff:ffff:1:ffff::/64",
		16, -5,
		"ffff:ffff:1:ffff::/80",
		"ffff:ffff:1::/48",
		"ffff:ffff:1:ffe0:*:*:*:*/59",
		//"ffff:ffff:1:ffe0::/59",
		//"ffff::/16",
		"ffff::*:*:*:*/16",
		"ffff::/16")

	t.testPrefixes("ffff:ffff:1:ffff::/64",
		16, 1,
		"ffff:ffff:1:ffff::/80",
		"ffff:ffff:1::/48",
		"ffff:ffff:1:ffff::/65",
		//"ffff::/16",
		"ffff::*:*:*:*/16",
		"ffff::/16")

	t.testBitwiseOr("1.2.0.0/16", cacheTestBits(8), "0.0.3.248", "1.2.3.248-255")
	t.testBitwiseOr("1.2.0.0/16", cacheTestBits(7), "0.0.2.0", "1.2.2-3.*")
	t.testBitwiseOr("1.2.*.*", cacheTestBits(7), "0.0.3.0", "")
	t.testBitwiseOr("1.2.0-3.*", cacheTestBits(0), "0.0.3.0", "1.2.3.*")
	t.testBitwiseOr("1.2.0.0/16", cacheTestBits(7), "0.0.3.0", "1.2.3.*")
	t.testBitwiseOr("0.0.0.0/0", cacheTestBits(0), "128.192.224.240", "128-255.192-255.224-255.240-255")
	t.testBitwiseOr("*.*", cacheTestBits(0), "128.192.224.240", "128-255.192-255.224-255.240-255")
	t.testBitwiseOr("0.0.0.0/0", cacheTestBits(0), "128.192.224.64", "")
	t.testBitwiseOr("*.*", cacheTestBits(0), "128.192.224.64", "")
	t.testPrefixBitwiseOr("1.3.0.0/15", 24, "0.0.255.1", "1.3.255.0", "1.3.255.1/15")
	t.testPrefixBitwiseOr("1.3.0.1/15", 24, "0.0.255.1", "1.3.255.1/24", "1.3.255.1/15")
	t.testPrefixBitwiseOr("1.3.0.1/15", 24, "0.0.255.0", "1.3.255.1/24", "1.3.255.1/15")
	t.testPrefixBitwiseOr("1.2.0.0/22", 24, "0.0.3.248", "1.2.3.0/24", ("1.2.3.248-255/22"))
	t.testPrefixBitwiseOr("1.2.0.0/24", 24, "0.0.3.248", "1.2.3.0/24", ("1.2.3.248-255/24"))
	t.testPrefixBitwiseOr("1.2.0.0/22", 23, "0.0.3.0", "1.2.2.0/23", "1.2.3.0-255/22")
	t.testPrefixBitwiseOr("1.2.0.0/24", 23, "0.0.3.0", "1.2.2.*", ("1.2.3.0-255/24"))
	t.testPrefixBitwiseOr("1:2::/46", 47, "0:0:3::", "1:2:2::/47", "1:2:3:*:*:*:*:*/46")

	t.testPrefixBitwiseOr("0.0.0.0/16", 18, "0.0.2.8", "0.0.0-192.0/18", "")

	t.testBitwiseOr("1:2::/32", cacheTestBits(16), "0:0:3:fff8::", "1:2:3:fff8-ffff:*")
	t.testBitwiseOr("1:2::/32", cacheTestBits(15), "0:0:2::", "1:2:2-3:*")
	t.testBitwiseOr("1:2:*", cacheTestBits(0), "0:0:8000::", "1:2:8000-ffff:*")
	t.testBitwiseOr("1:2:*", cacheTestBits(0), "0:0:c000::", "1:2:c000-ffff:*")
	t.testBitwiseOr("1:2::/32", cacheTestBits(15), "0:0:3::", "1:2:3:*")
	t.testBitwiseOr("::/0", cacheTestBits(0), "8000:c000:e000:fff0::", "8000-ffff:c000-ffff:e000-ffff:fff0-ffff:*")
	t.testBitwiseOr("*:*", cacheTestBits(0), "8000:c000:e000:fff0::", "8000-ffff:c000-ffff:e000-ffff:fff0-ffff:*")
	t.testBitwiseOr("::/0", cacheTestBits(0), "8000:c000:e000:4000::", "")
	t.testBitwiseOr("1:1::/16", cacheTestBits(32), "0:2:3::ffff", "1:2:3::ffff")       //note the prefix length is dropped to become "1.2.3.*", but equality still holds
	t.testBitwiseOr("1:1:0:*:0/16", nil, "0:2:3:*:ffff", "1:3:3:*:*:*:*:ffff")         //note the prefix length is dropped to become "1.2.3.*", but equality still holds
	t.testBitwiseOr("1:0:0:1::/16", cacheTestBits(32), "0:2:3::ffff", "1:2:3:1::ffff") //note the prefix length is dropped to become "1.2.3.*", but equality still holds
	t.testPrefixBitwiseOr("::/32", 34, "0:0:2:8::", "0:0:0-c000::/34", "")

	t.testDelimitedCount("1,2-3,4:3:4,5:6:7:8:ffff:ffff", 8)
	t.testDelimitedCount("1,2::3,6:7:8:4,5-6:6,8", 16)
	t.testDelimitedCount("1:2:3:*:4::5", 1)
	t.testDelimitedCount("1:2,3,*:3:ffff:ffff:6:4:5,ff,7,8,99", 15)
	t.testDelimitedCount("0,1-2,3,5:3::6:4:5,ffff,7,8,99", 30)

	//if(allPrefixesAreSubnets) {
	//	testMatches(true, "1.2.3.4/16", "1.2.*.*");
	//	testMatches(true, "1.2.3.4/16", "1.2.*");
	//	testMatches(false, "1.2.3.4/15", "1.2.*.*");
	//	testMatches(false, "1.2.3.4/17", "1.2.*.*");
	//} else {
	t.testMatches(true, "1.2.3.4/16", "1.2.3.4")
	t.testMatches(true, "1.2.3.4/15", "1.2.3.4")
	t.testMatches(true, "1.2.3.4/17", "1.2.3.4")

	t.testMatches(true, "1.2.0.4/16", "1.2.0.4")
	t.testMatches(true, "1.2.3.0/16", "1.2.3.0")

	t.testMatches(true, "1.2.3.4/14", "1.2.3.4")
	t.testMatches(true, "1.2.0.4/14", "1.2.0.4")
	t.testMatches(true, "1.2.0.0/14", "1.2.0.0")
	t.testMatches(true, "1.0.3.0/14", "1.0.3.0")

	//}

	t.testMatches(true, "1.2.0.0/16", "1.2.*.*")
	t.testMatches(true, "1.2.0.0/16", "1.2.*")

	t.testMatches(true, "1.4.0.0/14", "1.4-7.*")
	t.testMatches(true, "1.4.0.0/14", "1.4-7.*.*")

	t.testMatches(false, "1.2.3.4/16", "1.2.*/255.255.0.0")
	t.testMatches(false, "1.2.3.4/15", "1.2.3.*/255.254.0.0")
	t.testMatches(false, "1.2.3.4/17", "1.2.3.*/255.255.128.0")

	t.testMatches(true, "1.2.0.0/16", "1.2.*/255.255.0.0")
	t.testMatches(true, "1.2.3.*/15", "1.2.3.*/255.254.0.0")
	t.testMatches(true, "1.2.3.*/17", "1.2.3.*/255.255.128.0")

	t.testMatches(false, "1.1.3.4/15", "1.2.3.*/255.254.0.0")
	t.testMatches(false, "1.1.3.4/17", "1.2.3.*/255.255.128.0")

	t.testMatches(true, "1:2::/32", "1:2:*:*:*:*:*:*")
	t.testMatches(true, "1:2::/32", "1:2:*:*:*:*:*.*.*.*")
	t.testMatches(true, "1:2::/32", "1:2:*")
	t.testMatches(false, "1:2::/32", "1:2:*:*:*:*:3:*")
	t.testMatches(false, "1:2::/32", "1:2:*:*:*:*:*.*.3.*")
	t.testMatches(false, "1:2::/31", "1:2:*")
	t.testMatches(false, "1:2::/33", "1:2::*")

	t.testMatches(true, "1:2::/32", "1:2:*:*:*:*:*:*/ffff:ffff::")
	t.testMatches(true, "1:2::/31", "1:2-3:*:*:*:*:*:*/ffff:fffe::")
	t.testMatches(true, "1:2::/33", "1:2:0-7fff:*:*:*:*:*/ffff:ffff:8000::")

	t.testMatches(false, "1:2::/24", "1:__:*")
	t.testMatches(false, "1:2::/28", "1:_::/32")
	t.testMatches(false, "1:2::/20", "1:___::/32")
	t.testMatches(false, "1:2::/16", "1:____::/32")
	t.testMatches(false, "1:ffef::/24", "1:ff__::/32")
	t.testMatches(false, "1:ffef::/24", "1:ff__:*:*")

	t.testMatches(true, "1::/24", "1:__:*")
	t.testMatches(true, "1::/28", "1:_::/32")
	t.testMatches(true, "1::/20", "1:___::/32")
	t.testMatches(true, "1::/16", "1:____::/32")
	t.testMatches(true, "1:ff00::/24", "1:ff__::/32")
	t.testMatches(true, "1:ff00::/24", "1:ff__:*:*")

	t.testMatches(true, "250-255.200-255.0-255.20-29", "25_.2__.___.2_")
	t.testMatches(true, "150-159.100-199.0-99.10-19", "15_.1__.__.1_")
	t.testMatches(false, "251-255.200-255.0-255.20-29", "25_.2__.___.2_")
	t.testMatches(false, "150-158.100-199.0-99.10-19", "15_.1__.__.1_")
	t.testMatches(true, "250-25f:200-2ff:0-fff:20-2f::", "25_:2__:___:2_::")
	t.testMatches(true, "150-15f:100-1ff:0-ff:10-1f::", "15_:1__:__:1_::")
	t.testMatches(false, "250-25f:201-2ff:0-fff:20-2f::", "25_:2__:___:2_::")
	t.testMatches(false, "150-15f:100-1ef:0-ff:10-1f::", "15_:1__:__:1_::")
	t.testMatches(true, "::250-25f:200-2ff:0-fff:20-2f", "::25_:2__:___:2_")
	t.testMatches(true, "::150-15f:100-1ff:0-ff:10-1f", "::15_:1__:__:1_")
	t.testMatches(true, "250-25f:200-2ff::0-fff:20-2f", "25_:2__::___:2_")
	t.testMatches(true, "150-15f:100-1ff::0-ff:10-1f", "15_:1__::__:1_")

	t.testMatches(true, "1:2:3:4:5:6:1-2.*.0.4", "1:2:3:4:5:6:100-2ff:4")         // mixed starting with range
	t.testMatches(true, "1:2:3:4:5:6:1.2.0.4-5", "1:2:3:4:5:6:102:4-5")           // mixed ending with range
	t.testMatches(true, "1:2:3:4:5:6:1.2.0.*", "1:2:3:4:5:6:102:0-ff")            // mixed ending with range
	t.testMatches(true, "1:2:3:4:5:6:1.2.0._", "1:2:3:4:5:6:102:0-9")             // mixed ending with range
	t.testMatches(true, "1:2:3:4:5:6:1.2.0.1_", "1:2:3:4:5:6:102:a-13")           // mixed ending with range
	t.testMatches(true, "1:2:3:4:5:6:1.2.0.4-5", "1:2:3:4:5:6:102:5-4")           // mixed ending with range
	t.testMatches(true, "1:2:3:4:5:6:1.2.0.4-5", "1:2:3:4:5:6:1.2.0.5-4")         // mixed ending with range
	t.testMatches(true, "1:2:3:4:5:6:1.2-255.0.4-5", "1:2:3:4:5:6:1.255-2.0.5-4") // mixed ending with range
	t.testMatches(false, "1:2:3:4:5:6:1-3.2.0.4-5", "1:2:3:4:5:6:3-1.2.0.5-4")    // inet.ipaddr.IncompatibleAddressException: 1-3, 2, IP Address error: IPv4 segment ranges cannot be converted to IPv6 segment ranges
	t.testMatches(true, "1:2:3:4:5:6:1-3.*.0.4-5", "1:2:3:4:5:6:3-1.*.0.5-4")
	t.testMatches(true, "1:2:3:4:5:6:1-3.*.0.4-5", "1:2:3:4:5:6:3ff-100:5-4")

	t.testMatches(true, "1.2.2-3.4", "1.2.3-2.4")
	t.testMatches(true, "1.255-2.2-3.4", "1.2-255.3-2.4")
	t.testMatches(true, "1:2:3:4:5:6:7:7-8", "1:2:3:4:5:6:7:8-7")
	t.testMatches(true, "1-ffff:2:3:4:5:6:7:7-8", "ffff-1:2:3:4:5:6:7:8-7")
	t.testMatches(true, "1-ffff:2:3:4:aa-5:6:7:7-8", "ffff-1:2:3:4:5-aa:6:7:8-7")
	t.testMatches(true, "1.2.*.4", "1.2.255-0.4")
	t.testMatches(true, "1:2:3:4:5:*:7:7-8", "1:2:3:4:5:ffff-0:7:8-7")

	t.testMatchesInetAton(true, "1.2.3", "1.2.0.3", true)
	t.testMatchesInetAton(true, "1.2.2-3.4", "0x1.0x2.2-0x3.0x4", true)
	t.testMatchesInetAton(true, "1.2.2-3.4", "0x1.0x2.0x2-0x3.0x4", true)
	t.testMatchesInetAton(true, "1.2.2-3.4", "0x1.0x2.0x2-3.0x4", true)
	t.testMatchesInetAton(true, "1.2.2-3.4", "01.02.2-03.04", true)
	t.testMatchesInetAton(true, "1.2.2-3.4", "01.02.2-3.04", true)
	t.testMatchesInetAton(true, "1.2.2-3.4", "01.02.02-03.04", true)
	t.testMatchesInetAton(true, "1.2.2-3.4", "01.02.0x2-03.04", true)
	t.testMatchesInetAton(true, "1.2.2-3.4", "01.02.0x2-0x3.04", true)
	t.testMatchesInetAton(true, "1.2.0200-0277.4", "01.02.02__.04", true)
	t.testMatchesInetAton(true, "1.2.0x20-0x2f.4", "01.02.0x2_.04", true)
	t.testMatchesInetAton(true, "1.2.0x10-0x1f.4", "01.02.0x1_.04", true)
	t.testMatchesInetAton(true, "1.2.*.4", "01.02.0x__.04", true)
	t.testMatchesInetAton(true, "1.2.0-077.4", "01.02.0__.04", true)

	t.testMatchesInetAton(true, "1.2.2-3.4", "01.02.0x2-0x3.04", true)

	t.testMatchesInetAton(true, "0.0.0-1.4", "00.0x0.0x00-0x000001.04", true)
	t.testMatchesInetAton(true, "11.10-11.10-11.10-11", "11.012-0xb.0xa-013.012-0xB", true)
	t.testMatchesInetAton(true, "11.10-11.*.10-11", "11.012-0xb.0x0-0xff.012-0xB", true)
	t.testMatchesInetAton(true, "1.*", "1.*.*.0x0-0xff", true)
	t.testMatchesInetAton(true, "1.*", "1.0-255.0-65535", true)
	t.testMatchesInetAton(true, "1.*", "1.0-0xff.0-0xffff", true)
	t.testMatchesInetAton(true, "1.*", "1.0x0-0xff.00-0xffff", true)

	t.testMatchesInetAton(true, "11.11.0-11.*", "11.11.0-0xbff", true)
	t.testMatchesInetAton(true, "11.0.0.11-11", "11.0x00000000000000000b-0000000000000000000013", true)
	t.testMatchesInetAton(true, "11.1-11.*/16", "11.0x10000-786431/16", true)
	t.testMatchesInetAton(true, "11.1-11.*/16", "11.0x10000-0xbffff/16", true)

	t.testMatches(true, "1:2:3:4:5:6:1.2.3.4/128", "1:2:3:4:5:6:102:304")

	t.testMatches(false, "1:2:3:4:5:6:1.2.3.4/96", "1:2:3:4:5:6:*:*")
	t.testMatches(false, "1:2:3:4:5:6:255.2.3.4/97", "1:2:3:4:5:6:8000-ffff:*")
	t.testMatches(false, "1:2:3:4:5:6:1.2.3.4/112", "1:2:3:4:5:6:102:*")
	t.testMatches(false, "1:2:3:4:5:6:1.2.255.4/115", "1:2:3:4:5:6:102:e000-ffff")

	t.testMatches(false, "1.2.3.4/0", "*.*")
	t.testMatches(false, "1.2.3.4/0", "*.*.*.*")
	t.testMatches(false, "1:2:3:4:5:6:7:8/0", "*:*")
	t.testMatches(false, "1:2:3:4:5:6:7:8/0", "*:*:*:*:*:*:*:*")

	t.testMatches(true, "1:2:3:4:5:6:1.2.3.4/96", "1:2:3:4:5:6:102:304")
	t.testMatches(true, "1:2:3:4:5:6:255.2.3.4/97", "1:2:3:4:5:6:ff02:304")
	t.testMatches(true, "1:2:3:4:5:6:1.2.3.4/112", "1:2:3:4:5:6:102:304")
	t.testMatches(true, "1:2:3:4:5:6:1.2.255.4/115", "1:2:3:4:5:6:102:ff04")

	t.testMatches(true, "1.2.3.4/0", "1.2.3.4")
	t.testMatches(true, "1.2.3.4/0", "1.2.3.4")
	t.testMatches(true, "1:2:3:4:5:6:7:8/0", "1:2:3:4:5:6:7:8")
	t.testMatches(true, "1:2:3:4:5:6:7:8/0", "1:2:3:4:5:6:7:8")

	t.testMatches(true, "1:2:3:4:5:6:0.0.0.0/96", "1:2:3:4:5:6:*:*")
	t.testMatches(false, "1:2:3:4:5:6:255.0.0.0/97", "1:2:3:4:5:6:8000-ffff:*")
	t.testMatches(true, "1:2:3:4:5:6:255.0.0.0/97", "1:2:3:4:5:6:ff00:0")
	t.testMatches(true, "1:2:3:4:5:6:128.0.0.0/97", "1:2:3:4:5:6:8000-ffff:*")
	t.testMatches(true, "1:2:3:4:5:6:1.2.0.0/112", "1:2:3:4:5:6:102:*")
	t.testMatches(false, "1:2:3:4:5:6:1.2.255.0/115", "1:2:3:4:5:6:102:e000-ffff")
	t.testMatches(true, "1:2:3:4:5:6:1.2.255.0/115", "1:2:3:4:5:6:102:FF00")
	t.testMatches(true, "1:2:3:4:5:6:1.2.224.0/115", "1:2:3:4:5:6:102:e000-ffff")

	t.testMatches(true, "0.0.0.0/0", "*.*")
	t.testMatches(true, "0.0.0.0/0", "*.*.*.*")
	t.testMatches(true, "::/0", "*:*")
	t.testMatches(true, "::/0", "*:*:*:*:*:*:*:*")

	t.testMatches(true, "1-02.03-4.05-06.07", "1-2.3-4.5-6.7")
	t.testMatches(true, "1-002.003-4.005-006.007", "1-2.3-4.5-6.7")

	t.testMatches(true, "1-2.0-0.00-00.00-0", "1-2.0.0.0")
	t.testMatches(true, "1-2:0-0:00-00:00-0:0-000:0000-0000:0000-00:0000-0", "1-2:0:0:0:0:0:0:0")
	t.testMatches(true, "00-0.0-0.00-00.00-0", "0.0.0.0")
	t.testMatches(true, "0-00:0-0:00-00:00-0:0-000:0000-0000:0000-00:0000-0", "::")

	t.testMatches(true, "-1.22.33.4", "0-1.22.33.4")
	t.testMatches(true, "-1.22.33.4", "0-1.22.33.4")
	t.testMatches(true, "22.1-.33.4", "22.1-255.33.4")
	t.testMatches(true, "22.33.4.1-", "22.33.4.1-255")
	t.testMatches(true, "aa:-1:cc::d:ee:f", "aa:0-1:cc::d:ee:f")
	t.testMatches(true, "aa:dd-:cc::d:ee:f", "aa:dd-ffff:cc::d:ee:f")
	t.testMatches(true, "aa:dd-:cc::d:ee:f-", "aa:dd-ffff:cc::d:ee:f-ffff")
	t.testMatches(true, "-:0:0:0:0:0:0:0", "0-ffff:0:0:0:0:0:0:0")
	t.testMatches(true, "0-:0:0:0:0:0:0:0", "-ffff:0:0:0:0:0:0:0")
	t.testMatches(true, "ffff:0:0:0:0:0:0:0", "ffff-:0:0:0:0:0:0:0")
	t.testMatches(true, "-0:0:0:0:0:0:0:0", "::")
	t.testMatches(true, "0:0:-:0:0:0:0:0", "0:0:0-ffff:0:0:0:0:0")
	t.testMatches(true, "0:0:0-:0:0:0:0:0", "0:0:-ffff:0:0:0:0:0")
	t.testMatches(true, "0:0:ffff:0:0:0:0:0", "0:0:ffff-:0:0:0:0:0")
	t.testMatches(true, "0:0:-0:0:0:0:0:0", "::")
	t.testMatches(true, "0:-:0:0:0:0:0:0", "0:0-ffff:0:0:0:0:0:0")
	t.testMatches(true, "0:0-:0:0:0:0:0:0", "0:-ffff:0:0:0:0:0:0")
	t.testMatches(true, "0:ffff:0:0:0:0:0:0", "0:ffff-:0:0:0:0:0:0")
	t.testMatches(true, "0:-0:0:0:0:0:0:0", "::")

	t.testMatches(true, "::1:0:0:0.0.0.0", "0:0:0:1::0.0.0.0")

	t.testMatches(true, "1::-1:16", "1::0-1:16")
	//if isNoAutoSubnets {
	//	t.testMatches(true, "1::-1:16/16", "1::0-1:16")
	//	t.testMatches(true, "1::-1:16", "1::0-1:16/16")
	//	t.testMatches(true, "1:-1::16/16", "1:0-1::16")
	//	t.testMatches(true, "1:-1::16", "1:0-1::16/16")
	//} else if allPrefixesAreSubnets {
	//	t.testMatches(true, "1:-1::16/32", "1:0-1:*")
	//	t.testMatches(true, "1:-1:*", "1:0-1::16/32")
	//} else {
	t.testMatches(true, "1:-1::16/32", "1:0-1::16")
	t.testMatches(true, "1:-1::16", "1:0-1::16/32")
	//}
	t.testMatches(true, "0.0.0.-", "0.0.0.*")           // ok
	t.testMatches(true, "1-.0.0.1-", "1-255.0.0.1-255") // ok // more than one inferred range

	t.testMatches(true, "0b1.0b01.0b101.1-0b11111111", "1.1.5.1-255")
	t.testMatches(true, "0b1.0b01.0b101.0b11110000-0b11111111", "1.1.5.240-255")
	t.testMatches(true, "0b1.0b01.0b101.0b1111____", "1.1.5.240-255")

	t.testMatches(true, "::0b0000111100001111-0b1111000011110000:3", "::f0f-f0f0:3")
	t.testMatches(true, "::0b000011110000____:3", "::f00-f0f:3")
	t.testMatches(true, "::0B000011110000____:3", "::f00-f0f:3")
	t.testMatches(true, "::f0f-0b1111000011110000:3", "::f0f-f0f0:3")
	t.testMatches(true, "::0b0000111100001111-f0f0:3", "::f0f-f0f0:3")
	t.testMatches(true, "::0B0000111100001111-f0f0:3", "::f0f-f0f0:3")
}
