package test

import "github.com/seancfoley/ipaddress/ipaddress-go/ipaddr"

type ipAddressRangeTester struct {
	ipAddressTester
}

func (t ipAddressRangeTester) testStrings() {

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

	t.ipv4test(true, "1.2.*.4/1")
	t.ipv4test(false, "1.2.*.4/-1")
	t.ipv4test(false, "1.2.*.4/")
	t.ipv4test(false, "1.2.*.4/x")
	t.ipv4test(true, "1.2.*.4/33") //we are now allowing extra-large prefixes
	t.ipv6test(true, "1:*::1/1")
	t.ipv6test(false, "1:*::1/-1")
	t.ipv6test(false, "1:*::1/")
	t.ipv6test(false, "1:*::1/x")
	t.ipv6test(false, "1:*::1/129") //we are not allowing extra-large prefixes

	//masks that have wildcards in them
	t.ipv4test(false, "1.2.3.4/*")
	t.ipv4test(false, "1.2.*.4/*")
	t.ipv4test(false, "1.2.3.4/1-2.2.3.4")
	t.ipv4test(false, "1.2.*.4/1-2.2.3.4")
	t.ipv4test(false, "1.2.3.4/**")
	t.ipv4test(false, "1.2.*.4/**")
	t.ipv4test(false, "1.2.3.4/*.*")
	t.ipv4test(false, "1.2.*.4/*.*")
	t.ipv4test(false, "1.2.3.4/*:*")
	t.ipv4test(false, "1.2.*.4/*:*")
	t.ipv4test(false, "1.2.3.4/*:*:*:*:*:*:*:*")
	t.ipv4test(false, "1.2.*.4/*:*:*:*:*:*:*:*")
	t.ipv4test(false, "1.2.3.4/1.2.*.4")
	t.ipv4test(false, "1.2.*.4/1.2.*.4")
	t.ipv4test(true, "1.2.*.4/1.2.3.4")
	t.ipv6test(false, "1:2::1/*")
	t.ipv6test(false, "1:*::1/*")
	t.ipv6test(false, "1:2::1/1:1-2:3:4:5:6:7:8")
	t.ipv6test(false, "1:*::1/1:1-2:3:4:5:6:7:8")
	t.ipv6test(false, "1:2::1/**")
	t.ipv6test(false, "1:*::1/**")
	t.ipv6test(false, "1:2::1/*:*")
	t.ipv6test(false, "1:*::1/*:*")
	t.ipv6test(false, "1:2::1/*.*")
	t.ipv6test(false, "1:*::1/*.*")
	t.ipv6test(false, "1:2::1/*.*.*.*")
	t.ipv6test(false, "1:*::1/*.*.*.*")
	t.ipv6test(false, "1:2::1/1:*::2")
	t.ipv6test(false, "1:*::1/1:*::2")
	t.ipv6test(true, "1:*::1/1::2")

	t.ipv4rangetest(true, "1.1.*.100-101", ipaddr.WildcardAndRange)
	t.ipv4rangetest(true, "1.2.*.101-100", ipaddr.WildcardAndRange)   //downwards range
	t.ipv4rangetest(false, "1.2.*.1010-100", ipaddr.WildcardAndRange) //downwards range
	t.ipv4rangetest(true, "1.2.*.101-101", ipaddr.WildcardAndRange)
	t.ipv6rangetest(true, "1:2:f4:a-ff:0-2::1", ipaddr.WildcardAndRange)
	t.ipv6rangetest(true, "1:2:4:ff-a:0-2::1", ipaddr.WildcardAndRange)     //downwards range
	t.ipv6rangetest(false, "1:2:4:ff1ff-a:0-2::1", ipaddr.WildcardAndRange) //downwards range
	t.ipv4rangetest(true, "1.2.*.101-100/24", ipaddr.WildcardAndRange)      //downwards range but covered CIDR

	//these tests create strings that validate ipv4 and ipv6 differently, allowing ranges for one and not the other
	t.ipv4rangestest(true, "1.*.3.4", ipaddr.WildcardAndRange, ipaddr.NoRange)
	t.ipv4rangestest(false, "1.*.3.4", ipaddr.NoRange, ipaddr.WildcardAndRange)
	t.ipv6rangestest(false, "a:*::1.*.3.4", ipaddr.WildcardAndRange, ipaddr.NoRange)
	t.ipv6rangestest(true, "a:*::1.*.3.4", ipaddr.NoRange, ipaddr.WildcardAndRange)
	t.ipv6rangestest(false, "a:*::", ipaddr.WildcardAndRange, ipaddr.NoRange)
	t.ipv6rangestest(true, "a:*::", ipaddr.NoRange, ipaddr.WildcardAndRange)

	//		octal, hex, dec overflow
	//		do it with 1, 2, 3, 4 segments
	t.ipv4_inet_aton_test(true, "0.0.0.1-255")
	t.ipv4_inet_aton_test(false, "0.0.0.1-256")
	t.ipv4_inet_aton_test(true, "0.0.512-65535")
	t.ipv4_inet_aton_test(false, "0.0.512-65536")
	t.ipv4_inet_aton_test(true, "0.65536-16777215")
	t.ipv4_inet_aton_test(false, "0.65536-16777216")
	t.ipv4_inet_aton_test(true, "16777216-4294967295")
	t.ipv4_inet_aton_test(true, "0b00000001000000000000000000000000-4294967295")
	//t.ipv4_inet_aton_test(true, "0b1000000000000000000000000-4294967295");
	t.ipv4_inet_aton_test(false, "16777216-4294967296")
	t.ipv4_inet_aton_test(false, "0.0.0.0x1x")
	t.ipv4_inet_aton_test(false, "0.0.0.1x")
	t.ipv4_inet_aton_test(true, "0.0.0.0x1-0xff")
	t.ipv4_inet_aton_test(false, "0.0.0.0x1-0x100")
	t.ipv4_inet_aton_test(true, "0.0.0xfffe-0xffff")
	t.ipv4_inet_aton_test(false, "0.0.0xfffe-0x10000")
	t.ipv4_inet_aton_test(false, "0.0.0x10000-0x10001")
	t.ipv4_inet_aton_test(true, "0.0-0xffffff")
	t.ipv4_inet_aton_test(false, "0.0-0x1000000")
	t.ipv4_inet_aton_test(true, "0x11000000-0xffffffff")
	t.ipv4_inet_aton_test(false, "0x11000000-0x100000000")
	t.ipv4_inet_aton_test(false, "0x100000000-0x100ffffff")
	t.ipv4_inet_aton_test(true, "0.0.0.00-0377")
	t.ipv4_inet_aton_test(false, "0.0.0.00-0400")
	t.ipv4_inet_aton_test(true, "0.0.0x100-017777")
	t.ipv4_inet_aton_test(false, "0.0.0x100-0200000")
	t.ipv4_inet_aton_test(true, "0.0x10000-077777777")
	//t.ipv4_inet_aton_test(false, "0.0x1-077777777"); the given address throw IncompatibleAddressException as expected, would need to rewrite the test to make that a pass
	t.ipv4_inet_aton_test(false, "0.0x10000-0100000000")
	t.ipv4_inet_aton_test(true, "0x1000000-03777777777")
	t.ipv4_inet_aton_test(true, "0x1000000-037777777777")
	t.ipv4_inet_aton_test(true, "0x1000000-0b11111111111111111111111111111111") //[0-1, 0, 0-255, 0-255]
	t.ipv4_inet_aton_test(false, "0x1000000-040000000000")

	t.ipv4test(true, "*") //toAddress() should not work on this, toAddress(Version) should.

	t.ipv4test2(false, "*%", false, true)  //because the string could represent ipv6, and we are allowing zone, we treat the % as ipv6 zone, and then we invalidate because no zone for ipv4
	t.ipv4test2(false, "*%x", false, true) //no zone for ipv4
	t.ipv4test(true, "**")                 // toAddress() should not work on this, toAddress(Version) should.
	t.ipv6test(true, "**")                 // toAddress() should not work on this, toAddress(Version) should.
	t.ipv6test(true, "*%x")                //ipv6 which allows zone

	t.ipv4test(true, "*.*.*.*") //toAddress() should work on this

	t.ipv4test(true, "1.*.3")

	t.ipv4test(false, "a.*.3.4")
	t.ipv4test(false, "*.a.3.4")
	t.ipv4test(false, "1.*.a.4")
	t.ipv4test(false, "1.*.3.a")

	t.ipv4test(false, ".2.3.*")
	t.ipv4test(false, "1..*.4")
	t.ipv4test(false, "1.*..4")
	t.ipv4test(false, "*.2.3.")

	t.ipv4test(false, "256.*.3.4")
	t.ipv4test(false, "1.256.*.4")
	t.ipv4test(false, "*.2.256.4")
	t.ipv4test(false, "1.*.3.256")

	t.ipv4test(true, "0.0.*.0")
	t.ipv4test(true, "00.*.0.0")
	t.ipv4test(true, "0.00.*.0")
	t.ipv4test(true, "0.*.00.0")
	t.ipv4test(true, "*.0.0.00")
	t.ipv4test(true, "000.0.*.0")
	t.ipv4test(true, "0.000.0.*")
	t.ipv4test(true, "*.0.000.0")
	t.ipv4test(true, "0.0.*.000")

	t.ipv4test(true, "0.0.*.0")
	t.ipv4test(true, "00.*.0.0")
	t.ipv4test(true, "0.00.*.0")
	t.ipv4test(true, "0.*.00.0")
	t.ipv4test(true, "*.0.0.00")
	t.ipv4test(true, "000.0.*.0")
	t.ipv4test(true, "0.000.0.*")
	t.ipv4test(true, "*.0.000.0")
	t.ipv4test(true, "0.0.*.000")

	t.ipv4test(true, "000.000.000.*")

	t.ipv4test(t.isLenient(), "0000.0.*.0")
	t.ipv4test(t.isLenient(), "*.0000.0.0")
	t.ipv4test(t.isLenient(), "0.*.0000.0")
	t.ipv4test(t.isLenient(), "*.0.0.0000")

	t.ipv4test(false, ".0.*.0")
	t.ipv4test(false, "0..*.0")
	t.ipv4test(false, "0.*..0")
	t.ipv4test(false, "*.0.0.")

	t.ipv4test(true, "1.*.3.4/255.1.0.0")
	t.ipv4test(false, "1.*.3.4/255.1.0.0/16")
	t.ipv4test(false, "1.*.3.4/255.*.0.0")   //range in mask
	t.ipv4test(false, "1.*.3.4/255.1-2.0.0") //range in mask
	t.ipv4test(false, "1.*.3.4/1::1")        //mask mismatch
	t.ipv6test(false, "1:*::/1.2.3.4")       //mask mismatch

	t.ipv4test(false, "1.2.3.4/255.*.0.0")   //range in mask
	t.ipv4test(false, "1.2.3.4/255.1-2.0.0") //range in mask
	t.ipv6test(false, "1:2::/1:*::")         //range in mask
	t.ipv6test(false, "1:2::/1:1-2::")       //range in mask

	t.ipv4testOnly(false, "1:2:3:4:5:*:7:8") //fixed
	t.ipv4testOnly(false, "*::1")            //fixed

	t.ipv6test(true, "*")  //toAddress() should not work on this, toAddress(version) should
	t.ipv6test(true, "*%") //toAddress() should not work on this, toAddress(version) should

	t.ipv6test(true, "*:*:*:*:*:*:*:*") //toAddress() should work on this

	t.ipv6test(true, "*::1") // loopback, compressed, non-routable

	t.ipv4test(true, "1.0-0.3.0")
	t.ipv4test(true, "1.0-3.3.0")
	t.ipv4test(true, "1.1-3.3.0")
	t.ipv4test(true, "1-8.1-3.2-4.0-5")

	t.ipv6test(true, "1:0-0:2:0::")
	t.ipv6test(true, "1:0-3:2:0::")
	t.ipv6test(true, "1:1-3:2:0::")
	t.ipv6test(true, "1-fff:1-3:2-4:0-5::")

	t.ipv6test(false, "-:0:0:0:0:0:0:0:0")
	t.ipv6test(true, "-:0:0:0:0:0:0:0") // this is actually equivalent to 0-ffff:0:0:0:0:0:0:0 or 0-:0:0:0:0:0:0:0 or -ffff:0:0:0:0:0:0:0
	t.ipv6test(false, "-:0:0:0:0:0:0")
	t.ipv6test(false, "-:0:0:0:0:0")
	t.ipv6test(false, "-:0:0:0:0")
	t.ipv6test(false, "-:0:0:0")
	t.ipv6test(false, "-:0:0")
	t.ipv6test(false, "-:0")

	t.ipv6test(false, ":-0:0:0:0:0:0:0")
	t.ipv6test(false, ":-0:0:0:0:0:0")
	t.ipv6test(false, ":-0:0:0:0:0")
	t.ipv6test(false, ":-0:0:0:0")
	t.ipv6test(false, ":-0:0:0")
	t.ipv6test(false, ":-0:0")
	t.ipv6test(false, ":-0")

	t.ipv6test(false, "-:1:1:1:1:1:1:1:1")
	t.ipv6test(true, "-:1:1:1:1:1:1:1") // this is actually equivalent to 0-ffff:0:0:0:0:0:0:0 or 0-:0:0:0:0:0:0:0 or -ffff:0:0:0:0:0:0:0
	t.ipv6test(false, "-:1:1:1:1:1:1")
	t.ipv6test(false, "-:1:1:1:1:1")
	t.ipv6test(false, "-:1:1:1:1")
	t.ipv6test(false, "-:1:1:1")
	t.ipv6test(false, "-:1:1")
	t.ipv6test(false, "-:1")

	t.ipv6test(false, ":-1:1:1:1:1:1:1")
	t.ipv6test(false, ":-1:1:1:1:1:1")
	t.ipv6test(false, ":-1:1:1:1:1")
	t.ipv6test(false, ":-1:1:1:1")
	t.ipv6test(false, ":-1:1:1")
	t.ipv6test(false, ":-1:1")
	t.ipv6test(false, ":-1")

	t.ipv6test(true, "::*")                             // unspecified, compressed, non-routable
	t.ipv6test(true, "0:0:*:0:0:0:0:1")                 // loopback, full
	t.ipv6test(true, "0:0:*:0:0:0:0:0")                 // unspecified, full
	t.ipv6test(true, "2001:*:0:0:8:800:200C:417A")      // unicast, full
	t.ipv6test(true, "FF01:*:0:0:0:0:0:101")            // multicast, full
	t.ipv6test(true, "2001:DB8::8:800:200C:*")          // unicast, compressed
	t.ipv6test(true, "FF01::*:101")                     // multicast, compressed
	t.ipv6test(false, "2001:DB8:0:0:8:*:200C:417A:221") // unicast, full
	t.ipv6test(false, "FF01::101::*")                   // multicast, compressed
	t.ipv6test(true, "fe80::217:f2ff:*:ed62")

	t.ipv6test(true, "2001:*:1234:0000:0000:C1C0:ABCD:0876")
	t.ipv6test(true, "3ffe:0b00:0000:0000:0001:0000:*:000a")
	t.ipv6test(true, "FF02:0000:0000:0000:0000:0000:*:0001")
	t.ipv6test(true, "*:0000:0000:0000:0000:0000:0000:0001")
	t.ipv6zerotest(false, "0000:0000:0000:0000:*0000:0000:0000:*0")
	t.ipv6test(t.isLenient(), "02001:*:1234:0000:0000:C1C0:ABCD:0876") // extra 0 not allowed!
	t.ipv6test(false, "2001:0000:1234:0000:0*:C1C0:ABCD:0876")         // extra 0 not allowed!
	t.ipv6test(true, "2001:0000:1234:0000:*:C1C0:ABCD:0876")

	//t.ipv6test(true," 2001:0000:1234:0000:0000:C1C0:ABCD:0876"); // leading space
	//t.ipv6test(true,"2001:0000:1234:0000:0000:C1C0:ABCD:0876 "); // trailing space
	//t.ipv6test(true," 2001:0000:1234:0000:0000:C1C0:ABCD:0876  "); // leading and trailing space

	t.ipv6test(false, "2001:0000:1234:0000:0000:C1C0*:ABCD:0876  0") // junk after valid address
	t.ipv6test(false, "0 2001:0000:123*:0000:0000:C1C0:ABCD:0876")   // junk before valid address
	t.ipv6test(false, "2001:0000:1234: 0000:0000:C1C0:*:0876")       // internal space

	t.ipv6test(true, "3ffe:0b00:*:0001:0000:0000:000a")
	t.ipv6test(false, "3ffe:0b00:1:0001:0000:0000:000a")           // seven segments
	t.ipv6test(false, "FF02:0000:0000:0000:0000:0000:0000:*:0001") // nine segments
	t.ipv6test(false, "3ffe:*::1::a")                              // double "::"
	t.ipv6test(false, "::1111:2222:3333:4444:5555:*::")            // double "::"
	t.ipv6test(true, "2::10")
	t.ipv6test(true, "ff02::1")
	t.ipv6test(true, "fe80:*::")
	t.ipv6test(true, "2002:*::")
	t.ipv6test(true, "2001:*::")
	t.ipv6test(true, "*:0db8:1234::")
	t.ipv6test(true, "::ffff:*:0")
	t.ipv6test(true, "*::1")
	t.ipv6test(true, "1:2:3:4:*:6:7:8")
	t.ipv6test(true, "1:2:*:4:5:6::8")
	t.ipv6test(true, "1:2:3:4:5::*")
	t.ipv6test(true, "1:2:3:*::8")
	t.ipv6test(true, "1:2:3::8")
	t.ipv6test(true, "*:2::8")
	t.ipv6test(true, "1::*")
	t.ipv6test(true, "*::2:3:4:5:6:7")
	t.ipv6test(true, "*::2:3:4:5:6")
	t.ipv6test(true, "1::2:3:4:*")
	t.ipv6test(true, "1::2:*:4")
	t.ipv6test(true, "1::*:3")
	t.ipv6test(true, "1::*")

	t.ipv6test(true, "::*:3:4:5:6:7:8")
	t.ipv6test(true, "*::2:3:4:5:6:7")
	t.ipv6test(true, "::*:3:4:5:6")
	t.ipv6test(true, "::*:3:4:5")
	t.ipv6test(true, "::2:3:*")
	t.ipv6test(true, "*::2:3")
	t.ipv6test(true, "::*")
	t.ipv6test(true, "1:*:3:4:5:6::")
	t.ipv6test(true, "1:2:3:4:*::")
	t.ipv6test(true, "1:2:3:*::")
	t.ipv6test(true, "1:2:3::*")
	t.ipv6test(true, "*:2::")
	t.ipv6test(true, "*::")
	t.ipv6test(true, "*:2:3:4:5::7:8")
	t.ipv6test(false, "1:2:3::4:5::7:*") // Double "::"
	t.ipv6test(false, "12345::6:7:*")
	t.ipv6test(true, "1:2:3:4::*:*")
	t.ipv6test(true, "1:*:3::7:8")
	t.ipv6test(true, "*:*::7:8")
	t.ipv6test(true, "*::*:8")

	// Testing IPv4 addresses represented as dotted-quads
	// Leading zero's in IPv4 addresses not allowed: some systems treat the leading "0" in ".086" as the start of an octal number
	// Update: The BNF in RFC-3986 explicitly defines the dec-octet (for IPv4 addresses) not to have a leading zero
	//t.ipv6test(false,"fe80:0000:0000:*:0204:61ff:254.157.241.086");
	t.ipv6test(!t.isLenient(), "fe80:0000:0000:*:0204:61ff:254.157.241.086")
	t.ipv6test(true, "::*:192.0.128.*")
	t.ipv6test(false, "XXXX:XXXX:XXXX:XXXX:XXXX:XXXX:1.2.3.4")
	t.ipv6test(true, "1111:2222:*:4444:5555:6666:00.00.00.00")
	t.ipv6test(true, "1111:2222:3333:4444:5555:6666:000.*.000.000")
	t.ipv6test(false, "*:2222:3333:4444:5555:6666:256.256.256.256")

	t.ipv6test(true, "*:2222:3333:4444:5555:6666:123.123.123.123")
	t.ipv6test(true, "1111:*:3333:4444:5555::123.123.123.123")
	t.ipv6test(true, "1111:2222:*:4444::123.123.123.123")
	t.ipv6test(true, "1111:2222:3333::*.*.123.123")
	t.ipv6test(true, "1111:2222::123.123.*.*")
	t.ipv6test(true, "1111:2222::123.123.123.*")
	t.ipv6test(true, "1111::123.*.123.123")
	t.ipv6test(true, "::123.123.123.*")
	t.ipv6test(true, "1111:2222:3333:4444::*:123.123.123.123")
	t.ipv6test(true, "1111:2222:*::6666:123.123.123.123")
	t.ipv6test(true, "*:2222::6666:123.123.123.123")
	t.ipv6test(true, "1111::6666:*.*.*.*")
	t.ipv6test(true, "::6666:123.123.2.123")
	t.ipv6test(true, "1111:*:3333::5555:6666:123.*.123.123")
	t.ipv6test(true, "1111:2222::*:6666:123.123.*.*")
	t.ipv6test(true, "1111::*:6666:*.*.123.123")
	t.ipv6test(true, "1111::*:6666:*.0-255.123.123") //1111::*:6666:*.123.123
	t.ipv6test(true, "::5555:6666:123.123.123.123")
	t.ipv6test(true, "1111:2222::4444:5555:*:123.123.123.123")
	t.ipv6test(true, "1111::4444:5555:6666:123.*.123.123")
	t.ipv6test(true, "*::4444:5555:6666:123.123.123.123")
	t.ipv6test(true, "1111::*:4444:5555:6666:123.123.123.123")
	t.ipv6test(true, "::2222:*:4444:5555:6666:123.123.123.123")
	t.ipv6test(true, "::*:*:*:*:*:*.*.*.*")
	t.ipv6test(true, "*::*:*:*:*:*.*.*.*")
	t.ipv6test(false, "*:::*:*:*:*.*.*.*")
	t.ipv6test(false, "*:::*:*:*:*:*.*.*.*")
	t.ipv6test(true, "*::*:*:*:*:*.*.*.*")
	t.ipv6test(false, "*::*:*:*:*:*:*.*.*.*")
	t.ipv6test(false, "*:*:*:*:*:*:*:*:*.*.*.*")
	t.ipv6test(false, "*:*:*:*:*:*:*::*.*.*.*")
	t.ipv6test(false, "*:*:*:*:*:*::*:*.*.*.*")
	t.ipv6test(true, "*:*:*:*:*:*:*.*.*.*")
	t.ipv6test(true, "*:*:*:*:*::*.*.*.*")
	t.ipv6test(true, "*:*:*:*::*:*.*.*.*")

	t.ipv6test(true, "::*")
	t.ipv6test(true, "*:0:0:0:0:0:0:*")

	// Additional cases: http://crisp.tweakblogs.net/blog/2031/ipv6-validation-%28and-caveats%29.html
	t.ipv6test(true, "0:a:b:*:d:e:f::")
	t.ipv6test(true, "::0:a:*:*:d:e:f") // syntactically correct, but bad form (::0:... could be combined)
	t.ipv6test(true, "a:b:c:*:*:f:0::")
	t.ipv6test(false, "':10.*.0.1")

	t.ipv4test(true, "1.*.4")
	t.ipv4test(true, "1.2.*")
	t.ipv4test(true, "*.1")
	t.ipv4test(true, "1.*")
	t.ipv4test(true, "1.*.1")
	t.ipv4test(true, "1.*.*")
	t.ipv4test(true, "*.*.1")
	t.ipv4test(true, "*.1.*")
	t.ipv4test(t.isLenient(), "1")
	t.ipv4test(t.isLenient(), "1.1")
	t.ipv4test(t.isLenient(), "1.1.1")

	t.ipv4test(true, "*.1.2.*")
	t.ipv4test(true, "*.1.*.2")
	t.ipv4test(true, "*.*.*.2")
	t.ipv4test(true, "*.*.*.*")
	t.ipv4test(true, "1.*.2.*")
	t.ipv4test(true, "1.2.*.*")

	t.ipv4test(true, "*.*")
	t.ipv6test(true, "1::1.2.*")
	t.ipv6test(true, "1::1.2.**")
	t.ipv6test(false, "1::1.2.**z")
	t.ipv6test(true, "1::1.2.3.4")
	t.ipv6test(true, "1:*:1")
	t.ipv4test(true, "1.2.*")

	t.ipv4test(false, "%.%")
	t.ipv6test(false, "1::1.2.%")
	t.ipv6test(true, "1::1.2.*%")
	t.ipv6test(true, "1::1.2.*%z")
	t.ipv6test(false, "1:%:1")

	t.ipv6test(true, "1::%-.1")
	t.ipv6test(true, "1::%-.1/16") //that is a zone of "-." and a prefix of 16
	t.ipv6test(true, "1::%-1/16")  //that is a zone of "-" and a prefix of 16
	t.ipv6test(true, "1::-1:16")   //that is just an address with a ranged segment 0-1

	t.ipv6test(true, "1::%-.1-16")  // -.1-16 is the zone
	t.ipv6test(true, "1::%-.1/16")  //we treat /16 as prefix length
	t.ipv6test(false, "1::%-.1:16") //we reject ':' as part of zone
	t.ipv6test(false, "1::%-.1/1a") //prefix has 'a'
	t.ipv6test(false, "1::%-1/1a")  //prefix has 'a'
	t.ipv6test(true, "1::%%1")      //zone has '%'
	t.ipv6test(true, "1::%%1/16")   //zone has '%'
	t.ipv6test(true, "1::%%ab")     //zone has '%'
	t.ipv6test(true, "1::%%ab/16")  //zone has '%'
	t.ipv6test(true, "1::%$1")      //zone has '$'
	t.ipv6test(true, "1::%$1/16")   //zone has '$'

	t.ipv4test(true, "1.2.%") //we allow this now, the % is seen as a wildcard because we are ipv4 - if we allow zone and the string can be interpreted as ipv6 then % is seen as zone character

	t.ipv6test(true, "1:*")
	t.ipv6test(true, "*:1:*")
	t.ipv6test(true, "*:1")

	//t.ipv6test(true, "*:1:1.*.1");//cannot be converted to ipv6 range
	t.ipv6test(true, "*:1:1.*.*")
	//t.ipv6test(true, "*:1:*.1");//cannot be converted to ipv6 range
	t.ipv6test(true, "*:1:*.0-255.1.1")
	t.ipv6test(true, "*:1:1.*")

	t.ipv6test(false, "1:1:1.*.1")
	t.ipv6test(false, "1:1:1.*.1.1")
	t.ipv6test(true, "1:1:*.*")
	t.ipv6test(true, "1:2:3:4:5:*.*")
	t.ipv6test(true, "1:2:3:4:5:6:*.*")
	t.ipv6test(false, "1:1:1.*")

	t.ipv6test(true, "1::1:1.*.*")
	t.ipv6test(true, "1::1:*.*.1.1")
	t.ipv6test(true, "1::1:1.*")

	t.ipv6test(true, "1:*.*.*.*") //in this one, the wildcard covers both ipv6 and ipv4 parts
	t.ipv6test(true, "1::*.*.*.*")
	t.ipv6test(true, "1:*.*.1.2")    //in this one, the wildcard covers both ipv6 and ipv4 parts
	t.ipv6test(true, "1::*.*.1.2")   //compression takes precedence so the wildcard does not cover both ipv6 and ipv4 parts
	t.ipv6test(true, "1::2:*.*.1.2") //compression takes precedence so the wildcard does not cover both ipv6 and ipv4 parts
	t.ipv6test(true, "::2:*.*.1.2")  //compression takes precedence so the wildcard does not cover both ipv6 and ipv4 parts
	t.ipv6test(false, "1:1.*.2")
	t.ipv6test(false, "1:1.*.2.2")
	t.ipv6test(t.isLenient(), "1:*:1.2")

	t.ipv6test(true, "*:1:1.*")
	t.ipv6test(t.isLenient(), "*:1:1.2.3")
	t.ipv6test(true, "::1:1.*")
	t.ipv6test(t.isLenient(), "::1:1.2.3")

	t.ipv6test(true, "1:*:1")
	t.ipv6test(true, "1:*:1:1.1.*")
	t.ipv6test(true, "1:*:1:1.1.*.*")
	t.ipv6test(true, "1:*:1:*")
	t.ipv6test(true, "1:*:1:*.*.1.2")
	t.ipv6test(true, "1:*:1:1.*")
	t.ipv6test(t.isLenient(), "1:*:1:1.2.3")

	t.ipv6test(false, "1:*:1:2:3:4:5:6:7")
	t.ipv6test(false, "1:*:1:2:3:4:5:1.2.3.4")
	t.ipv6test(true, "1:*:2:3:4:5:1.2.3.4")
	t.ipv6test(false, "1:*:2:3:4:5:1.2.3.4.5")
	t.ipv6test(false, "1:1:2:3:4:5:1.2.3.4.5")
	t.ipv6test(false, "1:1:2:3:4:5:6:1.2.3.4")
	t.ipv6test(false, "1:1:2:3:4:5:6:1.*.3.4")
	t.ipv6test(true, "1:2:3:4:5:6:1.2.3.4")
	t.ipv6test(true, "1:2:3:4:5:6:1.*.3.4")

	t.ipv4test(true, "255._.3.4")
	t.ipv4test(true, "1.255._.4")
	t.ipv4test(true, "_.2.255.4")
	t.ipv4test(true, "1._.3.255")

	t.ipv4test(true, "255.__.3.4")
	t.ipv4test(true, "1.255.__.4")
	t.ipv4test(true, "__.2.255.4")
	t.ipv4test(true, "1.__.3.255")

	t.ipv4test(true, "255.___.3.4")
	t.ipv4test(true, "1.255.___.4")
	t.ipv4test(true, "___.2.255.4")
	t.ipv4test(true, "1.___.3.255")

	t.ipv4test(t.isLenient(), "255.____.3.4")
	t.ipv4test(t.isLenient(), "1.255.____.4")
	t.ipv4test(t.isLenient(), "____.2.255.4")
	t.ipv4test(t.isLenient(), "1.____.3.255")

	t.ipv4test(false, "255._2_.3.4")
	t.ipv4test(false, "1.255._2_.4")
	t.ipv4test(false, "_2_.2.255.4")
	t.ipv4test(false, "1._2_.3.255")

	t.ipv4test(true, "255.2__.3.4")
	t.ipv4test(true, "1.255.2__.4")
	t.ipv4test(true, "2__.2.255.4")
	t.ipv4test(true, "1.2__.3.255")

	t.ipv4test(true, "255.2_.3.4")
	t.ipv4test(true, "1.255.2_.4")
	t.ipv4test(true, "2_.2.255.4")
	t.ipv4test(true, "1.2_.3.255")

	t.ipv4test(false, "255.__2.3.4")
	t.ipv4test(false, "1.255.__2.4")
	t.ipv4test(false, "__2.2.255.4")
	t.ipv4test(false, "1.__2.3.255")

	t.ipv4test(true, "25_.__.3.4")
	t.ipv4test(true, "1.255.2__._")
	t.ipv4test(true, "2_.2_.255.__")
	t.ipv4test(false, "1.2__.3__.25_")
	t.ipv4test(true, "1.2__.3_.25_")
	t.ipv4test(true, "1.2__.2__.25_")

	t.ipv4test(false, "1.1--2.1.1")
	t.ipv4test(false, "1.1-2-3.1.1")
	t.ipv4test(false, "1.1-2-.1.1")
	t.ipv4test(false, "1.-1-2.1.1")

	t.ipv4test(false, "1.1_2_.1.1")
	t.ipv4test(false, "1.1_2.1.1")
	t.ipv4test(true, "1.1_.1.1")
	t.ipv4test(false, "1.1_-2.1.1")
	t.ipv4test(false, "1.1-2_.1.1")
	t.ipv4test(false, "1.1*-2.1.1")
	t.ipv4test(false, "1.1-2*.1.1")
	t.ipv4test(false, "1.*1-2.1.1")
	t.ipv4test(false, "1.1-*2.1.1")
	t.ipv4test(false, "1.*-2.1.1")
	t.ipv4test(false, "1.1-*.1.1")

	t.ipv6test(false, "1:1--2:1:1::")
	t.ipv6test(false, "1:1-2-3:1:1::")
	t.ipv6test(false, "1:1-2-:1:1::")
	t.ipv6test(false, "1:-1-2:1:1::")

	t.ipv6test(false, "1:1_2_:1.1::")
	t.ipv6test(false, "1:1_2:1:1::")
	t.ipv6test(true, "1:1_:1:1::")

	t.ipv6test(false, "1:1_-2:1:1::")
	t.ipv6test(false, "1:1-2_:1:1::")
	t.ipv6test(false, "1:1-_2:1:1::")
	t.ipv6test(false, "1:1*-2:1:1::")
	t.ipv6test(false, "1:1-2*:1:1::")
	t.ipv6test(false, "1:*-2:1:1::")
	t.ipv6test(false, "1:1-*:1:1::")
	t.ipv6test(false, "1:*1-2:1:1::")
	t.ipv6test(false, "1:1-*2:1:1::")

	//double -
	// _4_ single char wildcards not in trailing position

	t.ipv6test(true, "::ffff:_:0")
	t.ipv6test(true, "_::1")
	t.ipv6test(true, "1:2:3:4:_:6:7:8")
	t.ipv6test(true, "1:2:_:4:5:6::8")
	t.ipv6test(true, "1:2:3:4:5::_")
	t.ipv6test(true, "1:2:3:_::8")
	t.ipv6test(true, "_:2::8")
	t.ipv6test(true, "1::_")
	t.ipv6test(true, "_::2:3:4:5:6:7")
	t.ipv6test(true, "_::2:3:4:5:6")
	t.ipv6test(true, "1::2:3:4:_")
	t.ipv6test(true, "1::2:_:4")
	t.ipv6test(true, "1::_:3")
	t.ipv6test(true, "1::_")

	t.ipv6test(true, "::ffff:__:0")
	t.ipv6test(true, "__::1")
	t.ipv6test(true, "1:2:3:4:__:6:7:8")
	t.ipv6test(true, "1:2:__:4:5:6::8")
	t.ipv6test(true, "1:2:3:4:5::__")
	t.ipv6test(true, "1:2:3:__::8")
	t.ipv6test(true, "__:2::8")
	t.ipv6test(true, "1::__")
	t.ipv6test(true, "__::2:3:4:5:6:7")
	t.ipv6test(true, "__::2:3:4:5:6")
	t.ipv6test(true, "1::2:3:4:__")
	t.ipv6test(true, "1::2:__:4")
	t.ipv6test(true, "1::__:3")
	t.ipv6test(true, "1::__")

	t.ipv6test(true, "::ffff:___:0")
	t.ipv6test(true, "___::1")
	t.ipv6test(true, "1:2:3:4:___:6:7:8")
	t.ipv6test(true, "1:2:___:4:5:6::8")
	t.ipv6test(true, "1:2:3:4:5::___")
	t.ipv6test(true, "1:2:3:___::8")
	t.ipv6test(true, "___:2::8")
	t.ipv6test(true, "1::___")
	t.ipv6test(true, "___::2:3:4:5:6:7")
	t.ipv6test(true, "___::2:3:4:5:6")
	t.ipv6test(true, "1::2:3:4:___")
	t.ipv6test(true, "1::2:___:4")
	t.ipv6test(true, "1::___:3")
	t.ipv6test(true, "1::___")

	t.ipv6test(true, "::ffff:____:0")
	t.ipv6test(true, "____::1")
	t.ipv6test(true, "1:2:3:4:____:6:7:8")
	t.ipv6test(true, "1:2:____:4:5:6::8")
	t.ipv6test(true, "1:2:3:4:5::____")
	t.ipv6test(true, "1:2:3:____::8")
	t.ipv6test(true, "____:2::8")
	t.ipv6test(true, "1::____")
	t.ipv6test(true, "____::2:3:4:5:6:7")
	t.ipv6test(true, "____::2:3:4:5:6")
	t.ipv6test(true, "1::2:3:4:____")
	t.ipv6test(true, "1::2:____:4")
	t.ipv6test(true, "1::____:3")
	t.ipv6test(true, "1::____")

	t.ipv6test(false, "::ffff:_____:0")
	t.ipv6test(false, "_____::1")
	t.ipv6test(false, "1:2:3:4:_____:6:7:8")
	t.ipv6test(false, "1:2:_____:4:5:6::8")
	t.ipv6test(false, "1:2:3:4:5::_____")
	t.ipv6test(false, "1:2:3:_____::8")
	t.ipv6test(false, "_____:2::8")
	t.ipv6test(false, "1::_____")
	t.ipv6test(false, "_____::2:3:4:5:6:7")
	t.ipv6test(false, "_____::2:3:4:5:6")
	t.ipv6test(false, "1::2:3:4:_____")
	t.ipv6test(false, "1::2:_____:4")
	t.ipv6test(false, "1::_____:3")
	t.ipv6test(false, "1::_____")

	t.ipv6test(false, "::ffff:ff___:0")
	t.ipv6test(false, "f____::1")
	t.ipv6test(false, "1:2:3:4:ffff_:6:7:8")
	t.ipv6test(false, "1:2:ffff_:4:5:6::8")
	t.ipv6test(false, "1:2:3:4:5::f_f__")
	t.ipv6test(false, "1:2:3:fff__::8")
	t.ipv6test(false, "f___f:2::8")
	t.ipv6test(false, "1::ff_ff")
	t.ipv6test(false, "ff_ff::2:3:4:5:6:7")
	t.ipv6test(false, "f____::2:3:4:5:6")
	t.ipv6test(false, "1::2:3:4:F____")
	t.ipv6test(false, "1::2:FF___:4")
	t.ipv6test(false, "1::FFF__:3")
	t.ipv6test(false, "1::FFFF_")

	t.ipv6test(false, "::ffff:_2_:0")
	t.ipv6test(false, "_2_::1")
	t.ipv6test(false, "1:2:3:4:_2_:6:7:8")
	t.ipv6test(false, "1:2:_2_:4:5:6::8")
	t.ipv6test(false, "1:2:3:4:5::_2_")
	t.ipv6test(false, "1:2:3:_2_::8")
	t.ipv6test(false, "_2_:2::8")
	t.ipv6test(false, "1::_2_")
	t.ipv6test(false, "_2_::2:3:4:5:6:7")
	t.ipv6test(false, "_2_::2:3:4:5:6")
	t.ipv6test(false, "1::2:3:4:_2_")
	t.ipv6test(false, "1::2:_2_:4")
	t.ipv6test(false, "1::_2_:3")
	t.ipv6test(false, "1::_2_")

	t.ipv6test(false, "::ffff:_2:0")
	t.ipv6test(false, "_2::1")
	t.ipv6test(false, "1:2:3:4:_2:6:7:8")
	t.ipv6test(false, "1:2:_2:4:5:6::8")
	t.ipv6test(false, "1:2:3:4:5::_2")
	t.ipv6test(false, "1:2:3:_2::8")
	t.ipv6test(false, "_2:2::8")
	t.ipv6test(false, "1::_2")
	t.ipv6test(false, "_2::2:3:4:5:6:7")
	t.ipv6test(false, "_2::2:3:4:5:6")
	t.ipv6test(false, "1::2:3:4:_2")
	t.ipv6test(false, "1::2:_2:4")
	t.ipv6test(false, "1::_2:3")
	t.ipv6test(false, "1::_2")

	t.ipv6test(true, "::ffff:2_:0")
	t.ipv6test(true, "2_::1")
	t.ipv6test(true, "1:2:3:4:2_:6:7:8")
	t.ipv6test(true, "1:2:2_:4:5:6::8")
	t.ipv6test(true, "1:2:3:4:5::2_")
	t.ipv6test(true, "1:2:3:2_::8")
	t.ipv6test(true, "2_:2::8")
	t.ipv6test(true, "1::2_")
	t.ipv6test(true, "2_::2:3:4:5:6:7")
	t.ipv6test(true, "2_::2:3:4:5:6")
	t.ipv6test(true, "1::2:3:4:2_")
	t.ipv6test(true, "1::2:2_:4")
	t.ipv6test(true, "1::2_:3")
	t.ipv6test(true, "1::2_")

	t.ipv6test(true, "::ffff:2___:0")
	t.ipv6test(true, "2___::1")
	t.ipv6test(true, "1:2:3:4:2___:6:7:8")
	t.ipv6test(true, "1:2:2___:4:5:6::8")
	t.ipv6test(true, "1:2:3:4:5::2___")
	t.ipv6test(true, "1:2:3:2___::8")
	t.ipv6test(true, "2___:2::8")
	t.ipv6test(true, "1::2___")
	t.ipv6test(true, "2___::2:3:4:5:6:7")
	t.ipv6test(true, "2___::2:3:4:5:6")
	t.ipv6test(true, "1::2:3:4:2___")
	t.ipv6test(true, "1::2:2___:4")
	t.ipv6test(true, "1::2___:3")
	t.ipv6test(true, "1::2___")

	t.ipv6test(true, "::fff_:2___:0")
	t.ipv6test(true, "2___::_")
	t.ipv6test(true, "1:2:3:4:2___:6_:7_:8")
	t.ipv6test(true, "1:2:2___:4:5:6::8__")
	t.ipv6test(true, "1:2:3_:4:5::2___")
	t.ipv6test(true, "1:2:3:2___::8")
	t.ipv6test(true, "2___:2::8")
	t.ipv6test(true, "1::2___")
	t.ipv6test(true, "2___::2_:3__:4:5:6:7")
	t.ipv6test(true, "2___::2:3_:4:5:6")
	t.ipv6test(true, "1::2:3:4_:2___")
	t.ipv6test(true, "1::2:2___:4f__")
	t.ipv6test(true, "1___::2___:3___")
	t.ipv6test(true, "1_::2___")

	t.ipv6test(t.isLenient(), "*:1:1._.__")
	t.ipv6test(true, "*:1:1._.__.___")
	//t.ipv6test(false, "*:_:1:_.1.1._");//this passes validation but conversion to mask fails because the ipv4 ranges cannot be converted to ipv6 ranges
	t.ipv6test(true, "*:_:1:1._.1._")
	t.ipv6test(true, "*:_:1:_.___.1._")
	t.ipv6test(true, "*:_:1:_.___._.___")
	t.ipv6test(true, "1:*:1_:1:1.1_.1.1")

	t.ipv6test(false, "1:1:1.2_.1")
	t.ipv6test(false, "1:1:1.2__.1.1")
	t.ipv6test(false, "1:1:_.*")
	t.ipv6test(false, "1:1:1._")

	t.ipv6test(true, "a-f:b:c:d:e:f:a:bb")
	t.ipv6test(true, "-f:b:c:d:e:f:a:bb")

	t.testCIDRSubnets("9.*.237.26/0", "9.*.237.26")
	t.testCIDRSubnets("9.*.237.26/1", "9.*.237.26")
	t.testCIDRSubnets("9.*.237.26/4", "9.*.237.26")
	t.testCIDRSubnets("9.*.237.26/5", "9.*.237.26")
	t.testCIDRSubnets("9.*.237.26/7", "9.*.237.26")
	t.testCIDRSubnets("9.*.237.26/8", "9.*.237.26")
	t.testCIDRSubnets("9.*.237.26/9", "9.*.237.26")
	t.testCIDRSubnets("9.*.237.26/16", "9.*.237.26")
	t.testCIDRSubnets("9.*.237.26/30", "9.*.237.26")
	t.testCIDRSubnets("9.*.237.26/31", "9.*.237.26-27")
	t.testCIDRSubnets("9.*.237.26/32", "9.*.237.26")

	t.testContains("0.0.0.0/0", "1-2.*.3.*", false)

	t.testContains("0-127.0.0.0/8", "127-127.*.3.*", false)
	t.testContains("0.0.0.0/4", "13-15.*.3.*", false)
	t.testContains("0-15.*.*.*/4", "13-15.*.3.*", false)
	t.testContains("0.0.0.0/4", "9.*.237.*/16", false)
	t.testContains("0.0.0.0/4", "8-9.*.237.*/16", false)

	t.testNotContains("1-2.0.0.0/4", "9.*.237.*/16")
	t.testNotContains("1-2.0.0.0/4", "8-9.*.237.*/16")

	t.testNotContains("1-2.0.0.0/4", "9-17.*.237.*/16")
	t.testContains("8.0.0.0/5", "15.2.3.4", false)
	t.testContains("8.0.0.0/7", "8-9.*.3.*", false)
	t.testContains("9.0.0.0/8", "9.*.3.*", false)
	t.testContains("9.128.0.0/9", "9.128-255.*.0", false)
	t.testContains("9.128.0.0/15", "9.128-129.3.*", false)
	t.testContains("9.129.0.0/16", "9.129.3.*", false)
	t.testNotContains("9.129.0.0/16", "9.128-129.3.*")
	t.testNotContains("9.129.0.0/16", "9.128.3.*")
	t.testContains("9.129.237.24/30", "9.129.237.24-27", true)
	t.testContains("9.129.237.24/30", "9.129.237.24-27/31", true)
	t.testContains("9.129.237.24-27/30", "9.129.237.24-27/31", true)

	t.testContains("*.*.*.*/0", "9.129.237.26/0", false)
	t.testContains("0.0.0.0/0", "*.*.*.*/0", true)
	t.testContains("0.0.0.0/4", "0-15.0.0.*/4", false)
	t.testNotContains("192.0.0.0/4", "0-15.0.0.*/4")

	t.testNotContains("0-127.129.237.26/1", "0-127.0.*.0/1")
	t.testNotContains("9.129.237.26/0", "*.*.*.1/0")
	t.testNotContains("9.129.237.26/4", "0-15.0.1.*/4")
	t.testNotContains("1-16.0.0.*/4", "9.129.237.26/4")
	t.testNotContains("9.129.237.26/5", "8-15.0.0.0/5")
	t.testNotContains("9.129.237.26/7", "8-9.0.0.1-3/7")
	t.testNotContains("7-9.0.0.1-3/7", "9.129.237.26/7")
	t.testNotContains("9.129.237.26/8", "9.*.0.0/8")
	t.testNotContains("9.129.237.26/9", "9.128-255.0.0/9")
	t.testNotContains("9.129.237.26/15", "9.128-129.0.*/15")
	t.testNotContains("9.129.237.26/16", "9.129.*.1/16")
	t.testNotContains("9.129.237.26/30", "9.129.237.27/30")

	t.testContains("0.0.0.0/4", "9.129.237.26/4", false)
	t.testContains("8.0.0.0/5", "8-15.0.0.0/5", false)
	t.testContains("8.0.0.0/7", "8-9.0.0.1-3/7", false)
	t.testContains("7-9.*.*.*/7", "9.129.237.26/7", false)
	t.testContains("9.0.0.0/8", "9.*.0.0/8", false)
	t.testContains("9.128.0.0/9", "9.128-255.0.0/9", false)
	t.testContains("9.128.0.0/15", "9.128-129.0.*/15", false)
	t.testContains("9.128.0.0/15", "9.128.0.0/15", true)
	t.testContains("9.129.0.0/16", "9.129.*.*/16", true)
	t.testContains("9.128-129.*.*/15", "9.128.0.0/15", true)
	t.testContains("9.128.*.*/16", "9.128.0.0/16", true)
	t.testContains("9.129.*.*/16", "9.129.*.*/16", true)
	t.testContains("9.129.*.*/16", "9.129.*.0/16", false)
	t.testContains("9.129.237.24/30", "9.129.237.24-27/30", true)
	t.testContains("9.128-129.*.26/32", "9.128-129.*.26/32", true)

	t.testNotContains("1-16.0.0.0/4", "9.129.237.26/4")
	t.testNotContains("9.129.237.26/5", "8-15.0.0.0/5")
	t.testNotContains("9.129.237.26/7", "8-9.0.0.1-3/7")
	t.testNotContains("7-9.0.0.1-3/7", "9.129.237.26/7")
	t.testNotContains("9.129.237.26/8", "9.*.0.0/8")
	t.testNotContains("9.129.237.26/9", "9.128-255.0.0/9")
	t.testNotContains("9.129.237.26/15", "9.128-129.0.*/15")
	t.testNotContains("9.129.237.26/16", "9.129.*.1/16")
	t.testNotContains("9.129.237.26/16", "9.129.1.*/16")
	t.testNotContains("9.129.237.25/30", "9.129.237.26/30")

	t.testContains("1-16.0.0.*/4", "9.0.0.*/4", false)
	t.testNotContains("1-16.0.0.0-254/4", "9.0.0.*/4")
	t.testContains("0-16.0.0.0/4", "9.0.0.*/4", false)
	t.testContains("8-15.129.237.26/5", "9.129.237.26/5", false)
	t.testContains("8-9.129.237.26/7", "9.129.237.26/7", false)
	t.testContains("7-9.0.0.1-3/7", "9.0.0.2/7", false)
	t.testContains("9.*.237.26/8", "9.*.237.26/8", true)
	t.testContains("9.128-255.237.26/9", "9.129.237.26/9", false)
	t.testContains("9.128-129.237.26/15", "9.129.237.26/15", false)
	t.testContains("9.129.*.*/16", "9.129.237.26/16", false)
	t.testContains("9.129.237.24-27/30", "9.129.237.26/30", false)
	t.testContains("9.128-129.*.26/32", "9.128-129.*.26/32", true)

	t.testNotContains("9.129.237.26/4", "16-17.0.0.*/4")
	t.testNotContains("9.129.237.26/7", "2.0.0.1-3/7")

	t.testContains("::ffff:1.*.3.4", "1.2.3.4", false) //ipv4 mapped

	t.testNotContains("::ffff:1.2-4.3.4/112", "1.2-3.3.*")
	t.testNotContains("ffff:0:0:0:0:0:*:0/32", "ffff:0:ffff:1-d:e:f:*:b")
	t.testNotContains("fffc-ffff::ffff/30", "fffd-fffe:0:0:0:0:0:0:0/30")
	t.testNotContains("ffff:0-d::ffff/32", "ffff:a-c:0:0:0:0:0:0/32")
	t.testNotContains("ffff::ffff/0", "a-b:0:b:0:c:d-e:*:0/0")
	t.testNotContains("ffff::ffff/1", "8000-8fff:0:0:0:0:*:a-b:0/1")
	t.testNotContains("ffff:*::fffb/126", "ffff:*:0:0:0:0:0:fffc-ffff/126")
	t.testNotContains("ffff:1-2::fffb/126", "ffff:1-2:0:0:0:0:0:fffc-ffff/126")

	t.testContains("::ffff:1.2-4.0.0/112", "1.2-3.3.*", false)

	t.testContains("0:0:0:0:0:0:0:0/0", "a:*:c:d:e:1-ffff:a:b", false)
	t.testContains("8000:0:0:0:0:0:0:0/1", "8000-8fff:b:c:d:e:f:*:b", false)
	t.testNotContains("8000:0:0:0:0:0:0:0/1", "7fff-8fff:b:c:d:e:f:*:b")
	t.testContains("ffff:0:0:0:0:0:0:0/30", "ffff:0-3:c:d:e:f:a:b", false)
	t.testNotContains("ffff:0:0:0:0:0:0:0/30", "ffff:0-4:c:d:e:f:a:b")

	t.testContains("ffff:0:0:0:0:0:0:0/32", "ffff:0:ffff:1-d:e:f:*:b", false)
	t.testContains("fffc-ffff::/30", "fffd-fffe:0:0:0:0:0:0:0/30", false)
	t.testContains("ffff:0-d::/32", "ffff:a-c:0:0:0:0:0:0/32", false)

	t.testNotContains("ffff:0:0:0:0:1-2:0:0/32", "ffff:0-1:ffff:d:e:f:a:b")
	t.testContains("ffff:0:0:0:0:4-ffff:0:fffc-ffff", "ffff:0:0:0:0:4-ffff:0:fffd-ffff", false)
	t.testContains("ffff:0:0:0:0:4-ffff:0:fffc/126", "ffff:0:0:0:0:4-ffff:0:fffd-ffff", false)
	t.testContains("ffff:0:0:0:0:4-ffff:0:fffc/126", "ffff:0:0:0:0:4-ffff:0:fffc-ffff", true)
	t.testContains("ffff:0:*:0:0:4-ffff:0:ffff/128", "ffff:0:*:0:0:4-ffff:0:ffff", true)

	t.testContains("ffff:*:0:0:0:0:0:fffa-ffff/126", "ffff:*::ffff/126", false)

	t.testContains("::/0", "a-b:0:b:0:c:d-e:*:0/0", false)
	t.testContains("8000::/1", "8000-8fff:0:0:0:0:*:a-b:0/1", false)
	t.testContains("ffff:*::fffc/126", "ffff:*:0:0:0:0:0:fffc-ffff/126", true)
	t.testContains("ffff:1-2::fffc/126", "ffff:1-2:0:0:0:0:0:fffc-ffff/126", true)

	t.testContains("10.162.155.1-255", "10.162.155.1-51", false)
	t.testContains("10.162.155.1-51", "10.162.155.1-51", true)
	t.testContains("10.162.1-51.155", "10.162.1-51.155", true)
	t.testContains("10.162.1-255.155", "10.162.1-51.155", false)
	t.testContains("1-255.10.162.155", "1-51.10.162.155", false)

	t.testContains("10.162.155.0-255", "10.162.155.0-51", false)
	t.testContains("10.162.155.0-51", "10.162.155.0-51", true)
	t.testContains("10.162.0-51.155", "10.162.0-51.155", true)
	t.testContains("10.162.0-255.155", "10.162.0-51.155", false)
	t.testContains("0-255.10.162.155", "0-51.10.162.155", false)

	t.testNotContains("192.13.1.0/25", "192.13.1.1-255")
	t.testNotContains("192.13.1.1-255", "192.13.1.0/25")

	t.testContains("192.13.1.0/25", "192.13.1.1-127", false)
	t.testContains("192.13.1.0/25", "192.13.1.0-127", true)

	t.testContains("192.13.1.0-127", "192.13.1.0/25", true)

	t.testContains("ffff:1-3::/32", "ffff:2::", false)
	t.testContains("ffff:2-3::/32", "ffff:2::", false)
	t.testContains("ffff:1-3::/32", "ffff:3::", false)

	t.testNotContains("ffff:1-3::/32", "ffff:4::")

	t.testContains("ffff:1000-3000::/20", "ffff:2000::", false)
	t.testContains("ffff:2000-3000::/20", "ffff:2000::", false)
	t.testContains("ffff:1000-3000::/20", "ffff:3000::", false)

	t.testNotContains("ffff:1000-3000::/20", "ffff:4000::")
	t.testNotContains("ffff:2000-3000::/20", "ffff:4000::")

	t.testContains("ffff:1000::/20", "ffff:1111-1222::", false)
	t.testNotContains("ffff:1000::/20", "ffff:1-::")

	t.testContains("ffff:1-:*", "ffff:1000::/20", false)
	t.testNotContains("ffff:1000::/20", "ffff:1111-2222::")
	t.testNotContains("ffff:1000::/20", "ffff:1-10::")
	t.testNotContains("ffff:1000::/20", "ffff:1-1::")

	t.testContains("::/64", "::", false)
	t.testNotContains("1:2::/64", "::")
	t.testContains("1:2::/64", "1:2::", false)

	t.testNotContains("5.62.62-63.*", "5.62.64.1")
	t.testNotContains("5.62.62-63.*", "5.62.68.1")
	t.testNotContains("5.62.62-63.*", "5.62.78.1")

	t.testContains("192.13.1.0/25", "192.13.1.1-127", false)

	t.testNotContains("192.13.1.0/25", "192.13.1.1-255")
	//testContainsNonZeroHosts("192.13.1.1-127", "192.13.1.0/25")
	//testContainsNonZeroHosts("192.13.1.1-255", "192.13.1.0/24")
	//testNotContainsNonZeroHosts("192.13.1.1-255", "192.13.1.0/23")
	//
	//testContainsNonZeroHosts("192.13.1.0-255", "192.13.1.0/23")

	t.testContains("192.13.1.0-255", "192.13.1.0/23", false)

	t.testContains("192.13.0-1.0-255", "192.13.1.0/23", false)
	t.testContains("192.13.0-1.0-255", "192.13.0.0/23", true)

	//testContainsNonZeroHosts("::192:13:1:1-7fff", "::192:13:1:0/113")
	//testContainsNonZeroHosts("::192:13:1:1-ffff", "::192:13:1:0/112")
	//testNotContainsNonZeroHosts("::192:13:1:1-ffff", "::192:13:1:0/111")

	t.testSubnet("1.2-4.3.4", "255.255.254.255", 24, "1.2-4.2.4/24", "1.2-4.2.4", "1.2-4.3.4/24")
	t.testSubnet("1.2-4.3.4", "255.248.254.255", 24, "1.0.2.4/24", "1.0.2.4", "1.2-4.3.4/24")

	t.testSubnet("__::", "ffff::", 128, "0-ff:0:0:0:0:0:0:0/128", "0-ff:0:0:0:0:0:0:0", "0-ff:0:0:0:0:0:0:0/128")
	t.testSubnet("0-ff::", "fff0::", 128, "", "", "0-ff:0:0:0:0:0:0:0/128")

	t.testSubnet("0-ff::", "fff0::", 12, "0-ff:0:0:0:0:0:0:0/12", "", "0-ff:0:0:0:0:0:0:0/12")
	//testSubnet("0-f0::", "fff0::", 12, "0-f0:0:0:0:0:0:0:0/12", "0-f0:0:0:0:0:0:0:0", "0-f0:0:0:0:0:0:0:0/12");
	t.testSubnet("0-f0::", "fff0::", 12, "0-f0:0:0:0:0:0:0:0/12", "", "0-f0:0:0:0:0:0:0:0/12")
	t.testSubnet("0-f::", "fff0::", 12, "0-f:0:0:0:0:0:0:0/12", "0:0:0:0:0:0:0:0", "0-f:0:0:0:0:0:0:0/12")
	t.testSubnet("0-f::*", "fff0::ffff", 12, "0-f:0:0:0:0:0:0:*/12", "0:0:0:0:0:0:0:*", "0-f:0:0:0:0:0:0:*/12")

	t.testSubnet("::1:__", "::1:ffff", 128, "0:0:0:0:0:0:1:0-ff/128", "0:0:0:0:0:0:1:0-ff", "0:0:0:0:0:0:1:0-ff/128")
	t.testSubnet("::1:__", "::1:ffff", 126, "0:0:0:0:0:0:1:0-fc/126", "0:0:0:0:0:0:1:0-ff", "0:0:0:0:0:0:1:0-fc/126")
	t.testSubnet("::1:0-ff", "::1:fff0", 128, "", "", "0:0:0:0:0:0:1:0-ff/128")
	t.testSubnet("::1:0-ff", "::1:fff0", 124, "0:0:0:0:0:0:1:0-f0/124", "", "0:0:0:0:0:0:1:0-f0/124")
	t.testSubnet("*::1:0-f", "ffff::1:fff0", 124, "*:0:0:0:0:0:1:0/124", "*:0:0:0:0:0:1:0", "*:0:0:0:0:0:1:0/124")

	t.testReverseHostAddress("*.*.0-240.0/20")
	t.testReverseHostAddress("*.*.0.0/16")
	t.testReverseHostAddress("*:0-f000::/20")

	t.testResolved("8.*.27.26", "8.*.27.26")

	t.testResolved("2001:*:0:0:8:800:200C:417A", "2001:*:0:0:8:800:200C:417A")

	t.testNormalized("ABCD:EF12:*:*:***:A:*:BBBB", "abcd:ef12:*:*:*:a:*:bbbb")
	t.testNormalized("ABCD:EF12:*:*:**:A:***:BBBB%g", "abcd:ef12:*:*:*:a:*:bbbb%g")

	t.testNormalized("1.*", "1.*.*.*")
	t.testNormalized("*.1.*", "*.1.*.*")
	t.testNormalized("*:1::*", "*:1::*")
	t.testNormalized("*:1:*", "*:1:*:*:*:*:*:*")
	t.testNormalized("001-002:0001-0002:01-2:1-02:01-02:*", "1-2:1-2:1-2:1-2:1-2:*:*:*")

	//TODO soon
	//testMasked("1.*.3.4", null, null, "1.*.3.4");
	//testMasked("1.*.3.4/255.255.1.0", "255.255.1.0", null, "1.*.1.0");
	//testMasked("1.*.3.4/255.255.254.0", "255.255.254.0", 23, false ? "1.*.2.0/23" : "1.*.3.4/23");
	//
	//testMasked("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", null, null, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff");
	//testMasked("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/0:101:0:101:0:101:0:101", "0:101:0:101:0:101:0:101", null, "0:101:0:101:0:101:0:101");
	//testMasked("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/ffff:ffff:8000::", "ffff:ffff:8000::", 33, false ? "ffff:ffff:8000::/33" : "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/33");
	//testMasked("ffff:ffff::/ffff:ffff:8000::", "ffff:ffff:8000::", 33, "ffff:ffff::/33");

	t.ipAddressTester.run()
}

func (t ipAddressRangeTester) ipv4rangestest(pass bool, x string, ipv4RangeOptions, ipv6RangeOptions ipaddr.RangeParameters) {
	t.iprangestest(pass, x, false, false, true, ipv4RangeOptions, ipv6RangeOptions)
}

func (t ipAddressRangeTester) ipv4rangetest(pass bool, x string, rangeOptions ipaddr.RangeParameters) {
	t.iprangetest(pass, x, false, false, true, rangeOptions)
}

func (t ipAddressRangeTester) ipv6rangestest(pass bool, x string, ipv4Options, ipv6Options ipaddr.RangeParameters) {
	t.iprangestest(pass, x, false, false, false, ipv4Options, ipv6Options)
}

func (t ipAddressRangeTester) ipv6rangetest(pass bool, x string, options ipaddr.RangeParameters) {
	t.iprangetest(pass, x, false, false, false, options)
}

func (t ipAddressRangeTester) iprangestest(pass bool, x string, isZero, notBoth, ipv4Test bool, ipv4RangeOptions, ipv6RangeOptions ipaddr.RangeParameters) {

	addr := t.createDoubleParametrizedAddress(x, ipv4RangeOptions, ipv6RangeOptions)
	if t.iptest(pass, addr, isZero, notBoth, ipv4Test) {
		//do it a second time to test the caching
		t.iptest(pass, addr, isZero, notBoth, ipv4Test)
	}
}

func (t ipAddressRangeTester) iprangetest(pass bool, x string, isZero, notBoth, ipv4Test bool, rangeOptions ipaddr.RangeParameters) {
	addr := t.createParametrizedAddress(x, rangeOptions)
	if t.iptest(pass, addr, isZero, notBoth, ipv4Test) {
		//do it a second time to test the caching
		t.iptest(pass, addr, isZero, notBoth, ipv4Test)
	}
}
