package test

import (
	"github.com/seancfoley/ipaddress/ipaddress-go/ipaddr"
	"strconv"
	"strings"
)

//TODO I decided to start with IPAddresstester.runTest and go in order there
//But also handling the same tests in the other testers (so not in order in the other ones)
// So I will need to survey the other oneslater to see what I missed in the others

type ipAddressTester struct {
	testBase
}

func (t ipAddressTester) run() {
	t.testEquivalentPrefix("1.2.3.4", 32)

	t.testEquivalentPrefix("0.0.0.0/1", 1)
	t.testEquivalentPrefix("128.0.0.0/1", 1)
	t.testEquivalentPrefix("1.2.0.0/15", 15)
	t.testEquivalentPrefix("1.2.0.0/16", 16)
	t.testEquivalentPrefix("1:2::/32", 32)
	t.testEquivalentPrefix("8000::/1", 1)
	t.testEquivalentPrefix("1:2::/31", 31)
	t.testEquivalentPrefix("1:2::/34", 34)

	t.testEquivalentPrefix("1.2.3.4/32", 32)

	t.testEquivalentPrefix("1.2.3.4/1", 32)
	t.testEquivalentPrefix("1.2.3.4/15", 32)
	t.testEquivalentPrefix("1.2.3.4/16", 32)
	t.testEquivalentPrefix("1.2.3.4/32", 32)
	t.testEquivalentPrefix("1:2::/1", 128)

	t.testEquivalentPrefix("1:2::/128", 128)

	t.testReverse("255.127.128.255", false, false)
	t.testReverse("255.127.128.255/16", false, false)
	t.testReverse("1.2.3.4", false, false)
	t.testReverse("1.1.2.2", false, false)
	t.testReverse("1.1.1.1", false, false)
	t.testReverse("0.0.0.0", true, true)

	t.testReverse("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", true, true)
	t.testReverse("ffff:ffff:1:ffff:ffff:ffff:ffff:ffff", false, false)
	t.testReverse("ffff:ffff:8181:ffff:ffff:ffff:ffff:ffff", false, true)
	t.testReverse("ffff:ffff:c3c3:ffff:ffff:ffff:ffff:ffff", false, true)
	t.testReverse("ffff:4242:c3c3:2424:ffff:ffff:ffff:ffff", false, true)
	t.testReverse("ffff:ffff:8000:ffff:ffff:0001:ffff:ffff", true, false)
	t.testReverse("ffff:ffff:1:ffff:ffff:ffff:ffff:ffff/64", false, false)
	t.testReverse("1:2:3:4:5:6:7:8", false, false)
	t.testReverse("1:1:2:2:3:3:4:4", false, false)
	t.testReverse("1:1:1:1:1:1:1:1", false, false)
	t.testReverse("::", true, true)

	t.testPrefixes("255.127.128.255",
		16, -5,
		"255.127.128.255",
		"255.127.128.255/32",
		"255.127.128.255/27",
		"255.127.128.255/16",
		"255.127.128.255/16")

	t.testPrefixes("255.127.128.255/32",
		16, -5,
		"255.127.128.255",
		"255.127.128.0/24",
		"255.127.128.224/27", //xxx need to specify the non prefix subnet xxxx (224-224) range
		"255.127.0.0/16",
		"255.127.0.0/16")

	t.testPrefixes("255.127.0.0/16",
		18, 17,
		"255.127.0.0/24",
		"255.0.0.0/8",
		"255.127.0.0",
		"255.127.0.0/18",
		"255.127.0.0/16")

	t.testPrefixes("255.127.0.0/16",
		18, 16,
		"255.127.0.0/24",
		"255.0.0.0/8",
		"255.127.0.0/32",
		"255.127.0.0/18",
		"255.127.0.0/16")

	t.testPrefixes("254.0.0.0/7",
		18, 17,
		"254.0.0.0/8",
		"0.0.0.0/0",
		"254.0.0.0/24",
		"254.0.0.0/18",
		"254.0.0.0/7")

	t.testPrefixes("254.255.127.128/7",
		18, 17,
		"254.255.127.128/8",
		"0.255.127.128/0",
		"254.0.0.128/24",
		"254.0.63.128/18",
		"254.255.127.128/7")

	t.testPrefixes("254.255.127.128/23",
		18, 17,
		"254.255.126.128/24",
		"254.255.1.128/16",
		"254.255.126.0/32",
		"254.255.65.128/18",
		"254.255.65.128/18")

	t.testPrefixes("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
		16, -5,
		"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
		"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128",
		"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/123",
		"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/16",
		"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/16")

	t.testPrefixes("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128",
		16, -5,
		"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
		"ffff:ffff:ffff:ffff:ffff:ffff:ffff:0/112",
		"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffe0/123",
		"ffff::/16",
		"ffff::/16")

	t.testPrefixes("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
		15, 1,
		"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
		"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128",
		"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
		"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/15",
		"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/15")

	t.testPrefixes("ffff:ffff:1:ffff:ffff:ffff:1:ffff/64",
		16, -5,
		"ffff:ffff:1:ffff:0:ffff:1:ffff/80",
		"ffff:ffff:1::ffff:ffff:1:ffff/48",
		"ffff:ffff:1:ffe0:ffff:ffff:1:ffff/59",
		"ffff::ffff:ffff:1:ffff/16",
		"ffff::ffff:ffff:1:ffff/16")

	t.testPrefixes("ffff:ffff:1:ffff::/63",
		16, -5,
		"ffff:ffff:1:fffe::/64",
		"ffff:ffff:1:1::/48",
		"ffff:ffff:1:ffc1::/58",
		"ffff:0:0:1::/16",
		"ffff:0:0:1::/16")

	t.testPrefixes("ffff:ffff:1:ffff::/63",
		17, -64,
		"ffff:ffff:1:fffe::/64",
		"ffff:ffff:1:1::/48",
		"0:0:0:1::/0",
		"ffff:8000:0:1::/16",
		"ffff:8000:0:1::/16")

	t.testPrefixes("ffff:ffff:1:ffff::/63",
		15, -63,
		"ffff:ffff:1:fffe::/64",
		"ffff:ffff:1:1::/48",
		"0:0:0:1::/0",
		"fffe:0:0:1::/15",
		"fffe:0:0:1::/15")

	t.testPrefixes("ffff:ffff:1:ffff::/63",
		65, 1,
		"ffff:ffff:1:fffe::/64",
		"ffff:ffff:1:1::/48",
		"ffff:ffff:1:fffe::/64",
		"ffff:ffff:1:fffe::/65",
		"ffff:ffff:1:ffff::/63")

	t.testPrefixes("ffff:ffff:1:ffff:ffff:ffff:ffff:ffff/128",
		127, 1,
		"ffff:ffff:1:ffff:ffff:ffff:ffff:ffff",
		"ffff:ffff:1:ffff:ffff:ffff:ffff::/112",
		"ffff:ffff:1:ffff:ffff:ffff:ffff:ffff",
		"ffff:ffff:1:ffff:ffff:ffff:ffff:fffe/127",
		"ffff:ffff:1:ffff:ffff:ffff:ffff:fffe/127")

	t.testBitwiseOr("1.2.0.0", nil, "0.0.3.4", "1.2.3.4")
	t.testBitwiseOr("1.2.0.0", nil, "0.0.0.0", "1.2.0.0")
	t.testBitwiseOr("1.2.0.0", nil, "255.255.255.255", "255.255.255.255")
	t.testBitwiseOr("1.0.0.0/8", cacheTestBits(16), "0.2.3.0", "1.2.3.0/24") //note the prefix length is dropped to become "1.2.3.*", but equality still holds
	t.testBitwiseOr("1.2.0.0/16", cacheTestBits(8), "0.0.3.0", "1.2.3.0/24") //note the prefix length is dropped to become "1.2.3.*", but equality still holds

	t.testBitwiseOr("0.0.0.0", nil, "1.2.3.4", "1.2.3.4")
	t.testBitwiseOr("0.0.0.0", cacheTestBits(1), "1.2.3.4", "1.2.3.4")
	t.testBitwiseOr("0.0.0.0", cacheTestBits(-1), "1.2.3.4", "1.2.3.4")
	t.testBitwiseOr("0.0.0.0", cacheTestBits(0), "1.2.3.4", "1.2.3.4")
	t.testBitwiseOr("0.0.0.0/0", cacheTestBits(-1), "1.2.3.4", "")
	t.testBitwiseOr("0.0.0.0/16", nil, "0.0.255.255", "0.0.255.255")

	t.testPrefixBitwiseOr("0.0.0.0/16", 18, "0.0.98.8", "", "")
	t.testPrefixBitwiseOr("0.0.0.0/16", 18, "0.0.194.8", "0.0.192.0/18", "")

	//no zeroing going on - first one applies mask up to the new prefix and then applies the prefix, second one masks everything and then keeps the prefix as well (which in the case of all prefixes subnets wipes out any masking done in host)
	t.testPrefixBitwiseOr("0.0.0.1/16", 18, "0.0.194.8", "0.0.192.1/18", "0.0.194.9/16")

	t.testPrefixBitwiseOr("1.2.0.0/16", 24, "0.0.3.248", "", "")
	t.testPrefixBitwiseOr("1.2.0.0/16", 23, "0.0.3.0", "", "")
	t.testPrefixBitwiseOr("1.2.0.0", 24, "0.0.3.248", "1.2.3.0", "1.2.3.248")
	t.testPrefixBitwiseOr("1.2.0.0", 24, "0.0.3.0", "1.2.3.0", "1.2.3.0")
	t.testPrefixBitwiseOr("1.2.0.0", 23, "0.0.3.0", "1.2.2.0", "1.2.3.0")

	t.testPrefixBitwiseOr("::/32", 36, "0:0:6004:8::", "", "")
	t.testPrefixBitwiseOr("::/32", 36, "0:0:f000:8::", "0:0:f000::/36", "")

	t.testPrefixBitwiseOr("1:2::/32", 48, "0:0:3:effe::", "", "")
	t.testPrefixBitwiseOr("1:2::/32", 47, "0:0:3::", "", "")
	t.testPrefixBitwiseOr("1:2::/46", 48, "0:0:3:248::", "1:2:3::/48", "")
	t.testPrefixBitwiseOr("1:2::/48", 48, "0:0:3:248::", "1:2:3::/48", "")
	t.testPrefixBitwiseOr("1:2::/48", 47, "0:0:3::", "1:2:2::/48", "1:2:3::/48")
	t.testPrefixBitwiseOr("1:2::", 48, "0:0:3:248::", "1:2:3::", "1:2:3:248::")
	t.testPrefixBitwiseOr("1:2::", 47, "0:0:3::", "1:2:2::", "1:2:3::")

	t.testBitwiseOr("1:2::", nil, "0:0:3:4::", "1:2:3:4::")
	t.testBitwiseOr("1:2::", nil, "::", "1:2::")
	t.testBitwiseOr("1:2::", nil, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")
	t.testBitwiseOr("1:2::", nil, "fffe:fffd:ffff:ffff:ffff:ffff:ff0f:ffff", "ffff:ffff:ffff:ffff:ffff:ffff:ff0f:ffff")
	t.testBitwiseOr("1::/16", cacheTestBits(32), "0:2:3::", "1:2:3::/48")   //note the prefix length is dropped to become "1.2.3.*", but equality still holds
	t.testBitwiseOr("1:2::/32", cacheTestBits(16), "0:0:3::", "1:2:3::/48") //note the prefix length is dropped to become "1.2.3.*", but equality still holds

	t.testBitwiseOr("::", nil, "::1:2:3:4", "::1:2:3:4")
	t.testBitwiseOr("::", cacheTestBits(1), "::1:2:3:4", "::1:2:3:4")
	t.testBitwiseOr("::", cacheTestBits(-1), "::1:2:3:4", "::1:2:3:4")
	t.testBitwiseOr("::", cacheTestBits(0), "::1:2:3:4", "::1:2:3:4")
	t.testBitwiseOr("::/0", cacheTestBits(-1), "::1:2:3:4", "")
	t.testBitwiseOr("::/32", nil, "::ffff:ffff:ffff:ffff:ffff:ffff", "::ffff:ffff:ffff:ffff:ffff:ffff")

	t.testDelimitedCount("1,2.3.4,5.6", 4) //this will iterate through 1.3.4.6 1.3.5.6 2.3.4.6 2.3.5.6
	t.testDelimitedCount("1,2.3,6.4,5.6,8", 16)
	t.testDelimitedCount("1:2:3:6:4:5:6:8", 1)
	t.testDelimitedCount("1:2,3,4:3:6:4:5,6fff,7,8,99:6:8", 15)

	t.testMatches(false, "1::", "2::")
	t.testMatches(false, "1::", "1.2.3.4")
	t.testMatches(true, "1::", "1:0::")
	t.testMatches(true, "f::", "F:0::")
	t.testMatches(false, "1::", "1:0:1::")
	t.testMatches(false, "f::1.2.3.4", "F:0::1.1.1.1")
	t.testMatches(true, "f::1.2.3.4", "F:0::1.2.3.4")
	t.testMatches(true, "1.2.3.4", "1.2.3.4")
	t.testMatches(true, "1.2.3.4", "001.2.3.04")
	t.testMatches(true, "1.2.3.4", "::ffff:1.2.3.4") //ipv4 mapped
	t.testMatches(true, "1.2.3.4/32", "1.2.3.4")

	//inet_aton style
	t.testMatchesInetAton(true, "1.2.3", "1.2.0.3", true)
	t.testMatchesInetAton(true, "1.2.3.4", "0x1.0x2.0x3.0x4", true)
	t.testMatchesInetAton(true, "1.2.3.4", "01.02.03.04", true)
	t.testMatchesInetAton(true, "0.0.0.4", "00.0x0.0x00.04", true)
	t.testMatchesInetAton(true, "11.11.11.11", "11.0xb.013.0xB", true)
	t.testMatchesInetAton(true, "11.11.0.11", "11.0xb.0xB", true)
	t.testMatchesInetAton(true, "11.11.0.11", "11.0x00000000000000000b.0000000000000000000013", true)
	//if(allPrefixesAreSubnets) {
	//	t.testMatches(true, "11.11.0.11/16", "11.720896/16", true);
	//	t.testMatches(true, "11.0.0.11/16", "184549376/16", true);
	//	t.testMatches(true, "11.0.0.11/16", "0xb000000/16", true);
	//	t.testMatches(true, "11.0.0.11/16", "01300000000/16", true);
	//}
	t.testMatchesInetAton(true, "11.11.0.11/16", "11.720907/16", true)
	t.testMatchesInetAton(true, "11.0.0.11/16", "184549387/16", true)
	t.testMatchesInetAton(true, "11.0.0.11/16", "0xb00000b/16", true)
	t.testMatchesInetAton(true, "11.0.0.11/16", "01300000013/16", true)

	t.testMatches(true, "/16", "/16") //no prefix to speak of, since not known to be ipv4 or ipv6
	t.testMatches(false, "/16", "/15")
	t.testMatches(true, "/15", "/15")
	t.testMatches(true, "/0", "/0")
	t.testMatches(false, "/1", "/0")
	t.testMatches(false, "/0", "/1")
	t.testMatches(true, "/128", "/128")
	t.testMatches(false, "/127", "/128")
	t.testMatches(false, "/128", "/127")

	t.testMatches(true, "11::1.2.3.4/112", "11::102:304/112")
	t.testMatches(true, "11:0:0:0:0:0:1.2.3.4/112", "11:0:0:0:0:0:102:304/112")

	t.testMatches(true, "1:2::/32", "1:2::/ffff:ffff::")
	t.testMatches(true, "1:2::/1", "1:2::/8000::")
	//if(allPrefixesAreSubnets) {
	//	t.testMatches(true, "1:2::", "1:2::/ffff:ffff::1");
	//} else {
	t.testMatches(true, "1:2::/1", "1:2::/ffff:ffff::1")
	//}

	t.testMatches(true, "1:2::/31", "1:2::/ffff:fffe::")

	t.testMatches(true, "0.2.3.0", "1.2.3.4/0.255.255.0")
	//if(allPrefixesAreSubnets) {
	//	t.testMatches(true, "1.2.3.4/16", "1.2.3.4/255.255.0.0");
	//	t.testMatches(true, "1.2.3.4/15", "1.2.3.4/255.254.0.0");
	//	t.testMatches(true, "1.2.3.4/17", "1.2.3.4/255.255.128.0");
	//} else {
	t.testMatches(true, "1.2.128.0/16", "1.2.128.4/255.255.254.1")
	t.testMatches(true, "1.2.2.0/15", "1.2.3.4/255.254.2.3")
	t.testMatches(true, "1.2.0.4/17", "1.2.3.4/255.255.128.5")
	//}

	t.testMatches(false, "1.2.0.0/16", "1.2.3.4/255.255.0.0")
	t.testMatches(false, "1.2.0.0/15", "1.2.3.4/255.254.0.0")
	t.testMatches(false, "1.2.0.0/17", "1.2.3.4/255.255.128.0")

	t.testMatches(true, "1.2.3.4/16", "1.2.3.4/255.255.0.0")
	t.testMatches(true, "1.2.3.4/15", "1.2.3.4/255.254.0.0")
	t.testMatches(true, "1.2.3.4/17", "1.2.3.4/255.255.128.0")

	t.testMatches(false, "1.1.3.4/15", "1.2.3.4/255.254.0.0")
	t.testMatches(false, "1.1.3.4/17", "1.2.3.4/255.255.128.0")

	t.testMatches(false, "0.2.3.4", "1.2.3.4/0.255.255.0")
	t.testMatches(false, "1.2.3.0", "1.2.3.4/0.255.255.0")
	t.testMatches(false, "1.2.3.4", "1.2.3.4/0.255.255.0")
	t.testMatches(false, "1.1.3.4/16", "1.2.3.4/255.255.0.0")

	t.testMatches(true, "1:2:3:4:5:6:1.2.3.4/1:2:3:4:5:6:1.2.3.4", "1:2:3:4:5:6:1.2.3.4")
	t.testMatches(true, "1:2:3:4:5:6:1.2.3.4/1:2:3:4:5:6:0.0.0.0", "1:2:3:4:5:6::")
	t.testMatches(true, "1:2:3:4:5:6:1.2.3.4/1:2:3:4:5:0:0.0.0.0", "1:2:3:4:5::")

	t.testMatches(true, "1:2:3:4:5:6:1.2.3.4%12", "1:2:3:4:5:6:102:304%12")
	t.testMatches(true, "1:2:3:4:5:6:1.2.3.4%a", "1:2:3:4:5:6:102:304%a")
	t.testMatches(true, "1:2:3:4:5:6:1.2.3.4%", "1:2:3:4:5:6:102:304%")
	t.testMatches(true, "1:2:3:4:5:6:1.2.3.4%%", "1:2:3:4:5:6:102:304%%") //the % reappearing as the zone itself is ok

	t.testMatches(false, "1:2:3:4:5:6:1.2.3.4%a", "1:2:3:4:5:6:102:304")
	t.testMatches(true, "1:2:3:4:5:6:1.2.3.4%", "1:2:3:4:5:6:102:304%")
	t.testMatches(true, "1:2:3:4:5:6:1.2.3.4%-a-", "1:2:3:4:5:6:102:304%-a-") //we don't validate the zone itself, so the % reappearing as the zone itself is ok

	//if(isNoAutoSubnets) {
	//	t.testMatches(true, "1::%-.1/16", "1::%-.1");//first one is prefixed and zone, second one just zone
	//	t.testMatches(false, "1::/16", "1::%-.1");//first one has no zone, second one has zone
	//	t.testMatches(true, "1::%-1/16", "1::%-1");//first one is prefixed and zone, second one just zone
	//	t.testMatches(false, "1::/16", "1::%-1");//first one has no zone, second one has zone
	//}
	t.testMatches(true, "1::0.0.0.0%-1", "1::%-1")
	t.testMatches(false, "1::0.0.0.0", "1::%-1") //zones do not match
	t.testMatches(false, "1::0.0.0.0%-1", "1::") //zones do not match

	//if(allPrefixesAreSubnets) {
	//	t.testMatches(true, "1:2:3:4:5:6:1.2.3.4/64", "1:2:3:4::/64");
	//
	//	//more stuff with prefix in mixed part 1:2:3:4:5:6:1.2.3.4/128
	//	t.testMatches(true, "1:2:3:4:5:6:1.2.3.4/96", "1:2:3:4:5:6::/96");
	//	t.testMatches(true, "1:2:3:4:5:6:255.2.3.4/97", "1:2:3:4:5:6:8000::/97");
	//	t.testMatches(true, "1:2:3:4:5:6:1.2.3.4/112", "1:2:3:4:5:6:102::/112");
	//	t.testMatches(true, "1:2:3:4:5:6:1.2.255.4/115", "1:2:3:4:5:6:102:e000/115");
	//}
	t.testMatches(true, "1:2:3:4::0.0.0.0/64", "1:2:3:4::/64")

	//more stuff with prefix in mixed part 1:2:3:4:5:6:1.2.3.4/128
	t.testMatches(true, "1:2:3:4:5:6:0.0.0.0/96", "1:2:3:4:5:6::/96")
	t.testMatches(true, "1:2:3:4:5:6:128.0.0.0/97", "1:2:3:4:5:6:8000::/97")
	t.testMatches(true, "1:2:3:4:5:6:1.2.0.0/112", "1:2:3:4:5:6:102::/112")
	t.testMatches(true, "1:2:3:4:5:6:1.2.224.0/115", "1:2:3:4:5:6:102:e000/115")
	t.testMatches(true, "1:2:3:4:5:6:1.2.3.4/128", "1:2:3:4:5:6:102:304/128")

	t.testMatches(true, "0b1.0b01.0b101.0b11111111", "1.1.5.255")
	t.testMatches(true, "0b1.0b01.0b101.0b11111111/16", "1.1.5.255/16")
	t.testMatches(true, "0b1.1.0b101.0b11111111/16", "1.1.5.255/16")

	t.testMatches(true, "::0b1111111111111111:1", "::ffff:1")
	t.testMatches(true, "0b1111111111111111:1::/64", "ffff:1::/64")
	t.testMatches(true, "::0b1111111111111111:1:0", "::0b1111111111111111:0b0.0b1.0b0.0b0")

}

func (t ipAddressTester) testEquivalentPrefix(host string, prefix ipaddr.BitCount) {
	t.testEquivalentMinPrefix(host, cacheTestBits(prefix), prefix)
}

func (t ipAddressTester) testEquivalentMinPrefix(host string, equivPrefix ipaddr.PrefixLen, minPrefix ipaddr.BitCount) {
	str := t.createAddress(host)
	h1, err := str.ToAddress()
	if err != nil {
		t.addFailure(newFailure("failed "+err.Error(), str))
		return
	}
	equiv := h1.GetPrefixLenForSingleBlock()
	if !equivPrefix.Equals(equiv) {
		t.addFailure(newIPAddrFailure("failed: prefix expected: "+equivPrefix.String()+" prefix got: "+equiv.String(), h1))
		equiv = h1.GetPrefixLenForSingleBlock()
	} else {
		prefixed := h1.AssignPrefixForSingleBlock()
		bareHost := host
		index := strings.Index(host, "/")
		if index >= 0 {
			bareHost = host[:index]
		}
		direct := t.createAddress(bareHost + "/" + equivPrefix.String())
		directAddress := direct.GetAddress()
		if equivPrefix != nil && h1.IsPrefixed() && h1.IsPrefixBlock() {
			directAddress = makePrefixSubnet(directAddress)
		}
		var isFailed bool
		if equiv == nil {
			isFailed = prefixed != nil
		} else {
			isFailed = !directAddress.Equals(prefixed)
		}
		if isFailed {
			t.addFailure(newIPAddrFailure("failed: prefix expected: "+direct.String(), prefixed))
		} else {
			minPref := h1.GetMinPrefixLenForBlock()
			if minPref != minPrefix {
				t.addFailure(newIPAddrFailure("failed: prefix expected: "+minPrefix.String()+" prefix got: "+minPref.String(), h1))
			} else {
				minPrefixed := h1.AssignMinPrefixForBlock()
				bareHost := host
				index := strings.Index(host, "/")
				if index >= 0 {
					bareHost = host[:index]
				}
				direct = t.createAddress(bareHost + "/" + minPrefix.String())
				directAddress = direct.GetAddress()
				if h1.IsPrefixed() && h1.IsPrefixBlock() {
					directAddress = makePrefixSubnet(directAddress)
				}
				//if equiv == nil {
				//	if prefixed != nil {
				//		t.addFailure(newIPAddrFailure("failed: prefix expected: "+direct.String(), minPrefixed))
				//	}
				//} else if !directAddress.Equals(minPrefixed) {
				//	t.addFailure(newIPAddrFailure("failed: prefix expected: "+direct.String(), minPrefixed))
				//}
				if !directAddress.Equals(minPrefixed) {
					// orig "1:2:*::/64" failed: expected match between: 1:2:*::*:*:*/64 and 1:2:*::/64
					t.addFailure(newIPAddrFailure("failed: expected match between: "+directAddress.String()+" and "+minPrefixed.String(), minPrefixed))
				}
			}
		}
	}
	t.incrementTestCount()
}
func (t ipAddressTester) testReverse(addressStr string, bitsReversedIsSame, bitsReversedPerByteIsSame bool) {
	str := t.createAddress(addressStr)
	addr := str.GetAddress()
	//try {
	t.testBase.testReverse(addr.ToAddress().Wrap(), bitsReversedIsSame, bitsReversedPerByteIsSame)
	//} catch(RuntimeException e) {
	//	addFailure(new Failure("reversal: " + addressStr));
	//}
	t.incrementTestCount()
}

func (t ipAddressTester) testPrefixes(
	orig string,
	prefix, adjustment ipaddr.BitCount,
	next,
	previous,
	adjusted,
	prefixSet,
	prefixApplied string) {
	original := t.createAddress(orig).GetAddress()
	if original.IsPrefixed() {
		removed := original.WithoutPrefixLen()
		for i := 0; i < removed.GetSegmentCount(); i++ {
			if !removed.GetSegment(i).Equals(original.GetSegment(i)) {
				t.addFailure(newIPAddrFailure("removed prefix: "+removed.String(), original))
				break
			}
		}
	}
	t.testBase.testPrefixes(original.Wrap(), // OK make it return WrappedAddress
		//t.testBase.testPrefixes(ipaddr.WrappedAddress{original.ToAddress()},
		prefix, adjustment,
		t.createAddress(next).GetAddress().Wrap(),
		t.createAddress(previous).GetAddress().Wrap(),
		t.createAddress(adjusted).GetAddress().Wrap(),
		t.createAddress(prefixSet).GetAddress().Wrap(),
		t.createAddress(prefixApplied).GetAddress().Wrap())
	t.incrementTestCount()
}

func (t ipAddressTester) testBitwiseOr(orig string, prefixAdjustment ipaddr.PrefixLen, or, expectedResult string) {
	original := t.createAddress(orig).GetAddress()
	orAddr := t.createAddress(or).GetAddress()
	if prefixAdjustment != nil {
		var err error
		original, err = original.AdjustPrefixLenZeroed(*prefixAdjustment)
		if err != nil {
			t.addFailure(newIPAddrFailure("adjusted prefix error: "+err.Error(), original))
			return
		}
	}
	//try {
	result, err := original.BitwiseOr(orAddr)
	if err != nil {
		if expectedResult != "" {
			t.addFailure(newIPAddrFailure("ored errored unexpectedly, "+original.String()+" orAddr: "+orAddr.String()+" "+err.Error(), original))
		}
	} else {
		if expectedResult == "" {
			//original.BitwiseOr(orAddr)
			t.addFailure(newIPAddrFailure("ored expected error, "+original.String()+" orAddr: "+orAddr.String()+" result: "+result.String(), original))
		} else {
			expectedResultAddr := t.createAddress(expectedResult).GetAddress()
			if !expectedResultAddr.Equals(result) {
				t.addFailure(newIPAddrFailure("ored expected: "+expectedResultAddr.String()+" actual: "+result.String(), original))
			}
			if !result.GetPrefixLen().Equals(original.GetPrefixLen()) {
				t.addFailure(newIPAddrFailure("ored expected null prefix: "+expectedResultAddr.String()+" actual: "+result.GetPrefixLen().String(), original))
			}
		}
	}
	//} catch(IncompatibleAddressException e) {
	//	if(expectedResult != null) {
	//		addFailure(new Failure("ored threw unexpectedly " + original + " orAddr: " + orAddr, original));
	//	}
	//}
	t.incrementTestCount()
}

//
//	void testPrefixBitwiseOr(String orig, Integer prefix, String or, String expectedNetworkResult) {
//		testPrefixBitwiseOr(orig, prefix, or, expectedNetworkResult, null);
//	}
//
func (t ipAddressTester) testPrefixBitwiseOr(orig string, prefix ipaddr.BitCount, or, expectedNetworkResult, expectedFullResult string) {
	original := t.createAddress(orig).GetAddress()
	orAddr := t.createAddress(or).GetAddress()
	////try {
	//	 result := original.BitwiseOrNetwork(orAddr, prefix);
	//	if(expectedNetworkResult == null) {
	//		t.addFailure(newFailure("ored network expected throw " + original + " orAddr: " + orAddr + " result: " + result, original));
	//	} else {
	//		IPAddressString expected = createAddress(expectedNetworkResult);
	//		IPAddress expectedResultAddr = expected.getAddress();
	//		if(!expectedResultAddr.isPrefixed() || expectedResultAddr.getPrefixLength() != prefix) {
	//			expectedResultAddr = expectedResultAddr.setPrefixLength(prefix, false, false);
	//		}
	//		if(!expectedResultAddr.equals(result)) {
	//			result = original.bitwiseOrNetwork(orAddr, prefix); // 3rd seg not pref block in result, which is right because 3rd seg in original was not
	//			//but 4th seg in result is pref block, which is also right, while not the base with the expected
	//			t.addFailure(newFailure("ored network expected: " + expectedResultAddr + " actual: " + result, original));
	//		}
	//		if(!Objects.equals(expectedResultAddr.getPrefixLength(), result.getPrefixLength())) {
	//			//result = original.bitwiseOrNetwork(orAddr, prefix);
	//			t.addFailure(newFailure("ored network expected pl: " + expectedResultAddr.getPrefixLength() + " actual: " + result.getPrefixLength(), original));
	//		}
	//	}
	////} catch(IncompatibleAddressException e) {
	////	if(expectedNetworkResult != null) {
	////		addFailure(new Failure("ored threw unexpectedly " + original + " orAddr: " + orAddr, original));
	////	}
	////}
	//try {
	result, err := original.BitwiseOr(orAddr)
	if err != nil {
		if expectedFullResult != "" {
			t.addFailure(newIPAddrFailure("ored errored unexpectedly "+original.String()+" orAddr: "+orAddr.String()+" "+err.Error(), original))
		}
	} else {
		if expectedFullResult == "" {
			t.addFailure(newIPAddrFailure("ored expected error, "+original.String()+" orAddr: "+orAddr.String()+" result: "+result.String(), original))
		} else {
			expected := t.createAddress(expectedFullResult)
			expectedResultAddr := expected.GetAddress()
			if !expectedResultAddr.Equals(result) || !expectedResultAddr.GetPrefixLen().Equals(result.GetPrefixLen()) {
				//result, _ = original.BitwiseOr(orAddr);
				t.addFailure(newIPAddrFailure("ored expected: "+expectedResultAddr.String()+" actual: "+result.String(), original))
			}
		}
		//} catch(IncompatibleAddressException e) {
		//	if(expectedFullResult != null) {
		//		addFailure(new Failure("ored threw unexpectedly " + original + " orAddr: " + orAddr, original));
		//	}
		//}
	}
	t.incrementTestCount()
}

func (t ipAddressTester) testDelimitedCount(str string, expectedCount int) {
	strings := ipaddr.ParseDelimitedSegments(str)
	var set []*ipaddr.IPAddress
	count := 0
	//try {
	for strings.HasNext() {
		set = append(set, t.createAddress(strings.Next()).GetAddress())
		count++
	}
	if count != expectedCount || len(set) != count || count != ipaddr.CountDelimitedAddresses(str) {
		t.addFailure(newFailure("count mismatch, count: "+strconv.Itoa(count)+" set count: "+strconv.Itoa(len(set))+" calculated count: "+strconv.Itoa(ipaddr.CountDelimitedAddresses(str))+" expected: "+strconv.Itoa(expectedCount), nil))
	}
	//} catch (AddressStringException | IncompatibleAddressException e) {
	//addFailure(new Failure("threw unexpectedly " + str));
	//}
	t.incrementTestCount()
}

//TODO need to add all the calls to this from IPAddressAllTest, but need to add ipaddralltest first
func (t ipAddressTester) testMatches(matches bool, host1Str, host2Str string) {
	t.testMatchesInetAton(matches, host1Str, host2Str, false)
}

func (t ipAddressTester) testMatchesInetAton(matches bool, host1Str, host2Str string, inet_aton bool) {
	var h1, h2 *ipaddr.IPAddressString
	if inet_aton {
		h1 = t.createInetAtonAddress(host1Str)
		h2 = t.createInetAtonAddress(host2Str)
	} else {
		h1 = t.createAddress(host1Str)
		h2 = t.createAddress(host2Str)
	}

	straightMatch := h1.Equals(h2)
	if matches != straightMatch && matches != conversionMatches(h1, h2) {
		//h1.equals(h2);
		//System.out.println(h1 + ": " + h1.getAddress());
		//System.out.println(h2 + ": " + h2.getAddress());
		t.addFailure(newFailure("failed: matching "+h1.String()+" with "+h2.String(), h1))
	} else {
		if matches != h2.Equals(h1) && matches != conversionMatches(h2, h1) {
			t.addFailure(newFailure("failed: match with "+h1.String(), h2))
		} else {
			var failed bool
			if matches {
				failed = h1.CompareTo(h2) != 0 && conversionCompare(h1, h2) != 0
			} else {
				failed = h1.CompareTo(h2) == 0
			}
			if failed {
				//if(matches ? (h1.CompareTo(h2) != 0 && conversionCompare(h1, h2) != 0) : (h1.CompareTo(h2) == 0)) {
				t.addFailure(newFailure("failed: matching "+h1.String()+" with "+h2.String(), h2))
			} else {
				if matches {
					failed = h2.CompareTo(h1) != 0 && conversionCompare(h2, h1) != 0
				} else {
					failed = h2.CompareTo(h1) == 0
				}
				if failed {
					//if(matches ? (h2.CompareTo(h1) != 0 && conversionCompare(h2, h1) != 0) : (h2.CompareTo(h1) == 0)) {
					t.addFailure(newFailure("failed: match with "+h2.String(), h1))
				} else if straightMatch {
					if h1.GetNetworkPrefixLength() != nil {
						//if(h1.isPrefixOnly() && h1.getNetworkPrefixLength() <= IPv4Address.BIT_COUNT) {
						//	if(h1.prefixEquals(h2)) {
						//		addFailure(new Failure("failed: prefix only match fail with " + h1, h2));
						//	} else {
						//		//this three step test is done so we try it before validation, and then try again before address creation, due to optimizations in IPAddressString
						//		if inet_aton {
						//			h1 = t.createInetAtonAddress(host1Str)
						//			h2 = t.createInetAtonAddress(host2Str)
						//		} else {
						//			h1 = t.createAddress(host1Str)
						//			h2 = t.createAddress(host2Str)
						//		}
						//		if(h1.prefixEquals(h2)) {
						//			addFailure(new Failure("failed: prefix only match fail with " + h1, h2));
						//		}
						//		h1.isValid();
						//		h2.isValid();
						//		if(h1.prefixEquals(h2)) {
						//			addFailure(new Failure("failed: 2 prefix only match fail with " + h1, h2));
						//		}
						//		h1.getAddress();
						//		h2.getAddress();
						//		if(h1.prefixEquals(h2)) {
						//			addFailure(new Failure("failed: 3 prefix only match fail with " + h1, h2));
						//		}
						//	}
						//} else {
						if !h1.PrefixEquals(h2) {
							t.addFailure(newFailure("failed: prefix match fail with "+h1.String(), h2))
						} else {
							//this three step test is done so we try it before validation, and then try again before address creation, due to optimizations in IPAddressString
							if inet_aton {
								h1 = t.createInetAtonAddress(host1Str)
								h2 = t.createInetAtonAddress(host2Str)
							} else {
								h1 = t.createAddress(host1Str)
								h2 = t.createAddress(host2Str)
							}
							//h1 = inet_aton ? createInetAtonAddress(host1Str) : createAddress(host1Str);
							//h2 = inet_aton ? createInetAtonAddress(host2Str) : createAddress(host2Str);
							if !h1.PrefixEquals(h2) {
								t.addFailure(newFailure("failed: prefix match fail with "+h1.String(), h2))
							}
							h1.IsValid()
							h2.IsValid()
							if !h1.PrefixEquals(h2) {
								t.addFailure(newFailure("failed: 2 prefix match fail with "+h1.String(), h2))
							}
							h1.GetAddress()
							h2.GetAddress()
							if !h1.PrefixEquals(h2) {
								t.addFailure(newFailure("failed: 3 prefix match fail with "+h1.String(), h2))
							}
						}
						//}
					}
				}
				//else {
				//	boolean allPrefixesAreSubnets = prefixConfiguration.allPrefixedAddressesAreSubnets();
				//	//if two are not equal, they can still have equal prefix.  Only if host the same can we conclude otherwise.
				//	//So here we first check that host is the same (ie full range host)
				//	if(allPrefixesAreSubnets && h2.getNetworkPrefixLength() != null && h1.getNetworkPrefixLength() != null && h1.getNetworkPrefixLength() >= h2.getNetworkPrefixLength()) {
				//		if(h1.prefixEquals(h2)) {
				//			addFailure(new Failure("failed: prefix match succeeds with " + h1, h2));
				//		} else {
				//			h1 = inet_aton ? createInetAtonAddress(host1Str) : createAddress(host1Str);
				//			h2 = inet_aton ? createInetAtonAddress(host2Str) : createAddress(host2Str);
				//			if(h1.prefixEquals(h2)) {
				//				addFailure(new Failure("failed: prefix match succeeds with " + h1, h2));
				//			}
				//		}
				//	}
				//}
			}
		}
	}
	t.incrementTestCount()
}

var conv = ipaddr.DefaultAddressConverter{}

func conversionMatches(h1, h2 *ipaddr.IPAddressString) bool {
	if h1.IsIPv4() {
		if !h2.IsIPv4() {
			if h2.GetAddress() != nil && conv.IsIPv4Convertible(h2.GetAddress()) {
				return h1.GetAddress().Equals(conv.ToIPv4(h2.GetAddress()))
			}
		}
	} else if h1.IsIPv6() {
		if !h2.IsIPv6() {
			if h2.GetAddress() != nil && conv.IsIPv6Convertible(h2.GetAddress()) {
				return h1.GetAddress().Equals(conv.ToIPv6(h2.GetAddress()))
			}
		}
	}
	return false
}

func conversionCompare(h1, h2 *ipaddr.IPAddressString) int {
	if h1.IsIPv4() {
		if !h2.IsIPv4() {
			if h2.GetAddress() != nil && conv.IsIPv4Convertible(h2.GetAddress()) {
				return h1.GetAddress().CompareTo(conv.ToIPv4(h2.GetAddress()))
			}
		}
		return -1
	} else if h1.IsIPv6() {
		if !h2.IsIPv6() {
			if h2.GetAddress() != nil && conv.IsIPv6Convertible(h2.GetAddress()) {
				return h1.GetAddress().CompareTo(conv.ToIPv6(h2.GetAddress()))
			}
		}
	}
	return 1
}

func makePrefixSubnet(directAddress *ipaddr.IPAddress) *ipaddr.IPAddress {
	segs := directAddress.GetSegments()
	pref := directAddress.GetPrefixLen()
	prefSeg := int(*pref / directAddress.GetBitsPerSegment())
	if prefSeg < len(segs) {
		creator := ipaddr.IPAddressCreator{directAddress.GetIPVersion()}
		if directAddress.GetPrefixCount().Cmp(bigOneConst()) == 0 {
			origSeg := segs[prefSeg]
			mask := origSeg.GetSegmentNetworkMask(*pref % directAddress.GetBitsPerSegment())

			segs[prefSeg] = creator.CreateSegment(origSeg.GetSegmentValue()&mask, origSeg.GetUpperSegmentValue()&mask, origSeg.GetSegmentPrefixLen())
			for ps := prefSeg + 1; ps < len(segs); ps++ {
				segs[ps] = creator.CreatePrefixSegment(0, cacheTestBits(0))
			}
			bytes := make([]byte, directAddress.GetByteCount())
			bytesPerSegment := directAddress.GetBytesPerSegment()
			for i, j := 0, 0; i < len(segs); i++ {
				segs[i].CopyBytes(bytes[j:])
				j += bytesPerSegment
			}
			directAddress = creator.FromPrefixedIP(bytes, pref)
		} else {
			//we could have used SegmentValueProvider in both blocks, but mixing it up to test everything
			origSeg := segs[prefSeg]
			mask := origSeg.GetSegmentNetworkMask(*pref % directAddress.GetBitsPerSegment())
			//maxValue := directAddress.GetMaxSegmentValue()
			directAddress = creator.FromPrefixedVals(
				func(segmentIndex int) ipaddr.SegInt {
					if segmentIndex < prefSeg {
						return segs[segmentIndex].GetSegmentValue()
					} else if segmentIndex == prefSeg {
						return origSeg.GetSegmentValue() & mask
					} else {
						return 0
					}
				},
				func(segmentIndex int) ipaddr.SegInt {
					if segmentIndex < prefSeg {
						return segs[segmentIndex].GetUpperSegmentValue()
					} else if segmentIndex == prefSeg {
						return origSeg.GetUpperSegmentValue() & mask
					} else {
						return 0
					}
				},
				pref,
			)
		}
	}
	return directAddress
}
