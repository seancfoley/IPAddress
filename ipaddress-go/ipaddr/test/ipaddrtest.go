package test

import (
	"bytes"
	"fmt"
	"github.com/seancfoley/ipaddress/ipaddress-go/ipaddr"
	"net"
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
	//if(false) {
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
	//if(false) {
	//	t.testMatches(true, "1:2::", "1:2::/ffff:ffff::1");
	//} else {
	t.testMatches(true, "1:2::/1", "1:2::/ffff:ffff::1")
	//}

	t.testMatches(true, "1:2::/31", "1:2::/ffff:fffe::")

	t.testMatches(true, "0.2.3.0", "1.2.3.4/0.255.255.0")
	//if(false) {
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

	//if(false) {
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

	t.ipv6test(t.allowsRange(), "aa:-1:cc::d:ee:f")  //same as "aa:0-1:cc::d:ee:f"
	t.ipv6test(t.allowsRange(), "aa:-dd:cc::d:ee:f") //same as "aa:0-dd:cc::d:ee:f"
	t.ipv6test(t.allowsRange(), "aa:1-:cc:d::ee:f")  //same as "aa:1-ff:cc:d::ee:f"
	t.ipv6test(t.allowsRange(), "-1:aa:cc:d::ee:f")  //same as "aa:0-1:cc:d::ee:f"
	t.ipv6test(t.allowsRange(), "1-:aa:cc:d::ee:f")  //same as "aa:0-1:cc:d::ee:f"
	t.ipv6test(t.allowsRange(), "aa:cc:d::ee:f:1-")
	t.ipv6test(t.allowsRange(), "aa:0-1:cc:d::ee:f")
	t.ipv6test(t.allowsRange(), "aa:1-ff:cc:d::ee:f")

	t.ipv4test(t.allowsRange(), "1.-1.33.4")
	t.ipv4test(t.allowsRange(), "-1.22.33.4")
	t.ipv4test(t.allowsRange(), "22.1-.33.4")
	t.ipv4test(t.allowsRange(), "22.33.4.1-")
	t.ipv4test(t.allowsRange(), "1-.22.33.4")
	t.ipv4test(t.allowsRange(), "22.0-1.33.4")
	t.ipv4test(t.allowsRange(), "22.1-22.33.4")

	t.ipv4test(false, "1.+1.33.4")
	t.ipv4test(false, "+1.22.33.4")
	t.ipv4test(false, "22.1+.33.4")
	t.ipv4test(false, "22.33.4.1+")
	t.ipv4test(false, "1+.22.33.4")
	t.ipv4test(false, "22.0+1.33.4")
	t.ipv4test(false, "22.1+22.33.4")

	t.ipv6test(false, "::0b11111111111111111:1") // one digit too many
	t.ipv6test(false, "::0b111111111111111:1")   // one digit too few

	t.ipv4test(t.allowsRange(), "0b1.0b01.0b101.1-0b11111111")
	t.ipv4test(t.allowsRange(), "0b1.0b01.0b101.0b11110000-0b11111111")

	t.ipv6test(t.allowsRange(), "::0b0000111100001111-0b1111000011110000:3")
	t.ipv6test(t.allowsRange(), "0b0000111100001111-0b1111000011110000::3")
	t.ipv6test(t.allowsRange(), "1::0b0000111100001111-0b1111000011110000:3")
	t.ipv6test(t.allowsRange(), "1::0b0000111100001111-0b1111000011110000")
	t.ipv6test(t.allowsRange(), "1:0b0000111100001111-0b1111000011110000:3::")

	t.ipv4test(false, "0b1.0b01.0b101.0b111111111") // one digit too many
	t.ipv4test(false, "0b.0b01.0b101.0b111111111")  // one digit too few
	t.ipv4test(false, "0b1.0b01.0b101.0b11121111")  // not binary
	t.ipv4test(false, "0b1.0b2.0b101.0b1111111")    // not binary
	t.ipv4test(false, "0b1.b1.0b101.0b1111111")     // not binary

	t.ipv4test(true, "1.2.3.4/255.1.0.0")
	t.ipv4test(false, "1.2.3.4/1::1") //mask mismatch
	t.ipv6test(true, "1:2::/1:2::")
	t.ipv6test(false, "1:2::/1:2::/16")
	t.ipv6test(false, "1:2::/1.2.3.4") //mask mismatch

	//test some valid and invalid prefixes
	t.ipv4test(true, "1.2.3.4/1")
	t.ipv4test(false, "1.2.3.4/ 1")
	t.ipv4test(false, "1.2.3.4/-1")
	t.ipv4test(false, "1.2.3.4/+1")
	t.ipv4test(false, "1.2.3.4/")
	t.ipv4test(true, "1.2.3.4/1.2.3.4")
	t.ipv4test(false, "1.2.3.4/x")
	t.ipv4test(true, "1.2.3.4/33") //we are now allowing extra-large prefixes
	t.ipv6test(true, "1::1/1")
	t.ipv6test(false, "1::1/-1")
	t.ipv6test(false, "1::1/")
	t.ipv6test(false, "1::1/x")
	t.ipv6test(false, "1::1/129") //we are not allowing extra-large prefixes
	t.ipv6test(true, "1::1/1::1")

	t.ipv4zerotest(t.isLenient(), "") //this needs special validation options to be valid

	t.ipv4test(true, "1.2.3.4")
	t.ipv4test(false, "[1.2.3.4]") //HostName accepts square brackets, not addresses

	t.ipv4test(false, "a")

	t.ipv4test(t.isLenient(), "1.2.3")

	t.ipv4test(false, "a.2.3.4")
	t.ipv4test(false, "1.a.3.4")
	t.ipv4test(false, "1.2.a.4")
	t.ipv4test(false, "1.2.3.a")

	t.ipv4test(false, ".2.3.4")
	t.ipv4test(false, "1..3.4")
	t.ipv4test(false, "1.2..4")
	t.ipv4test(false, "1.2.3.")

	t.ipv4test(false, "256.2.3.4")
	t.ipv4test(false, "1.256.3.4")
	t.ipv4test(false, "1.2.256.4")
	t.ipv4test(false, "1.2.3.256")

	t.ipv4test(false, "f.f.f.f")

	t.ipv4zerotest(true, "0.0.0.0")
	t.ipv4zerotest(true, "00.0.0.0")
	t.ipv4zerotest(true, "0.00.0.0")
	t.ipv4zerotest(true, "0.0.00.0")
	t.ipv4zerotest(true, "0.0.0.00")
	t.ipv4zerotest(true, "000.0.0.0")
	t.ipv4zerotest(true, "0.000.0.0")
	t.ipv4zerotest(true, "0.0.000.0")
	t.ipv4zerotest(true, "0.0.0.000")

	t.ipv4zerotest(true, "000.000.000.000")

	t.ipv4zerotest(t.isLenient(), "0000.0.0.0")
	t.ipv4zerotest(t.isLenient(), "0.0000.0.0")
	t.ipv4zerotest(t.isLenient(), "0.0.0000.0")
	t.ipv4zerotest(t.isLenient(), "0.0.0.0000")

	t.ipv4test(true, "3.3.3.3")
	t.ipv4test(true, "33.3.3.3")
	t.ipv4test(true, "3.33.3.3")
	t.ipv4test(true, "3.3.33.3")
	t.ipv4test(true, "3.3.3.33")
	t.ipv4test(true, "233.3.3.3")
	t.ipv4test(true, "3.233.3.3")
	t.ipv4test(true, "3.3.233.3")
	t.ipv4test(true, "3.3.3.233")

	t.ipv4test(true, "200.200.200.200")

	t.ipv4test(t.isLenient(), "0333.0.0.0")
	t.ipv4test(t.isLenient(), "0.0333.0.0")
	t.ipv4test(t.isLenient(), "0.0.0333.0")
	t.ipv4test(t.isLenient(), "0.0.0.0333")

	t.ipv4test(false, "1.2.3:4")
	t.ipv4test(false, "1.2:3.4")
	t.ipv6test(false, "1.2.3:4")
	t.ipv6test(false, "1.2:3.4")

	t.ipv4test(false, "1.2.3.4:1.2.3.4")
	t.ipv4test(false, "1.2.3.4.1:2.3.4")
	t.ipv4test(false, "1.2.3.4.1.2:3.4")
	t.ipv4test(false, "1.2.3.4.1.2.3:4")
	t.ipv6test(false, "1.2.3.4:1.2.3.4")
	t.ipv6test(false, "1.2.3.4.1:2.3.4")
	t.ipv6test(false, "1.2.3.4.1.2:3.4")
	t.ipv6test(false, "1.2.3.4.1.2.3:4")

	t.ipv4test(false, "1:2.3.4")
	t.ipv4test(false, "1:2:3.4")
	t.ipv4test(false, "1:2:3:4")
	t.ipv6test(false, "1:2.3.4")
	t.ipv6test(false, "1:2:3.4")
	t.ipv6test(false, "1:2:3:4")

	t.ipv6test(false, "1.2.3.4.1.2.3.4")
	t.ipv6test(false, "1:2.3.4.1.2.3.4")
	t.ipv6test(false, "1:2:3.4.1.2.3.4")
	t.ipv6test(false, "1:2:3:4.1.2.3.4")
	t.ipv6test(false, "1:2:3:4:1.2.3.4")
	t.ipv6test(false, "1:2:3:4:1:2.3.4")
	t.ipv6test(true, "1:2:3:4:1:2:1.2.3.4")
	t.ipv6test(t.isLenient(), "1:2:3:4:1:2:3.4") // if inet_aton allowed, this is equivalent to 1:2:3:4:1:2:0.0.3.4 or 1:2:3:4:1:2:0:304
	t.ipv6test(true, "1:2:3:4:1:2:3:4")

	t.ipv6zerotest(true, "0:0:0:0:0:0:0:0")
	t.ipv6zerotest(true, "00:0:0:0:0:0:0:0")
	t.ipv6zerotest(true, "0:00:0:0:0:0:0:0")
	t.ipv6zerotest(true, "0:0:00:0:0:0:0:0")
	t.ipv6zerotest(true, "0:0:0:00:0:0:0:0")
	t.ipv6zerotest(true, "0:0:0:0:00:0:0:0")
	t.ipv6zerotest(true, "0:0:0:0:0:00:0:0")
	t.ipv6zerotest(true, "0:0:0:0:0:0:00:0")
	t.ipv6zerotest(true, "0:0:0:0:0:0:0:00")
	t.ipv6zerotest(true, "0:0:0:0:0:0:0:0")
	t.ipv6zerotest(true, "000:0:0:0:0:0:0:0")
	t.ipv6zerotest(true, "0:000:0:0:0:0:0:0")
	t.ipv6zerotest(true, "0:0:000:0:0:0:0:0")
	t.ipv6zerotest(true, "0:0:0:000:0:0:0:0")
	t.ipv6zerotest(true, "0:0:0:0:000:0:0:0")
	t.ipv6zerotest(true, "0:0:0:0:0:000:0:0")
	t.ipv6zerotest(true, "0:0:0:0:0:0:000:0")
	t.ipv6zerotest(true, "0:0:0:0:0:0:0:000")
	t.ipv6zerotest(true, "0000:0:0:0:0:0:0:0")
	t.ipv6zerotest(true, "0:0000:0:0:0:0:0:0")
	t.ipv6zerotest(true, "0:0:0000:0:0:0:0:0")
	t.ipv6zerotest(true, "0:0:0:0000:0:0:0:0")
	t.ipv6zerotest(true, "0:0:0:0:0000:0:0:0")
	t.ipv6zerotest(true, "0:0:0:0:0:0000:0:0")
	t.ipv6zerotest(true, "0:0:0:0:0:0:0000:0")
	t.ipv6zerotest(true, "0:0:0:0:0:0:0:0000")
	t.ipv6zerotest(t.isLenient(), "00000:0:0:0:0:0:0:0")
	t.ipv6zerotest(t.isLenient(), "0:00000:0:0:0:0:0:0")
	t.ipv6zerotest(t.isLenient(), "0:0:00000:0:0:0:0:0")
	t.ipv6zerotest(t.isLenient(), "0:0:0:00000:0:0:0:0")
	t.ipv6zerotest(t.isLenient(), "0:0:0:0:00000:0:0:0")
	t.ipv6zerotest(t.isLenient(), "0:0:0:0:0:00000:0:0")
	t.ipv6zerotest(t.isLenient(), "0:0:0:0:0:0:00000:0")
	t.ipv6zerotest(t.isLenient(), "0:0:0:0:0:0:0:00000")
	t.ipv6zerotest(t.isLenient(), "00000:00000:00000:00000:00000:00000:00000:00000")

	t.ipv6test(t.isLenient(), "03333:0:0:0:0:0:0:0")
	t.ipv6test(t.isLenient(), "0:03333:0:0:0:0:0:0")
	t.ipv6test(t.isLenient(), "0:0:03333:0:0:0:0:0")
	t.ipv6test(t.isLenient(), "0:0:0:03333:0:0:0:0")
	t.ipv6test(t.isLenient(), "0:0:0:0:03333:0:0:0")
	t.ipv6test(t.isLenient(), "0:0:0:0:0:03333:0:0")
	t.ipv6test(t.isLenient(), "0:0:0:0:0:0:03333:0")
	t.ipv6test(t.isLenient(), "0:0:0:0:0:0:0:03333")
	t.ipv6test(t.isLenient(), "03333:03333:03333:03333:03333:03333:03333:03333")

	t.ipv4test(false, ".0.0.0")
	t.ipv4test(false, "0..0.0")
	t.ipv4test(false, "0.0..0")
	t.ipv4test(false, "0.0.0.")

	//t.ipv4test(true, "/0")
	//t.ipv4test(true, "/1")
	//t.ipv4test(true, "/31")
	//t.ipv4test(true, "/32")
	//t.ipv4test2(false, "/33", false, true)

	t.ipv4test(false, "/0")
	t.ipv4test(false, "/1")
	t.ipv4test(false, "/31")
	t.ipv4test(false, "/32")
	t.ipv4test(false, "/33")

	t.ipv4test(false, "1.2.3.4//16")
	t.ipv4test(false, "1.2.3.4//")
	t.ipv4test(false, "1.2.3.4/")
	t.ipv4test(false, "/1.2.3.4//16")
	t.ipv4test(false, "/1.2.3.4/16")
	t.ipv4test(false, "/1.2.3.4")
	t.ipv4test(false, "1.2.3.4/y")
	t.ipv4test(true, "1.2.3.4/16")
	t.ipv6test(false, "1:2::3:4//16")
	t.ipv6test(false, "1:2::3:4//")
	t.ipv6test(false, "1:2::3:4/")
	t.ipv6test(false, "1:2::3:4/y")
	t.ipv6test(true, "1:2::3:4/16")
	t.ipv6test(true, "1:2::3:1.2.3.4/16")
	t.ipv6test(false, "1:2::3:1.2.3.4//16")
	t.ipv6test(false, "1:2::3:1.2.3.4//")
	t.ipv6test(false, "1:2::3:1.2.3.4/y")

	t.ipv4test(false, "127.0.0.1/x")
	t.ipv4test(false, "127.0.0.1/127.0.0.1/x")

	t.ipv4_inet_aton_test(true, "0.0.0.255")
	t.ipv4_inet_aton_test(false, "0.0.0.256")
	t.ipv4_inet_aton_test(true, "0.0.65535")
	t.ipv4_inet_aton_test(false, "0.0.65536")
	t.ipv4_inet_aton_test(true, "0.16777215")
	t.ipv4_inet_aton_test(false, "0.16777216")
	t.ipv4_inet_aton_test(true, "4294967295")
	t.ipv4_inet_aton_test(false, "4294967296")
	t.ipv4_inet_aton_test(true, "0.0.0.0xff")
	t.ipv4_inet_aton_test(false, "0.0.0.0x100")
	t.ipv4_inet_aton_test(true, "0.0.0xffff")
	t.ipv4_inet_aton_test(false, "0.0.0x10000")
	t.ipv4_inet_aton_test(true, "0.0xffffff")
	t.ipv4_inet_aton_test(false, "0.0x1000000")
	t.ipv4_inet_aton_test(true, "0xffffffff")
	t.ipv4_inet_aton_test(false, "0x100000000")
	t.ipv4_inet_aton_test(true, "0.0.0.0377")
	t.ipv4_inet_aton_test(false, "0.0.0.0400")
	t.ipv4_inet_aton_test(true, "0.0.017777")
	t.ipv4_inet_aton_test(false, "0.0.0200000")
	t.ipv4_inet_aton_test(true, "0.077777777")
	t.ipv4_inet_aton_test(false, "0.0100000000")
	t.ipv4_inet_aton_test(true, "03777777777")
	t.ipv4_inet_aton_test(true, "037777777777")
	t.ipv4_inet_aton_test(false, "040000000000")

	t.ipv4_inet_aton_test(false, "1.00x.1.1")
	t.ipv4_inet_aton_test(false, "00x1.1.1.1")
	t.ipv4_inet_aton_test(false, "1.00x0.1.1")
	t.ipv4_inet_aton_test(false, "1.0xx.1.1")
	t.ipv4_inet_aton_test(false, "1.xx.1.1")
	t.ipv4_inet_aton_test(false, "1.0x4x.1.1")
	t.ipv4_inet_aton_test(false, "1.x4.1.1")

	t.ipv4test(false, "1.00x.1.1")
	t.ipv4test(false, "1.0xx.1.1")
	t.ipv4test(false, "1.xx.1.1")
	t.ipv4test(false, "1.0x4x.1.1")
	t.ipv4test(false, "1.x4.1.1")

	t.ipv4test(false, "1.4.1.1%1") //ipv4 zone

	t.ipv6test(false, "1:00x:3:4:5:6:7:8")
	t.ipv6test(false, "1:0xx:3:4:5:6:7:8")
	t.ipv6test(false, "1:xx:3:4:5:6:7:8")
	t.ipv6test(false, "1:0x4x:3:4:5:6:7:8")
	t.ipv6test(false, "1:x4:3:4:5:6:7:8")

	t.ipv4testOnly(false, "1:2:3:4:5:6:7:8")
	t.ipv4testOnly(false, "::1")

	// in this test, the validation will fail unless validation options have allowEmpty
	t.ipv6zerotest(t.isLenient(), "") // empty string //this needs special validation options to be valid

	//t.ipv6test(true, "/0")
	//t.ipv6test(true, "/1")
	//t.ipv6test(true, "/127")
	//t.ipv6test(true, "/128")
	t.ipv6test(false, "/0")
	t.ipv6test(false, "/1")
	t.ipv6test(false, "/127")
	t.ipv6test(false, "/128")
	t.ipv6test(false, "/129")

	t.ipv6test(true, "::/0")
	t.ipv6test(false, ":1.2.3.4") //invalid
	t.ipv6test(true, "::1.2.3.4")

	t.ipv6test(true, "::1")                               // loopback, compressed, non-routable
	t.ipv6zerotest(true, "::")                            // unspecified, compressed, non-routable
	t.ipv6test(true, "0:0:0:0:0:0:0:1")                   // loopback, full
	t.ipv6zerotest(true, "0:0:0:0:0:0:0:0")               // unspecified, full
	t.ipv6test(true, "2001:DB8:0:0:8:800:200C:417A")      // unicast, full
	t.ipv6test(true, "FF01:0:0:0:0:0:0:101")              // multicast, full
	t.ipv6test(true, "2001:DB8::8:800:200C:417A")         // unicast, compressed
	t.ipv6test(true, "FF01::101")                         // multicast, compressed
	t.ipv6test(false, "2001:DB8:0:0:8:800:200C:417A:221") // unicast, full
	t.ipv6test(false, "FF01::101::2")                     // multicast, compressed
	t.ipv6test(true, "fe80::217:f2ff:fe07:ed62")

	t.ipv6test(false, "[a::b:c:d:1.2.3.4]")                          // square brackets can enclose ipv6 in host names but not addresses
	t.ipv6test(false, "[a::b:c:d:1.2.3.4%x]")                        // square brackets can enclose ipv6 in host names but not addresses
	t.ipv6test(true, "a::b:c:d:1.2.3.4%x")                           //
	t.ipv6test(false, "[2001:0000:1234:0000:0000:C1C0:ABCD:0876]")   // square brackets can enclose ipv6 in host names but not addresses
	t.ipv6test(true, "2001:0000:1234:0000:0000:C1C0:ABCD:0876%x")    // square brackets can enclose ipv6 in host names but not addresses
	t.ipv6test(false, "[2001:0000:1234:0000:0000:C1C0:ABCD:0876%x]") //

	t.ipv6test(true, "::1%/32") // empty zone
	t.ipv6test(true, "::1%")    // empty zone

	t.ipv6test(true, "2001:0000:1234:0000:0000:C1C0:ABCD:0876")
	t.ipv6test(true, "3ffe:0b00:0000:0000:0001:0000:0000:000a")
	t.ipv6test(true, "FF02:0000:0000:0000:0000:0000:0000:0001")
	t.ipv6test(true, "0000:0000:0000:0000:0000:0000:0000:0001")
	t.ipv6zerotest(true, "0000:0000:0000:0000:0000:0000:0000:0000")
	t.ipv6test(t.isLenient(), "02001:0000:1234:0000:0000:C1C0:ABCD:0876") // extra 0 not allowed!
	t.ipv6test(t.isLenient(), "2001:0000:1234:0000:00001:C1C0:ABCD:0876") // extra 0 not allowed!
	t.ipv6test(false, "2001:0000:1234:0000:0000:C1C0:ABCD:0876  0")       // junk after valid address
	t.ipv6test(false, "0 2001:0000:1234:0000:0000:C1C0:ABCD:0876")        // junk before valid address
	t.ipv6test(false, "2001:0000:1234: 0000:0000:C1C0:ABCD:0876")         // internal space

	t.ipv6test(false, "3ffe:0b00:0000:0001:0000:0000:000a")           // seven segments
	t.ipv6test(false, "FF02:0000:0000:0000:0000:0000:0000:0000:0001") // nine segments
	t.ipv6test(false, "3ffe:b00::1::a")                               // double "::"
	t.ipv6test(false, "::1111:2222:3333:4444:5555:6666::")            // double "::"
	t.ipv6test(true, "2::10")
	t.ipv6test(true, "ff02::1")
	t.ipv6test(true, "fe80::")
	t.ipv6test(true, "2002::")
	t.ipv6test(true, "2001:db8::")
	t.ipv6test(true, "2001:0db8:1234::")
	t.ipv6test(true, "::ffff:0:0")
	t.ipv6test(true, "::1")
	t.ipv6test(true, "1:2:3:4:5:6:7:8")
	t.ipv6test(true, "1:2:3:4:5:6::8")
	t.ipv6test(true, "1:2:3:4:5::8")
	t.ipv6test(true, "1:2:3:4::8")
	t.ipv6test(true, "1:2:3::8")
	t.ipv6test(true, "1:2::8")
	t.ipv6test(true, "1::8")
	t.ipv6test(true, "1::2:3:4:5:6:7")
	t.ipv6test(true, "1::2:3:4:5:6")
	t.ipv6test(true, "1::2:3:4:5")
	t.ipv6test(true, "1::2:3:4")
	t.ipv6test(true, "1::2:3")
	t.ipv6test(true, "1::8")

	t.ipv6test(true, "::2:3:4:5:6:7:8")
	t.ipv6test(true, "::2:3:4:5:6:7")
	t.ipv6test(true, "::2:3:4:5:6")
	t.ipv6test(true, "::2:3:4:5")
	t.ipv6test(true, "::2:3:4")
	t.ipv6test(true, "::2:3")
	t.ipv6test(true, "::8")
	t.ipv6test(true, "1:2:3:4:5:6::")
	t.ipv6test(true, "1:2:3:4:5::")
	t.ipv6test(true, "1:2:3:4::")
	t.ipv6test(true, "1:2:3::")
	t.ipv6test(true, "1:2::")
	t.ipv6test(true, "1::")
	t.ipv6test(true, "1:2:3:4:5::7:8")
	t.ipv6test(false, "1:2:3::4:5::7:8") // Double "::"
	t.ipv6test(false, "12345::6:7:8")
	t.ipv6test(true, "1:2:3:4::7:8")
	t.ipv6test(true, "1:2:3::7:8")
	t.ipv6test(true, "1:2::7:8")
	t.ipv6test(true, "1::7:8")

	// IPv4 addresses as dotted-quads
	t.ipv6test(true, "1:2:3:4:5:6:1.2.3.4")
	t.ipv6zerotest(true, "0:0:0:0:0:0:0.0.0.0")

	t.ipv6test(true, "1:2:3:4:5::1.2.3.4")
	t.ipv6zerotest(true, "0:0:0:0:0::0.0.0.0")

	t.ipv6zerotest(true, "0::0.0.0.0")
	t.ipv6zerotest(true, "::0.0.0.0")

	t.ipv6test(false, "1:2:3:4:5:6:.2.3.4")
	t.ipv6test(false, "1:2:3:4:5:6:1.2.3.")
	t.ipv6test(false, "1:2:3:4:5:6:1.2..4")
	t.ipv6test(true, "1:2:3:4:5:6:1.2.3.4")

	t.ipv6test(true, "1:2:3:4::1.2.3.4")
	t.ipv6test(true, "1:2:3::1.2.3.4")
	t.ipv6test(true, "1:2::1.2.3.4")
	t.ipv6test(true, "1::1.2.3.4")
	t.ipv6test(true, "1:2:3:4::5:1.2.3.4")
	t.ipv6test(true, "1:2:3::5:1.2.3.4")
	t.ipv6test(true, "1:2::5:1.2.3.4")
	t.ipv6test(true, "1::5:1.2.3.4")
	t.ipv6test(true, "1::5:11.22.33.44")
	t.ipv6test(false, "1::5:400.2.3.4")
	t.ipv6test(false, "1::5:260.2.3.4")
	t.ipv6test(false, "1::5:256.2.3.4")
	t.ipv6test(false, "1::5:1.256.3.4")
	t.ipv6test(false, "1::5:1.2.256.4")
	t.ipv6test(false, "1::5:1.2.3.256")
	t.ipv6test(false, "1::5:300.2.3.4")
	t.ipv6test(false, "1::5:1.300.3.4")
	t.ipv6test(false, "1::5:1.2.300.4")
	t.ipv6test(false, "1::5:1.2.3.300")
	t.ipv6test(false, "1::5:900.2.3.4")
	t.ipv6test(false, "1::5:1.900.3.4")
	t.ipv6test(false, "1::5:1.2.900.4")
	t.ipv6test(false, "1::5:1.2.3.900")
	t.ipv6test(false, "1::5:300.300.300.300")
	t.ipv6test(false, "1::5:3000.30.30.30")
	t.ipv6test(false, "1::400.2.3.4")
	t.ipv6test(false, "1::260.2.3.4")
	t.ipv6test(false, "1::256.2.3.4")
	t.ipv6test(false, "1::1.256.3.4")
	t.ipv6test(false, "1::1.2.256.4")
	t.ipv6test(false, "1::1.2.3.256")
	t.ipv6test(false, "1::300.2.3.4")
	t.ipv6test(false, "1::1.300.3.4")
	t.ipv6test(false, "1::1.2.300.4")
	t.ipv6test(false, "1::1.2.3.300")
	t.ipv6test(false, "1::900.2.3.4")
	t.ipv6test(false, "1::1.900.3.4")
	t.ipv6test(false, "1::1.2.900.4")
	t.ipv6test(false, "1::1.2.3.900")
	t.ipv6test(false, "1::300.300.300.300")
	t.ipv6test(false, "1::3000.30.30.30")
	t.ipv6test(false, "::400.2.3.4")
	t.ipv6test(false, "::260.2.3.4")
	t.ipv6test(false, "::256.2.3.4")
	t.ipv6test(false, "::1.256.3.4")
	t.ipv6test(false, "::1.2.256.4")
	t.ipv6test(false, "::1.2.3.256")
	t.ipv6test(false, "::300.2.3.4")
	t.ipv6test(false, "::1.300.3.4")
	t.ipv6test(false, "::1.2.300.4")
	t.ipv6test(false, "::1.2.3.300")
	t.ipv6test(false, "::900.2.3.4")
	t.ipv6test(false, "::1.900.3.4")
	t.ipv6test(false, "::1.2.900.4")
	t.ipv6test(false, "::1.2.3.900")
	t.ipv6test(false, "::300.300.300.300")
	t.ipv6test(false, "::3000.30.30.30")
	t.ipv6test(true, "fe80::217:f2ff:254.7.237.98")
	t.ipv6test(true, "::ffff:192.168.1.26")
	t.ipv6test(false, "2001:1:1:1:1:1:255Z255X255Y255") // garbage instead of "." in IPv4
	t.ipv6test(false, "::ffff:192x168.1.26")            // ditto
	t.ipv6test(true, "::ffff:192.168.1.1")
	t.ipv6test(true, "0:0:0:0:0:0:13.1.68.3")        // IPv4-compatible IPv6 address, full, deprecated
	t.ipv6test(true, "0:0:0:0:0:FFFF:129.144.52.38") // IPv4-mapped IPv6 address, full
	t.ipv6test(true, "::13.1.68.3")                  // IPv4-compatible IPv6 address, compressed, deprecated
	t.ipv6test(true, "::FFFF:129.144.52.38")         // IPv4-mapped IPv6 address, compressed
	t.ipv6test(true, "fe80:0:0:0:204:61ff:254.157.241.86")
	t.ipv6test(true, "fe80::204:61ff:254.157.241.86")
	t.ipv6test(true, "::ffff:12.34.56.78")
	t.ipv6test(t.isLenient(), "::ffff:2.3.4")
	t.ipv6test(false, "::ffff:257.1.2.3")
	t.ipv6testOnly(false, "1.2.3.4")

	//stuff that might be mistaken for mixed if we parse incorrectly
	t.ipv6test(false, "a:b:c:d:e:f:a:b:c:d:e:f:1.2.3.4")
	t.ipv6test(false, "a:b:c:d:e:f:a:b:c:d:e:f:a:b.")
	t.ipv6test(false, "a:b:c:d:e:f:1.a:b:c:d:e:f:a")
	t.ipv6test(false, "a:b:c:d:e:f:1.a:b:c:d:e:f:a:b")
	t.ipv6test(false, "a:b:c:d:e:f:.a:b:c:d:e:f:a:b")

	t.ipv6test(false, "::a:b:c:d:e:f:1.2.3.4")
	t.ipv6test(false, "::a:b:c:d:e:f:a:b.")
	t.ipv6test(false, "::1.a:b:c:d:e:f:a")
	t.ipv6test(false, "::1.a:b:c:d:e:f:a:b")
	t.ipv6test(false, "::.a:b:c:d:e:f:a:b")

	t.ipv6test(false, "1::a:b:c:d:e:f:1.2.3.4")
	t.ipv6test(false, "1::a:b:c:d:e:f:a:b.")
	t.ipv6test(false, "1::1.a:b:c:d:e:f:a")
	t.ipv6test(false, "1::1.a:b:c:d:e:f:a:b")
	t.ipv6test(false, "1::.a:b:c:d:e:f:a:b")

	t.ipv6test(true, "1:2:3:4:5:6:1.2.3.4/1:2:3:4:5:6:1.2.3.4")

	// Testing IPv4 addresses represented as dotted-quads
	// Leading zero's in IPv4 addresses not allowed: some systems treat the leading "0" in ".086" as the start of an octal number
	// Update: The BNF in RFC-3986 explicitly defines the dec-octet (for IPv4 addresses) not to have a leading zero
	//t.ipv6test(false,"fe80:0000:0000:0000:0204:61ff:254.157.241.086");
	t.ipv6test(!t.isLenient(), "fe80:0000:0000:0000:0204:61ff:254.157.241.086") //note the 086 is treated as octal when lenient!  So the lenient in this case fails.
	t.ipv6test(true, "::ffff:192.0.2.128")                                      // this is always OK, since there's a single digit
	t.ipv6test(false, "XXXX:XXXX:XXXX:XXXX:XXXX:XXXX:1.2.3.4")
	//t.ipv6test(false,"1111:2222:3333:4444:5555:6666:00.00.00.00");
	t.ipv6test(true, "1111:2222:3333:4444:5555:6666:00.00.00.00")
	//t.ipv6test(false,"1111:2222:3333:4444:5555:6666:000.000.000.000");
	t.ipv6test(true, "1111:2222:3333:4444:5555:6666:000.000.000.000")
	t.ipv6test(false, "1111:2222:3333:4444:5555:6666:256.256.256.256")

	// Not testing address with subnet mask
	// t.ipv6test(true,"2001:0DB8:0000:CD30:0000:0000:0000:0000/60");// full, with prefix
	// t.ipv6test(true,"2001:0DB8::CD30:0:0:0:0/60");// compressed, with prefix
	// t.ipv6test(true,"2001:0DB8:0:CD30::/60");// compressed, with prefix //2
	// t.ipv6test(true,"::/128");// compressed, unspecified address type, non-routable
	// t.ipv6test(true,"::1/128");// compressed, loopback address type, non-routable
	// t.ipv6test(true,"FF00::/8");// compressed, multicast address type
	// t.ipv6test(true,"FE80::/10");// compressed, link-local unicast, non-routable
	// t.ipv6test(true,"FEC0::/10");// compressed, site-local unicast, deprecated
	// t.ipv6test(false,"124.15.6.89/60");// standard IPv4, prefix not allowed

	t.ipv6test(true, "fe80:0000:0000:0000:0204:61ff:fe9d:f156")
	t.ipv6test(true, "fe80:0:0:0:204:61ff:fe9d:f156")
	t.ipv6test(true, "fe80::204:61ff:fe9d:f156")
	t.ipv6test(true, "::1")
	t.ipv6test(true, "fe80::")
	t.ipv6test(true, "fe80::1")
	t.ipv6test(false, ":")
	t.ipv6test(true, "::ffff:c000:280")

	// Aeron supplied these test cases

	t.ipv6test(false, "1111:2222:3333:4444::5555:")
	t.ipv6test(false, "1111:2222:3333::5555:")
	t.ipv6test(false, "1111:2222::5555:")
	t.ipv6test(false, "1111::5555:")
	t.ipv6test(false, "::5555:")

	t.ipv6test(false, ":::")
	t.ipv6test(false, "1111:")
	t.ipv6test(false, ":")

	t.ipv6test(false, ":1111:2222:3333:4444::5555")
	t.ipv6test(false, ":1111:2222:3333::5555")
	t.ipv6test(false, ":1111:2222::5555")
	t.ipv6test(false, ":1111::5555")

	t.ipv6test(false, ":::5555")
	t.ipv6test(false, ":::")

	// Additional test cases
	// from http://rt.cpan.org/Public/Bug/Display.html?id=50693

	t.ipv6test(true, "2001:0db8:85a3:0000:0000:8a2e:0370:7334")
	t.ipv6test(true, "2001:db8:85a3:0:0:8a2e:370:7334")
	t.ipv6test(true, "2001:db8:85a3::8a2e:370:7334")
	t.ipv6test(true, "2001:0db8:0000:0000:0000:0000:1428:57ab")
	t.ipv6test(true, "2001:0db8:0000:0000:0000::1428:57ab")
	t.ipv6test(true, "2001:0db8:0:0:0:0:1428:57ab")
	t.ipv6test(true, "2001:0db8:0:0::1428:57ab")
	t.ipv6test(true, "2001:0db8::1428:57ab")
	t.ipv6test(true, "2001:db8::1428:57ab")
	t.ipv6test(true, "0000:0000:0000:0000:0000:0000:0000:0001")
	t.ipv6test(true, "::1")
	t.ipv6test(true, "::ffff:0c22:384e")
	t.ipv6test(true, "2001:0db8:1234:0000:0000:0000:0000:0000")
	t.ipv6test(true, "2001:0db8:1234:ffff:ffff:ffff:ffff:ffff")
	t.ipv6test(true, "2001:db8:a::123")
	t.ipv6test(true, "fe80::")

	t.ipv6test2(false, "123", false, t.isLenient()) //this is passing the ipv4 side as inet_aton
	t.ipv6test(false, "ldkfj")
	t.ipv6test(false, "2001::FFD3::57ab")
	t.ipv6test(false, "2001:db8:85a3::8a2e:37023:7334")
	t.ipv6test(false, "2001:db8:85a3::8a2e:370k:7334")
	t.ipv6test(false, "1:2:3:4:5:6:7:8:9")
	t.ipv6test(false, "1::2::3")
	t.ipv6test(false, "1:::3:4:5")
	t.ipv6test(false, "1:2:3::4:5:6:7:8:9")

	t.ipv6test(true, "1111:2222:3333:4444:5555:6666:7777:8888")
	t.ipv6test(true, "1111:2222:3333:4444:5555:6666:7777::")
	t.ipv6test(true, "1111:2222:3333:4444:5555:6666::")
	t.ipv6test(true, "1111:2222:3333:4444:5555::")
	t.ipv6test(true, "1111:2222:3333:4444::")
	t.ipv6test(true, "1111:2222:3333::")
	t.ipv6test(true, "1111:2222::")
	t.ipv6test(true, "1111::")
	t.ipv6test(true, "1111:2222:3333:4444:5555:6666::8888")
	t.ipv6test(true, "1111:2222:3333:4444:5555::8888")
	t.ipv6test(true, "1111:2222:3333:4444::8888")
	t.ipv6test(true, "1111:2222:3333::8888")
	t.ipv6test(true, "1111:2222::8888")
	t.ipv6test(true, "1111::8888")
	t.ipv6test(true, "::8888")
	t.ipv6test(true, "1111:2222:3333:4444:5555::7777:8888")
	t.ipv6test(true, "1111:2222:3333:4444::7777:8888")
	t.ipv6test(true, "1111:2222:3333::7777:8888")
	t.ipv6test(true, "1111:2222::7777:8888")
	t.ipv6test(true, "1111::7777:8888")
	t.ipv6test(true, "::7777:8888")
	t.ipv6test(true, "1111:2222:3333:4444::6666:7777:8888")
	t.ipv6test(true, "1111:2222:3333::6666:7777:8888")
	t.ipv6test(true, "1111:2222::6666:7777:8888")
	t.ipv6test(true, "1111::6666:7777:8888")
	t.ipv6test(true, "::6666:7777:8888")
	t.ipv6test(true, "1111:2222:3333::5555:6666:7777:8888")
	t.ipv6test(true, "1111:2222::5555:6666:7777:8888")
	t.ipv6test(true, "1111::5555:6666:7777:8888")
	t.ipv6test(true, "::5555:6666:7777:8888")
	t.ipv6test(true, "1111:2222::4444:5555:6666:7777:8888")
	t.ipv6test(true, "1111::4444:5555:6666:7777:8888")
	t.ipv6test(true, "::4444:5555:6666:7777:8888")
	t.ipv6test(true, "1111::3333:4444:5555:6666:7777:8888")
	t.ipv6test(true, "::3333:4444:5555:6666:7777:8888")
	t.ipv6test(true, "::2222:3333:4444:5555:6666:7777:8888")

	t.ipv6test(true, "1111:2222:3333:4444:5555:6666:123.123.123.123")
	t.ipv6test(true, "1111:2222:3333:4444:5555::123.123.123.123")
	t.ipv6test(true, "1111:2222:3333:4444::123.123.123.123")
	t.ipv6test(true, "1111:2222:3333::123.123.123.123")
	t.ipv6test(true, "1111:2222::123.123.123.123")
	t.ipv6test(true, "1111::123.123.123.123")
	t.ipv6test(true, "::123.123.123.123")
	t.ipv6test(true, "1111:2222:3333:4444::6666:123.123.123.123")
	t.ipv6test(true, "1111:2222:3333::6666:123.123.123.123")
	t.ipv6test(true, "1111:2222::6666:123.123.123.123")
	t.ipv6test(true, "1111::6666:123.123.123.123")
	t.ipv6test(true, "::6666:123.123.123.123")
	t.ipv6test(true, "1111:2222:3333::5555:6666:123.123.123.123")
	t.ipv6test(true, "1111:2222::5555:6666:123.123.123.123")
	t.ipv6test(true, "1111::5555:6666:123.123.123.123")
	t.ipv6test(true, "::5555:6666:123.123.123.123")
	t.ipv6test(true, "1111:2222::4444:5555:6666:123.123.123.123")
	t.ipv6test(true, "1111::4444:5555:6666:123.123.123.123")
	t.ipv6test(true, "::4444:5555:6666:123.123.123.123")
	t.ipv6test(true, "1111::3333:4444:5555:6666:123.123.123.123")
	t.ipv6test(true, "::2222:3333:4444:5555:6666:123.123.123.123")

	t.ipv6test(false, "1::2:3:4:5:6:1.2.3.4")

	t.ipv6zerotest(true, "::")
	t.ipv6zerotest(true, "0:0:0:0:0:0:0:0")

	// Playing with combinations of "0" and "::"
	// NB: these are all sytactically correct, but are bad form
	//   because "0" adjacent to "::" should be combined into "::"
	t.ipv6zerotest(true, "::0:0:0:0:0:0:0")
	t.ipv6zerotest(true, "::0:0:0:0:0:0")
	t.ipv6zerotest(true, "::0:0:0:0:0")
	t.ipv6zerotest(true, "::0:0:0:0")
	t.ipv6zerotest(true, "::0:0:0")
	t.ipv6zerotest(true, "::0:0")
	t.ipv6zerotest(true, "::0")
	t.ipv6zerotest(true, "0:0:0:0:0:0:0::")
	t.ipv6zerotest(true, "0:0:0:0:0:0::")
	t.ipv6zerotest(true, "0:0:0:0:0::")
	t.ipv6zerotest(true, "0:0:0:0::")
	t.ipv6zerotest(true, "0:0:0::")
	t.ipv6zerotest(true, "0:0::")
	t.ipv6zerotest(true, "0::")

	// New invalid from Aeron
	// Invalid data
	t.ipv6test(false, "XXXX:XXXX:XXXX:XXXX:XXXX:XXXX:XXXX:XXXX")

	// Too many components
	t.ipv6test(false, "1111:2222:3333:4444:5555:6666:7777:8888:9999")
	t.ipv6test(false, "1111:2222:3333:4444:5555:6666:7777:8888::")
	t.ipv6test(false, "::2222:3333:4444:5555:6666:7777:8888:9999")

	// Too few components
	t.ipv6test(false, "1111:2222:3333:4444:5555:6666:7777")
	t.ipv6test(false, "1111:2222:3333:4444:5555:6666")
	t.ipv6test(false, "1111:2222:3333:4444:5555")
	t.ipv6test(false, "1111:2222:3333:4444")
	t.ipv6test(false, "1111:2222:3333")
	t.ipv6test(false, "1111:2222")
	t.ipv6test2(false, "1111", false, t.isLenient()) // this is passing the ipv4 side for inet_aton
	//t.ipv6test(false,"1111");

	// Missing :
	t.ipv6test(false, "11112222:3333:4444:5555:6666:7777:8888")
	t.ipv6test(false, "1111:22223333:4444:5555:6666:7777:8888")
	t.ipv6test(false, "1111:2222:33334444:5555:6666:7777:8888")
	t.ipv6test(false, "1111:2222:3333:44445555:6666:7777:8888")
	t.ipv6test(false, "1111:2222:3333:4444:55556666:7777:8888")
	t.ipv6test(false, "1111:2222:3333:4444:5555:66667777:8888")
	t.ipv6test(false, "1111:2222:3333:4444:5555:6666:77778888")

	// Missing : intended for ::
	t.ipv6test(false, "1111:2222:3333:4444:5555:6666:7777:8888:")
	t.ipv6test(false, "1111:2222:3333:4444:5555:6666:7777:")
	t.ipv6test(false, "1111:2222:3333:4444:5555:6666:")
	t.ipv6test(false, "1111:2222:3333:4444:5555:")
	t.ipv6test(false, "1111:2222:3333:4444:")
	t.ipv6test(false, "1111:2222:3333:")
	t.ipv6test(false, "1111:2222:")
	t.ipv6test(false, "1111:")
	t.ipv6test(false, ":")
	t.ipv6test(false, ":8888")
	t.ipv6test(false, ":7777:8888")
	t.ipv6test(false, ":6666:7777:8888")
	t.ipv6test(false, ":5555:6666:7777:8888")
	t.ipv6test(false, ":4444:5555:6666:7777:8888")
	t.ipv6test(false, ":3333:4444:5555:6666:7777:8888")
	t.ipv6test(false, ":2222:3333:4444:5555:6666:7777:8888")
	t.ipv6test(false, ":1111:2222:3333:4444:5555:6666:7777:8888")

	// :::
	t.ipv6test(false, ":::2222:3333:4444:5555:6666:7777:8888")
	t.ipv6test(false, "1111:::3333:4444:5555:6666:7777:8888")
	t.ipv6test(false, "1111:2222:::4444:5555:6666:7777:8888")
	t.ipv6test(false, "1111:2222:3333:::5555:6666:7777:8888")
	t.ipv6test(false, "1111:2222:3333:4444:::6666:7777:8888")
	t.ipv6test(false, "1111:2222:3333:4444:5555:::7777:8888")
	t.ipv6test(false, "1111:2222:3333:4444:5555:6666:::8888")
	t.ipv6test(false, "1111:2222:3333:4444:5555:6666:7777:::")

	// Double ::");
	t.ipv6test(false, "::2222::4444:5555:6666:7777:8888")
	t.ipv6test(false, "::2222:3333::5555:6666:7777:8888")
	t.ipv6test(false, "::2222:3333:4444::6666:7777:8888")
	t.ipv6test(false, "::2222:3333:4444:5555::7777:8888")
	t.ipv6test(false, "::2222:3333:4444:5555:7777::8888")
	t.ipv6test(false, "::2222:3333:4444:5555:7777:8888::")

	t.ipv6test(false, "1111::3333::5555:6666:7777:8888")
	t.ipv6test(false, "1111::3333:4444::6666:7777:8888")
	t.ipv6test(false, "1111::3333:4444:5555::7777:8888")
	t.ipv6test(false, "1111::3333:4444:5555:6666::8888")
	t.ipv6test(false, "1111::3333:4444:5555:6666:7777::")

	t.ipv6test(false, "1111:2222::4444::6666:7777:8888")
	t.ipv6test(false, "1111:2222::4444:5555::7777:8888")
	t.ipv6test(false, "1111:2222::4444:5555:6666::8888")
	t.ipv6test(false, "1111:2222::4444:5555:6666:7777::")

	t.ipv6test(false, "1111:2222:3333::5555::7777:8888")
	t.ipv6test(false, "1111:2222:3333::5555:6666::8888")
	t.ipv6test(false, "1111:2222:3333::5555:6666:7777::")

	t.ipv6test(false, "1111:2222:3333:4444::6666::8888")
	t.ipv6test(false, "1111:2222:3333:4444::6666:7777::")

	t.ipv6test(false, "1111:2222:3333:4444:5555::7777::")

	// Too many components"
	t.ipv6test(false, "1111:2222:3333:4444:5555:6666:7777:8888:1.2.3.4")
	t.ipv6test(false, "1111:2222:3333:4444:5555:6666:7777:1.2.3.4")
	t.ipv6test(false, "1111:2222:3333:4444:5555:6666::1.2.3.4")
	t.ipv6test(false, "::2222:3333:4444:5555:6666:7777:1.2.3.4")
	t.ipv6test(false, "1111:2222:3333:4444:5555:6666:1.2.3.4.5")

	// Too few components
	t.ipv6test(false, "1111:2222:3333:4444:5555:1.2.3.4")
	t.ipv6test(false, "1111:2222:3333:4444:1.2.3.4")
	t.ipv6test(false, "1111:2222:3333:1.2.3.4")
	t.ipv6test(false, "1111:2222:1.2.3.4")
	t.ipv6test(false, "1111:1.2.3.4")
	t.ipv6testOnly(false, "1.2.3.4")

	// Missing :
	t.ipv6test(false, "11112222:3333:4444:5555:6666:1.2.3.4")
	t.ipv6test(false, "1111:22223333:4444:5555:6666:1.2.3.4")
	t.ipv6test(false, "1111:2222:33334444:5555:6666:1.2.3.4")
	t.ipv6test(false, "1111:2222:3333:44445555:6666:1.2.3.4")
	t.ipv6test(false, "1111:2222:3333:4444:55556666:1.2.3.4")
	t.ipv6test(false, "1111:2222:3333:4444:5555:66661.2.3.4")

	// Missing .
	t.ipv6test(false, "1111:2222:3333:4444:5555:6666:255255.255.255")
	t.ipv6test(false, "1111:2222:3333:4444:5555:6666:255.255255.255")
	t.ipv6test(false, "1111:2222:3333:4444:5555:6666:255.255.255255")

	// Missing : intended for ::
	t.ipv6test(false, ":1.2.3.4")
	t.ipv6test(false, ":6666:1.2.3.4")
	t.ipv6test(false, ":5555:6666:1.2.3.4")
	t.ipv6test(false, ":4444:5555:6666:1.2.3.4")
	t.ipv6test(false, ":3333:4444:5555:6666:1.2.3.4")
	t.ipv6test(false, ":2222:3333:4444:5555:6666:1.2.3.4")
	t.ipv6test(false, ":1111:2222:3333:4444:5555:6666:1.2.3.4")

	// :::
	t.ipv6test(false, ":::2222:3333:4444:5555:6666:1.2.3.4")
	t.ipv6test(false, "1111:::3333:4444:5555:6666:1.2.3.4")
	t.ipv6test(false, "1111:2222:::4444:5555:6666:1.2.3.4")
	t.ipv6test(false, "1111:2222:3333:::5555:6666:1.2.3.4")
	t.ipv6test(false, "1111:2222:3333:4444:::6666:1.2.3.4")
	t.ipv6test(false, "1111:2222:3333:4444:5555:::1.2.3.4")

	// Double ::
	t.ipv6test(false, "::2222::4444:5555:6666:1.2.3.4")
	t.ipv6test(false, "::2222:3333::5555:6666:1.2.3.4")
	t.ipv6test(false, "::2222:3333:4444::6666:1.2.3.4")
	t.ipv6test(false, "::2222:3333:4444:5555::1.2.3.4")

	t.ipv6test(false, "1111::3333::5555:6666:1.2.3.4")
	t.ipv6test(false, "1111::3333:4444::6666:1.2.3.4")
	t.ipv6test(false, "1111::3333:4444:5555::1.2.3.4")

	t.ipv6test(false, "1111:2222::4444::6666:1.2.3.4")
	t.ipv6test(false, "1111:2222::4444:5555::1.2.3.4")

	t.ipv6test(false, "1111:2222:3333::5555::1.2.3.4")

	// Missing parts
	t.ipv6test(false, "::.")
	t.ipv6test(false, "::..")
	t.ipv6test(false, "::...")
	t.ipv6test(false, "::1...")
	t.ipv6test(false, "::1.2..")
	t.ipv6test(false, "::1.2.3.")
	t.ipv6test(false, "::.2..")
	t.ipv6test(false, "::.2.3.")
	t.ipv6test(false, "::.2.3.4")
	t.ipv6test(false, "::..3.")
	t.ipv6test(false, "::..3.4")
	t.ipv6test(false, "::...4")

	// Extra : in front
	t.ipv6test(false, ":1111:2222:3333:4444:5555:6666:7777::")
	t.ipv6test(false, ":1111:2222:3333:4444:5555:6666::")
	t.ipv6test(false, ":1111:2222:3333:4444:5555::")
	t.ipv6test(false, ":1111:2222:3333:4444::")
	t.ipv6test(false, ":1111:2222:3333::")
	t.ipv6test(false, ":1111:2222::")
	t.ipv6test(false, ":1111::")
	t.ipv6test(false, ":::")
	t.ipv6test(false, ":1111:2222:3333:4444:5555:6666::8888")
	t.ipv6test(false, ":1111:2222:3333:4444:5555::8888")
	t.ipv6test(false, ":1111:2222:3333:4444::8888")
	t.ipv6test(false, ":1111:2222:3333::8888")
	t.ipv6test(false, ":1111:2222::8888")
	t.ipv6test(false, ":1111::8888")
	t.ipv6test(false, ":::8888")
	t.ipv6test(false, ":1111:2222:3333:4444:5555::7777:8888")
	t.ipv6test(false, ":1111:2222:3333:4444::7777:8888")
	t.ipv6test(false, ":1111:2222:3333::7777:8888")
	t.ipv6test(false, ":1111:2222::7777:8888")
	t.ipv6test(false, ":1111::7777:8888")
	t.ipv6test(false, ":::7777:8888")
	t.ipv6test(false, ":1111:2222:3333:4444::6666:7777:8888")
	t.ipv6test(false, ":1111:2222:3333::6666:7777:8888")
	t.ipv6test(false, ":1111:2222::6666:7777:8888")
	t.ipv6test(false, ":1111::6666:7777:8888")
	t.ipv6test(false, ":::6666:7777:8888")
	t.ipv6test(false, ":1111:2222:3333::5555:6666:7777:8888")
	t.ipv6test(false, ":1111:2222::5555:6666:7777:8888")
	t.ipv6test(false, ":1111::5555:6666:7777:8888")
	t.ipv6test(false, ":::5555:6666:7777:8888")
	t.ipv6test(false, ":1111:2222::4444:5555:6666:7777:8888")
	t.ipv6test(false, ":1111::4444:5555:6666:7777:8888")
	t.ipv6test(false, ":::4444:5555:6666:7777:8888")
	t.ipv6test(false, ":1111::3333:4444:5555:6666:7777:8888")
	t.ipv6test(false, ":::3333:4444:5555:6666:7777:8888")
	t.ipv6test(false, ":::2222:3333:4444:5555:6666:7777:8888")

	t.ipv6test(false, ":1111:2222:3333:4444:5555:6666:1.2.3.4")
	t.ipv6test(false, ":1111:2222:3333:4444:5555::1.2.3.4")
	t.ipv6test(false, ":1111:2222:3333:4444::1.2.3.4")
	t.ipv6test(false, ":1111:2222:3333::1.2.3.4")
	t.ipv6test(false, ":1111:2222::1.2.3.4")
	t.ipv6test(false, ":1111::1.2.3.4")
	t.ipv6test(false, ":::1.2.3.4")
	t.ipv6test(false, ":1111:2222:3333:4444::6666:1.2.3.4")
	t.ipv6test(false, ":1111:2222:3333::6666:1.2.3.4")
	t.ipv6test(false, ":1111:2222::6666:1.2.3.4")
	t.ipv6test(false, ":1111::6666:1.2.3.4")
	t.ipv6test(false, ":::6666:1.2.3.4")
	t.ipv6test(false, ":1111:2222:3333::5555:6666:1.2.3.4")
	t.ipv6test(false, ":1111:2222::5555:6666:1.2.3.4")
	t.ipv6test(false, ":1111::5555:6666:1.2.3.4")
	t.ipv6test(false, ":::5555:6666:1.2.3.4")
	t.ipv6test(false, ":1111:2222::4444:5555:6666:1.2.3.4")
	t.ipv6test(false, ":1111::4444:5555:6666:1.2.3.4")
	t.ipv6test(false, ":::4444:5555:6666:1.2.3.4")
	t.ipv6test(false, ":1111::3333:4444:5555:6666:1.2.3.4")
	t.ipv6test(false, ":::2222:3333:4444:5555:6666:1.2.3.4")

	// Extra : at end
	t.ipv6test(false, "1111:2222:3333:4444:5555:6666:7777:::")
	t.ipv6test(false, "1111:2222:3333:4444:5555:6666:::")
	t.ipv6test(false, "1111:2222:3333:4444:5555:::")
	t.ipv6test(false, "1111:2222:3333:4444:::")
	t.ipv6test(false, "1111:2222:3333:::")
	t.ipv6test(false, "1111:2222:::")
	t.ipv6test(false, "1111:::")
	t.ipv6test(false, ":::")
	t.ipv6test(false, "1111:2222:3333:4444:5555:6666::8888:")
	t.ipv6test(false, "1111:2222:3333:4444:5555::8888:")
	t.ipv6test(false, "1111:2222:3333:4444::8888:")
	t.ipv6test(false, "1111:2222:3333::8888:")
	t.ipv6test(false, "1111:2222::8888:")
	t.ipv6test(false, "1111::8888:")
	t.ipv6test(false, "::8888:")
	t.ipv6test(false, "1111:2222:3333:4444:5555::7777:8888:")
	t.ipv6test(false, "1111:2222:3333:4444::7777:8888:")
	t.ipv6test(false, "1111:2222:3333::7777:8888:")
	t.ipv6test(false, "1111:2222::7777:8888:")
	t.ipv6test(false, "1111::7777:8888:")
	t.ipv6test(false, "::7777:8888:")
	t.ipv6test(false, "1111:2222:3333:4444::6666:7777:8888:")
	t.ipv6test(false, "1111:2222:3333::6666:7777:8888:")
	t.ipv6test(false, "1111:2222::6666:7777:8888:")
	t.ipv6test(false, "1111::6666:7777:8888:")
	t.ipv6test(false, "::6666:7777:8888:")
	t.ipv6test(false, "1111:2222:3333::5555:6666:7777:8888:")
	t.ipv6test(false, "1111:2222::5555:6666:7777:8888:")
	t.ipv6test(false, "1111::5555:6666:7777:8888:")
	t.ipv6test(false, "::5555:6666:7777:8888:")
	t.ipv6test(false, "1111:2222::4444:5555:6666:7777:8888:")
	t.ipv6test(false, "1111::4444:5555:6666:7777:8888:")
	t.ipv6test(false, "::4444:5555:6666:7777:8888:")
	t.ipv6test(false, "1111::3333:4444:5555:6666:7777:8888:")
	t.ipv6test(false, "::3333:4444:5555:6666:7777:8888:")
	t.ipv6test(false, "::2222:3333:4444:5555:6666:7777:8888:")

	// Additional cases: http://crisp.tweakblogs.net/blog/2031/ipv6-validation-%28and-caveats%29.html
	t.ipv6test(true, "0:a:b:c:d:e:f::")
	t.ipv6test(true, "::0:a:b:c:d:e:f") // syntactically correct, but bad form (::0:... could be combined)
	t.ipv6test(true, "a:b:c:d:e:f:0::")
	t.ipv6test(false, "':10.0.0.1")

	t.testCIDRSubnets("9.129.237.26/32", "9.129.237.26/32")
	t.testCIDRSubnets("ffff::ffff/128", "ffff:0:0:0:0:0:0:ffff/128")

	t.testMasksAndPrefixes()

	t.testContains("0.0.0.0/0", "1.2.3.4", false)
	t.testContains("0.0.0.0/1", "127.2.3.4", false)
	t.testNotContains("0.0.0.0/1", "128.2.3.4")
	t.testContains("0.0.0.0/4", "15.2.3.4", false)
	t.testContains("0.0.0.0/4", "9.129.0.0/16", false)
	t.testContains("8.0.0.0/5", "15.2.3.4", false)
	t.testContains("8.0.0.0/7", "9.2.3.4", false)
	t.testContains("9.0.0.0/8", "9.2.3.4", false)
	t.testContains("9.128.0.0/9", "9.255.3.4", false)
	t.testContains("9.128.0.0/15", "9.128.3.4", false)
	t.testNotContains("9.128.0.0/15", "10.128.3.4")
	t.testContains("9.129.0.0/16", "9.129.3.4", false)
	t.testContains("9.129.237.24/30", "9.129.237.27", false)
	t.testContains("9.129.237.24/30", "9.129.237.26/31", false)

	t.testContains("9.129.237.26/32", "9.129.237.26", true)
	t.testNotContains("9.129.237.26/32", "9.128.237.26")

	t.testContains("0.0.0.0/0", "0.0.0.0/0", true)
	t.testContains("0.0.0.0/1", "0.0.0.0/1", true)
	t.testContains("0.0.0.0/4", "0.0.0.0/4", true)
	t.testContains("8.0.0.0/5", "8.0.0.0/5", true)
	t.testContains("8.0.0.0/7", "8.0.0.0/7", true)
	t.testContains("9.0.0.0/8", "9.0.0.0/8", true)
	t.testContains("9.128.0.0/9", "9.128.0.0/9", true)
	t.testContains("9.128.0.0/15", "9.128.0.0/15", true)
	t.testContains("9.129.0.0/16", "9.129.0.0/16", true)
	t.testContains("9.129.237.24/30", "9.129.237.24/30", true)
	t.testContains("9.129.237.26/32", "9.129.237.26/32", true)

	t.testContains("::ffff:1.2.3.4", "1.2.3.4", true) //ipv4 mapped

	t.testContains("::ffff:1.2.0.0/112", "1.2.3.4", false)
	t.testContains("::ffff:1.2.0.0/112", "1.2.0.0/16", true)

	t.testContains("0:0:0:0:0:0:0:0/0", "a:b:c:d:e:f:a:b", false)
	t.testContains("8000:0:0:0:0:0:0:0/1", "8aaa:b:c:d:e:f:a:b", false)
	t.testNotContains("8000:0:0:0:0:0:0:0/1", "aaa:b:c:d:e:f:a:b")
	t.testContains("ffff:0:0:0:0:0:0:0/30", "ffff:3:c:d:e:f:a:b", false)
	t.testNotContains("ffff:0:0:0:0:0:0:0/30", "ffff:4:c:d:e:f:a:b")
	t.testContains("ffff:0:0:0:0:0:0:0/32", "ffff:0:ffff:d:e:f:a:b", false)
	t.testNotContains("ffff:0:0:0:0:0:0:0/32", "ffff:1:ffff:d:e:f:a:b")
	t.testContains("ffff:0:0:0:0:0:0:fffc/126", "ffff:0:0:0:0:0:0:ffff", false)
	t.testContains("ffff:0:0:0:0:0:0:ffff/128", "ffff:0:0:0:0:0:0:ffff", true)

	t.testContains("::/0", "0:0:0:0:0:0:0:0/0", true)
	t.testContains("8000::/1", "8000:0:0:0:0:0:0:0/1", true)
	t.testContains("ffff::/30", "ffff:0:0:0:0:0:0:0/30", true)
	t.testContains("ffff::/32", "ffff:0:0:0:0:0:0:0/32", true)
	t.testContains("ffff::fffc/126", "ffff:0:0:0:0:0:0:fffc/126", true)
	t.testContains("ffff::ffff/128", "ffff:0:0:0:0:0:0:ffff/128", true)

	t.testContains("2001:db8::/120", "2001:db8::1", false)

	t.testContains("2001:db8::1/120", "2001:db8::1", !false)

	t.testNotContains("2001:db8::1/120", "2001:db8::")

	t.testContains("2001:db8::/112", "2001:db8::", !true)
	t.testContains("2001:db8::/111", "2001:db8::", !true)
	t.testContains("2001:db8::/113", "2001:db8::", !true)
	t.testNotContains("2001:db80::/113", "2001:db8::")
	t.testNotContains("2001:db0::/113", "2001:db8::")
	t.testNotContains("2001:db7::/113", "2001:db8::")

	t.testContains("2001:0db8:85a3:0000:0000:8a2e:0370:7334/120", "2001:0db8:85a3:0000:0000:8a2e:0370:7334/128", !false)
	t.testContains("2001:0db8:85a3::8a2e:0370:7334/120", "2001:0db8:85a3:0000:0000:8a2e:0370:7334/128", !false)
	t.testContains("2001:0db8:85a3:0000:0000:8a2e:0370:7334/120", "2001:0db8:85a3::8a2e:0370:7334/128", !false)
	t.testContains("2001:0db8:85a3::8a2e:0370:7334/120", "2001:0db8:85a3::8a2e:0370:7334/128", !false)

	t.testContains("2001:0db8:85a3:0000:0000:8a2e:0370::/120", "2001:0db8:85a3:0000:0000:8a2e:0370::/128", !true)
	t.testContains("2001:0db8:85a3:0000:0000:8a2e:0370::/120", "2001:0db8:85a3::8a2e:0370:0/128", !true)
	t.testContains("2001:0db8:85a3::8a2e:0370:0/120", "2001:0db8:85a3:0000:0000:8a2e:0370::/128", !true)
	t.testContains("2001:0db8:85a3::8a2e:0370:0/120", "2001:0db8:85a3::8a2e:0370:0/128", !true)

	t.testNotContains("12::/4", "123::")
	t.testNotContains("12::/4", "1234::")
	t.testNotContains("12::/8", "123::")
	t.testNotContains("123::/8", "1234::")
	t.testNotContains("12::/12", "123::")
	t.testNotContains("12::/16", "123::")
	t.testNotContains("12::/24", "123::")

	t.testNotContains("1:12::/20", "1:123::")

	t.testNotContains("1:12::/20", "1:1234::")
	t.testNotContains("1:12::/24", "1:123::")
	t.testNotContains("1:123::/24", "1:1234::")
	t.testNotContains("1:12::/28", "1:123::")
	t.testNotContains("1:12::/32", "1:123::")
	t.testNotContains("1:12::/40", "1:123::")

	t.testNotContainsNoReverse("1.0.0.0/16", "1.0.0.0/8", true)
	t.testContains("::/4", "123::", false)

	t.testNotContains("::/4", "1234::")
	t.testNotContains("::/8", "123::")
	t.testNotContains("100::/8", "1234::")
	t.testNotContains("10::/12", "123::")
	t.testNotContains("10::/16", "123::")
	t.testNotContains("10::/24", "123::")

	t.testNotContains("1:12::/20", "1:123::")

	t.testNotContains("1::/20", "1:1234::")
	t.testNotContains("1::/24", "1:123::")
	t.testNotContains("1:100::/24", "1:1234::")
	t.testNotContains("1:10::/28", "1:123::")
	t.testNotContains("1:10::/32", "1:123::")
	t.testNotContains("1:10::/40", "1:123::")

	t.testContains("1.0.0.0/16", "1.0.0.0/24", !true)

	t.testContains("5.62.62.0/23", "5.62.63.1", false)

	t.testNotContains("5.62.62.0/23", "5.62.64.1")
	t.testNotContains("5.62.62.0/23", "5.62.68.1")
	t.testNotContains("5.62.62.0/23", "5.62.78.1")
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
					if h1.GetNetworkPrefixLen() != nil {
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
				//	boolean false = prefixConfiguration.allPrefixedAddressesAreSubnets();
				//	//if two are not equal, they can still have equal prefix.  Only if host the same can we conclude otherwise.
				//	//So here we first check that host is the same (ie full range host)
				//	if(false && h2.getNetworkPrefixLength() != null && h1.getNetworkPrefixLength() != null && h1.getNetworkPrefixLength() >= h2.getNetworkPrefixLength()) {
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

func (t ipAddressTester) ipv4_inet_aton_test(pass bool, x string) {
	addr := t.createInetAtonAddress(x)
	t.iptest(pass, addr, false, false, true)
}

func (t ipAddressTester) ipv4test(pass bool, x string) {
	addr := t.createAddress(x)
	t.iptest(pass, addr, false, false, true)
}

func (t ipAddressTester) ipv4test2(pass bool, x string, isZero, notBothTheSame bool) {
	addr := t.createAddress(x)
	t.iptest(pass, addr, isZero, notBothTheSame, true)
}

func (t ipAddressTester) ipv4testOnly(pass bool, x string) {
	addr := t.createAddress(x)
	t.iptest(pass, addr, false, true, true)
}

func (t ipAddressTester) ipv4zerotest(pass bool, x string) {
	addr := t.createAddress(x)
	t.iptest(pass, addr, true, false, true)
}

func (t ipAddressTester) ipv6test(pass bool, x string) {
	addr := t.createAddress(x)
	t.iptest(pass, addr, false, false, false)
}

func (t ipAddressTester) ipv6test2(pass bool, x string, isZero, notBothTheSame bool) {
	addr := t.createAddress(x)
	t.iptest(pass, addr, isZero, notBothTheSame, false)
}

func (t ipAddressTester) ipv6testOnly(pass bool, x string) {
	addr := t.createAddress(x)
	t.iptest(pass, addr, false, true, false)
}

func (t ipAddressTester) ipv6zerotest(pass bool, x string) {
	addr := t.createAddress(x)
	t.iptest(pass, addr, true, false, false)
}

func (t ipAddressTester) iptest(pass bool, addr *ipaddr.IPAddressString, isZero, notBothTheSame, ipv4Test bool) bool {
	failed := false
	var pass2 bool
	if notBothTheSame {
		pass2 = !pass
	} else {
		pass2 = pass
	}

	//notBoth means we validate as IPv4 or as IPv6, we don't validate as either one
	//try {
	if t.isNotExpected(pass, addr, ipv4Test, !ipv4Test) || t.isNotExpected(pass2, addr, false, false) {
		failed = true
		if addr.GetAddress() != nil {
			t.addFailure(newFailure("parse failure for "+addr.String()+" parsed to "+addr.GetAddress().String(), addr))
		} else {
			t.addFailure(newFailure("parse failure for "+addr.String(), addr))
		}
		////this part just for debugging
		if t.isNotExpected(pass, addr, ipv4Test, !ipv4Test) {
			t.isNotExpected(pass, addr, ipv4Test, !ipv4Test)
		} else {
			t.isNotExpected(pass2, addr, false, false)
		}
	} else {
		var zeroPass bool
		if notBothTheSame {
			zeroPass = !isZero
		} else {
			zeroPass = pass && !isZero
		}
		if t.isNotExpectedNonZero(zeroPass, addr) {
			failed = true
			t.addFailure(newFailure("zero parse failure", addr))

			//this part just for debugging
			//boolean val = isNotExpectedNonZero(zeroPass, addr);
			t.isNotExpectedNonZero(zeroPass, addr)
		} else {
			//test the bytes
			if pass && len(addr.String()) > 0 && addr.GetAddress() != nil && !(addr.GetAddress().IsIPv6() && addr.GetAddress().ToIPv6Address().HasZone()) && !addr.IsPrefixed() { //only for valid addresses
				address := addr.GetAddress()

				failed = !t.testBytes(address)

			}
		}
	}
	//} catch(IncompatibleAddressException e) {
	//	failed = true;
	//	addFailure(new Failure(e.toString(), addr));
	//} catch(RuntimeException e) {
	//	failed = true;
	//	addFailure(new Failure(e.toString(), addr));
	//}
	t.incrementTestCount()
	return !failed
}

//boolean isNotExpected(boolean expectedPass, IPAddressString addr) {
//	return isNotExpected(expectedPass, addr, false, false);
//}

func (t ipAddressTester) isNotExpected(expectedPass bool, addr *ipaddr.IPAddressString, isIPv4, isIPv6 bool) bool {
	//try {
	var err error
	if isIPv4 {
		err = addr.ValidateIPv4()
		if err == nil {
			_, err = addr.ToVersionedAddress(ipaddr.IPv4)
		}
	} else if isIPv6 {
		err = addr.ValidateIPv6()
		if err == nil {
			_, err = addr.ToVersionedAddress(ipaddr.IPv6)
		}
	} else {
		err = addr.Validate()
	}
	if err != nil {
		return expectedPass
	}
	return !expectedPass
	//} catch(AddressStringException e) {
	//	return expectedPass;
	//}
}

func (t ipAddressTester) isNotExpectedNonZero(expectedPass bool, addr *ipaddr.IPAddressString) bool {
	if !addr.IsValid() && !addr.IsAllAddresses() {
		//	//if(!addr.isIPAddress() && !addr.isPrefixOnly() && !addr.isAllAddresses()) {
		return expectedPass
	}
	//if expectedPass is true, we are expecting a non-zero address
	//return true to indicate we have gotten something not expected
	if addr.GetAddress() != nil && addr.GetAddress().IsZero() {
		return expectedPass
	}
	return !expectedPass
}

func (t ipAddressTester) testBytes(addr *ipaddr.IPAddress) bool {
	failed := false
	//try {

	if t.allowsRange() && addr.IsMultiple() {
		b := addr.GetBytes()
		b2 := addr.GetLower().GetBytes()
		if !bytes.Equal(b, b2) {
			t.addFailure(newIPAddrFailure("bytes on addr "+addr.String(), addr.ToIPAddress()))
			failed = true
		}
		return !failed
	}
	addrString := addr.String()
	index := strings.Index(addrString, "/")
	//int index = addrString.indexOf('/');
	if index >= 0 {
		addrString = addrString[:index]
		//addrString = addrString.substring(0, index);
	}
	inetAddress := net.ParseIP(addrString)
	if addr.IsIPv4() {
		inetAddress = inetAddress.To4()
	}
	//InetAddress inetAddress = InetAddress.getByName(addrString);
	//byte[] b = inetAddress.getAddress();
	b2 := addr.GetBytes()
	if !bytes.Equal(inetAddress, b2) {
		//if(!Arrays.equals(b, b2)) {
		var b3 []byte
		if addr.IsIPv4() {
			b3 = addr.GetSection().GetBytes()
			//inetAddress = inetAddress.To4()
		} else {
			addr, err := addr.ToIPv6Address().GetEmbeddedIPv4Address()
			if err != nil {
				//failed = true;
				t.addFailure(newIPAddrFailure("bytes on addr "+inetAddress.String(), addr.ToIPAddress()))
				return false
			}
			b3 = addr.GetBytes()
		}
		//byte[] b3 = addr.isIPv4() ? addr.getSection().getBytes() : addr.toIPv6().toMappedIPv4Segments().getBytes();
		if !bytes.Equal(inetAddress, b3) {
			//if(!Arrays.equals(b, b3)) {
			failed = true
			t.addFailure(newIPAddrFailure("bytes on addr "+inetAddress.String(), addr))
		}
	}
	//}
	//} catch(UnknownHostException e) {
	//failed = true;
	//addFailure(new Failure("bytes on addr " + e, addr));
	//}
	return !failed
}

func (t ipAddressTester) testMaskBytes(cidr2 string, w2 *ipaddr.IPAddressString) {

	if t.allowsRange() {
		t.testBytes(w2.GetAddress())
		return
	}

	index := strings.Index(cidr2, "/")
	if index < 0 {
		index = len(cidr2)
	}
	w3 := t.createAddress(cidr2[:index])
	//try {
	inetAddress := net.ParseIP(w3.String())
	if w3.IsIPv4() {
		inetAddress = inetAddress.To4()
	}
	//InetAddress inetAddress = null;
	//inetAddress = InetAddress.getByName(w3.toString());//no wildcards allowed here
	//byte[] b = inetAddress.getAddress();
	b2 := w3.GetAddress().GetBytes()
	if !bytes.Equal(inetAddress, b2) {
		//if(!Arrays.equals(b, b2)) {
		t.addFailure(newFailure("bytes on addr "+inetAddress.String(), w3))
	} else {
		b3 := w2.GetAddress().GetBytes()
		if !bytes.Equal(b3, b2) {
			//if(!Arrays.equals(b3, b2)) {
			t.addFailure(newFailure("bytes on addr "+w3.String(), w2))
		}
	}
	//} catch(UnknownHostException e) {
	//	addFailure(new Failure("bytes on addr " + w3, w3));
	//}
}

func (t ipAddressTester) testCIDRSubnets(cidr1, normalizedString string) {
	w := t.createAddress(cidr1)
	w2 := t.createAddress(normalizedString)
	//try {
	first := w.Equals(w2)
	v, err := w.ToAddress()
	v2, err2 := w2.ToAddress()
	if err != nil || err2 != nil {
		t.addFailure(newFailure("testCIDRSubnets addresses "+w.String()+", "+w2.String()+": "+err.Error()+", "+err2.Error(), w2))
	}
	second := v.Equals(v2)
	if !first || !second {
		t.addFailure(newFailure("failed "+w2.String(), w))
	} else {
		str := v2.ToNormalizedString()
		if normalizedString != (str) {
			t.addFailure(newFailure("failed "+str, w2))
		} else {
			t.testMaskBytes(normalizedString, w2)
		}
	}
	//} catch(AddressStringException e) {
	//	addFailure(new Failure("failed " + w2, w));
	//}
	t.incrementTestCount()
}

func (t ipAddressTester) testMasksAndPrefixes() {
	sampleIpv6 := t.createAddress("1234:abcd:cdef:5678:9abc:def0:1234:5678").GetAddress().ToIPv6Address()
	sampleIpv4 := t.createAddress("123.156.178.201").GetAddress().ToIPv4Address()

	ipv6Network := ipaddr.DefaultIPv6Network
	//IPv6AddressNetwork ipv6Network = ADDRESS_OPTIONS.getIPv6Parameters().getNetwork();
	ipv6SampleNetMask := sampleIpv6.GetNetworkMask()
	ipv6SampleHostMask := sampleIpv6.GetHostMask()
	onesNetworkMask := ipv6Network.GetNetworkMask(ipaddr.IPv6BitCount)
	onesHostMask := ipv6Network.GetHostMask(0)
	if !ipv6SampleNetMask.Equals(onesNetworkMask) {
		t.addFailure(newIPAddrFailure("mask mismatch between address "+ipv6SampleNetMask.String()+" and network "+onesNetworkMask.String(), sampleIpv6.ToIPAddress()))
	}
	if !ipv6SampleHostMask.Equals(onesHostMask) {
		t.addFailure(newIPAddrFailure("mask mismatch between address "+ipv6SampleHostMask.String()+" and network "+onesHostMask.String(), sampleIpv6.ToIPAddress()))
	}

	//IPv4AddressNetwork ipv4Network = ADDRESS_OPTIONS.getIPv4Parameters().getNetwork();
	ipv4Network := ipaddr.DefaultIPv4Network
	ipv4SampleNetMask := sampleIpv4.GetNetworkMask()
	ipv4SampleHostMask := sampleIpv4.GetHostMask()
	onesNetworkMaskv4 := ipv4Network.GetNetworkMask(ipaddr.IPv4BitCount)
	onesHostMaskv4 := ipv4Network.GetHostMask(0)
	if !ipv4SampleNetMask.Equals(onesNetworkMaskv4) {
		t.addFailure(newIPAddrFailure("mask mismatch between address "+ipv4SampleNetMask.String()+" and network "+onesNetworkMaskv4.String(), sampleIpv4.ToIPAddress()))
	}
	if !ipv4SampleHostMask.Equals(onesHostMaskv4) {
		t.addFailure(newIPAddrFailure("mask mismatch between address "+ipv4SampleHostMask.String()+" and network "+onesHostMaskv4.String(), sampleIpv4.ToIPAddress()))
	}

	for i := ipaddr.BitCount(0); i <= ipaddr.IPv6BitCount; i++ {
		bits := i
		ipv6HostMask := ipv6Network.GetHostMask(bits)
		if t.checkMask(ipv6HostMask, bits, false, false) {
			ipv6NetworkMask := ipv6Network.GetPrefixedNetworkMask(bits)
			if t.checkMask(ipv6NetworkMask, bits, true, false) {
				samplePrefixedIpv6 := sampleIpv6.SetPrefixLen(bits)
				ipv6NetworkMask2 := samplePrefixedIpv6.GetNetworkMask()
				ipv6HostMask2 := samplePrefixedIpv6.GetHostMask()
				if !ipv6NetworkMask2.Equals(ipv6NetworkMask) {
					t.addFailure(newIPAddrFailure("mask mismatch between address "+ipv6NetworkMask2.String()+" and network "+ipv6NetworkMask.String(), samplePrefixedIpv6.ToIPAddress()))
				}
				if !ipv6HostMask2.Equals(ipv6HostMask) {
					t.addFailure(newIPAddrFailure("mask mismatch between address "+ipv6HostMask2.String()+" and network "+ipv6HostMask.String(), samplePrefixedIpv6.ToIPAddress()))
				}
				if i <= ipaddr.IPv4BitCount {
					ipv4HostMask := ipv4Network.GetHostMask(bits)
					if t.checkMask(ipv4HostMask, bits, false, false) {
						ipv4NetworkMask := ipv4Network.GetPrefixedNetworkMask(bits)
						t.checkMask(ipv4NetworkMask, bits, true, false)

						samplePrefixedIpv4 := sampleIpv4.SetPrefixLen(bits)
						ipv4NetworkMask2 := samplePrefixedIpv4.GetNetworkMask()
						ipv4HostMask2 := samplePrefixedIpv4.GetHostMask()
						if !ipv4NetworkMask2.Equals(ipv4NetworkMask) {
							t.addFailure(newIPAddrFailure("mask mismatch between address "+ipv4NetworkMask2.String()+" and network "+ipv4NetworkMask.String(), samplePrefixedIpv4.ToIPAddress()))
						}
						if !ipv4HostMask2.Equals(ipv4HostMask) {
							t.addFailure(newIPAddrFailure("mask mismatch between address "+ipv4HostMask2.String()+" and network "+ipv4HostMask.String(), samplePrefixedIpv4.ToIPAddress()))
						}
					}
				}
			}
		}
	}
}

//var secondTry bool

func (t ipAddressTester) checkMask(address *ipaddr.IPAddress, prefixBits ipaddr.BitCount, network bool, secondTry bool) bool {
	//fmt.Println("Handling 1 " + address.String())
	//if prefixBits == 65 {
	//	fmt.Println("how do we go back to 64?")
	//}
	maskPrefix := address.GetBlockMaskPrefixLen(network)
	otherMaskPrefix := address.GetBlockMaskPrefixLen(!network)

	// A mask is either network or host, but not both, unless it is all zeros or ones
	// so this ensures that a network mask is or is not a host mask, and vice versa
	var other bool
	if prefixBits == 0 || prefixBits == address.GetBitCount() {
		other = otherMaskPrefix == nil
	} else {
		other = otherMaskPrefix != nil
	}
	if *maskPrefix != min(prefixBits, address.GetBitCount()) || other {
		t.addFailure(newIPAddrFailure("failed mask "+address.String()+" otherMaskPrefix: "+otherMaskPrefix.String(), address))
		return false
	}
	if network {
		addr := address
		if address.IsPrefixBlock() {
			addr = address.GetLower()
		}
		if !addr.IsZeroHostLen(prefixBits) || (addr.IsPrefixed() && !addr.IsZeroHost()) {
			t.addFailure(newIPAddrFailure(addr.String()+" is zero host failure "+strconv.FormatBool(addr.IsZeroHostLen(prefixBits)), address))
			return false
		}
		if prefixBits < address.GetBitCount()-1 && !addr.IsZeroHostLen(prefixBits+1) {
			t.addFailure(newIPAddrFailure(addr.String()+" is zero host failure "+strconv.FormatBool(addr.IsZeroHostLen(prefixBits+1)), address))
			return false
		}
		if prefixBits > 0 && addr.IsZeroHostLen(prefixBits-1) {
			t.addFailure(newIPAddrFailure(addr.String()+" is zero host failure "+strconv.FormatBool(addr.IsZeroHostLen(prefixBits-1)), address))
			return false
		}
	} else {
		if !address.IncludesMaxHostLen(prefixBits) || (address.IsPrefixed() && !address.IncludesMaxHost()) {
			t.addFailure(newIPAddrFailure(address.String()+" is zero host failure "+strconv.FormatBool(address.IncludesMaxHostLen(prefixBits)), address))
			return false
		}
		if prefixBits < address.GetBitCount()-1 && !address.IncludesMaxHostLen(prefixBits+1) {
			t.addFailure(newIPAddrFailure(address.String()+" is max host failure "+strconv.FormatBool(address.IncludesMaxHostLen(prefixBits+1)), address))
			return false
		}
		if prefixBits > 0 && address.IncludesMaxHostLen(prefixBits-1) {
			t.addFailure(newIPAddrFailure(address.String()+" is max host failure "+strconv.FormatBool(address.IncludesMaxHostLen(prefixBits-1)), address))
			return false
		}
	}
	//ones := network
	leadingBits := address.GetLeadingBitCount(network)
	var trailingBits ipaddr.BitCount
	if network && address.IsPrefixBlock() {
		trailingBits = address.GetLower().GetTrailingBitCount(!network)
	} else {
		trailingBits = address.GetTrailingBitCount(!network)
	}
	if leadingBits != prefixBits {
		t.addFailure(newIPAddrFailure("leading bits failure, bit counts are leading: "+leadingBits.String()+" trailing: "+trailingBits.String(), address))
		return false
	}
	if leadingBits+trailingBits != address.GetBitCount() {
		t.addFailure(newIPAddrFailure("bit counts are leading: "+leadingBits.String()+" trailing: "+trailingBits.String(), address))
		return false
	}
	if network {
		//try {
		originalPrefixStr := "/" + prefixBits.String()
		//originalChoppedStr := originalPrefixStr
		//if prefixBits > address.GetBitCount() {
		//	originalChoppedStr = "/" + address.GetBitCount().String()
		//}
		prefix := t.createAddress(originalPrefixStr)
		//maskStr := convertToMask(prefix, address.GetIPVersion())

		prefixExtra := originalPrefixStr
		addressWithNoPrefix := address
		//fmt.Println("Handling 3 " + address.String())
		if address.IsPrefixed() {
			var err error
			addressWithNoPrefix, err = address.Mask(address.GetNetwork().GetNetworkMask(*address.GetPrefixLen()))
			if err != nil {
				t.addFailure(newIPAddrFailure("failed mask "+err.Error(), address))
			}
		} //else {
		//	panic("whatever")
		//}

		ipForNormalizeMask := addressWithNoPrefix.String()
		maskStrx2 := t.normalizeMask(originalPrefixStr, ipForNormalizeMask) + prefixExtra
		maskStrx3 := t.normalizeMask(prefixBits.String(), ipForNormalizeMask) + prefixExtra
		normalStr := address.ToNormalizedString()
		if maskStrx2 != normalStr || maskStrx3 != normalStr {
			//if maskStr != normalStr || maskStrx2 != normalStr || maskStrx3 != normalStr {
			t.addFailure(newFailure("failed prefix conversion", prefix))
			return false
		}
		//else {
		//	 maskStr2 := t.createAddress(maskStr);
		//	 prefixStr := maskStr2.ConvertToPrefixLength();
		//	if(prefixStr != originalChoppedStr) {
		//		maskStr2 = t.createAddress(maskStr);
		//		maskStr2.convertToPrefixLength();
		//		t.addFailure(newFailure("failed mask conversion " + prefixStr, maskStr2));
		//		return false;
		//	}
		//}
		//} catch(AddressStringException | RuntimeException e) {
		//	addFailure(new Failure("failed conversion: " + e.getMessage(), address));
		//	return false;
		//}
	}

	t.incrementTestCount()
	if !secondTry {
		//secondTry = true
		bytes := address.GetBytes()
		var another *ipaddr.IPAddress
		// if address.IsIPv4() {
		//ipaddr.DefaultIPv4Network.
		if network {
			another = ipaddr.FromPrefixedIP(bytes, cacheTestBits(prefixBits)) //TODO here
		} else {
			another = ipaddr.FromIP(bytes)
		}
		// }
		//IPAddressStringFormatParameters params = address.isIPv4() ? ADDRESS_OPTIONS.getIPv4Parameters() : ADDRESS_OPTIONS.getIPv6Parameters();
		//IPAddressNetwork<?, ?, ?, ?, ?> addressNetwork = params.getNetwork();
		//IPAddressCreator<?, ?, ?, ?, ?> creator = addressNetwork.getAddressCreator();
		//IPAddress another = network ? creator.createAddress(bytes, cacheTestBits(prefixBits)) : creator.createAddress(bytes);

		result := t.checkMask(another, prefixBits, network, true)
		//secondTry = false

		//now check the prefix in the mask
		if result {
			prefixBitsMismatch := false
			addrPrefixBits := address.GetPrefixLen()
			if !network {
				prefixBitsMismatch = addrPrefixBits != nil
			} else {
				prefixBitsMismatch = addrPrefixBits == nil || (prefixBits != *addrPrefixBits)
			}
			if prefixBitsMismatch {
				t.addFailure(newIPAddrFailure("prefix incorrect", address))
				return false
			}
		}
	}
	return true
}

func (t ipAddressTester) normalizeMask(maskString, ipString string) string {
	if ipString != "" && len(strings.TrimSpace(ipString)) > 0 && maskString != "" && len(strings.TrimSpace(maskString)) > 0 {
		maskString = strings.TrimSpace(maskString)
		if strings.HasPrefix(maskString, "/") {
			maskString = maskString[1:]
		}
		addressString := ipaddr.NewIPAddressString(ipString)
		if addressString.IsValid() {
			//try {
			version := addressString.GetIPVersion()
			// validatePrefixLenStr TODO add to IPAddressString
			prefix, perr := ipaddr.ValidatePrefixLenStr(maskString, version)
			if perr != nil {
				t.addFailure(newFailure("prefix string incorrect: "+perr.Error(), addressString))
				return ""
			}
			maskAddress := addressString.GetAddress().GetNetwork().GetNetworkMask(*prefix)
			return maskAddress.ToNormalizedString()
			//} catch(PrefixLenException e) {
			//if validation vails, fall through and return mask string
			//}
		}
	}
	//Note that here I could normalize the mask to be a full one with an else
	return maskString
}

//func convertToMask(str *ipaddr.IPAddressString, version ipaddr.IPVersion) string {
//	address := str.GetVersionedAddress(version)
//	if address != nil {
//		return address.ToNormalizedString()
//	}
//	return ""
//}

func (t ipAddressTester) testNotContains(cidr1, cidr2 string) {
	t.testNotContainsNoReverse(cidr1, cidr2, false)
}

func (t ipAddressTester) testNotContainsNoReverse(cidr1, cidr2 string, skipReverse bool) {
	//	try {
	w := t.createAddress(cidr1).GetAddress()
	w2 := t.createAddress(cidr2).GetAddress()
	if w.Contains(w2) {
		t.addFailure(newIPAddrFailure("failed "+w2.String(), w))
	} else if !skipReverse && w2.Contains(w) {
		t.addFailure(newIPAddrFailure("failed "+w.String(), w2))
	}
	//} catch(AddressStringException e) {
	//	addFailure(new Failure("failed " + e));
	//}
	t.testContainsEqual(cidr1, cidr2, false, false)
	t.incrementTestCount()
}

func (t ipAddressTester) testContains(cidr1, cidr2 string, equal bool) {
	t.testContainsEqual(cidr1, cidr2, true, equal)
}

func (t ipAddressTester) testContainsEqual(cidr1, cidr2 string, result, equal bool) {
	//	try {
	wstr := t.createAddress(cidr1)
	w2str := t.createAddress(cidr2)
	w := wstr.GetAddress()
	w2 := w2str.GetAddress()
	needsConversion := !w.GetIPVersion().Equals(w2.GetIPVersion())
	firstContains := w.Contains(w2)
	convCont := false
	if !firstContains {
		convCont = conversionContains(w, w2)
	}
	if !firstContains && !convCont {
		if result {
			t.addFailure(newIPAddrFailure("containment failed "+w2.String(), w))
		}
	} else {
		if !result && firstContains {
			t.addFailure(newIPAddrFailure("containment passed "+w2.String(), w))
		} else if !result {
			t.addFailure(newIPAddrFailure("conv containment passed "+w2.String(), w))
		} else {
			if equal {
				if !(w2.Contains(w) || conversionContains(w2, w)) {
					t.addFailure(newIPAddrFailure("failed "+w.String(), w2))
				}
			} else {
				if w2.Contains(w) || conversionContains(w2, w) {
					t.addFailure(newIPAddrFailure("failed "+w.String(), w2))
				}
			}
		}
	}
	if !convCont {
		t.testStringContains(result, equal, wstr, w2str)
		//compare again, this tests the string-based optimization (which is skipped if we validated already)
		t.testStringContains(result, equal, t.createAddress(cidr1), t.createAddress(cidr2))

	}
	//boolean allPrefixesAreSubnets = prefixConfiguration.allPrefixedAddressesAreSubnets();
	//if(allPrefixesAreSubnets) {
	//	wstr = createAddress(cidr1);
	//	w2str = createAddress(cidr2);
	//	boolean prefixMatches = wstr.prefixEquals(w2str);
	//	if(prefixMatches && !result) {
	//		addFailure(new Failure("expected containment due to same prefix 1" + w2, w));
	//	}
	//	wstr.isValid();
	//	w2str.isValid();
	//	prefixMatches = wstr.prefixEquals(w2str);
	//	if(prefixMatches && !result) {
	//		addFailure(new Failure("expected containment due to same prefix 2" + w2, w));
	//	}
	//	w = wstr.toAddress();
	//	w2 = w2str.toAddress();
	//	prefixMatches = wstr.prefixEquals(w2str);
	//	if(prefixMatches && !result) {
	//		addFailure(new Failure("expected containment due to same prefix 3 " + w2, w));
	//	}
	//}

	if !needsConversion {
		//var params ipaddr.RangeParameters
		//if w.IsIPv4() {
		//	params = wstr.GetValidationOptions().GetIPv4Parameters().GetRangeParameters()
		//} else {
		//	params = wstr.GetValidationOptions().GetIPv6Parameters().GetRangeParameters()
		//}
		//noRangeParsingAllowed := ipaddr.AllowsNoRange(params)

		wstr = t.createAddress(cidr1)
		w2str = t.createAddress(cidr2)
		prefContains := wstr.PrefixContains(w2str)
		if !prefContains {
			// if contains, then prefix should also contain other prefix
			if result {
				t.addFailure(newIPAddrFailure("str prefix containment failed "+w2.String(), w))
			}
			wstr.IsValid()
			w2str.IsValid()
			prefContains = wstr.PrefixContains(w2str)
			if prefContains {
				t.addFailure(newIPAddrFailure("str prefix containment failed "+w2.String(), w))
			}
			w = wstr.GetAddress()
			w2 = w2str.GetAddress()
			prefContains = wstr.PrefixContains(w2str)
			if prefContains {
				t.addFailure(newIPAddrFailure("str prefix containment failed "+w2.String(), w))
			}
		}

		if !needsConversion { // with explicit subnets strings look like 1.2.*.*/16
			//if(!needsConversion && !(prefixConfiguration.prefixedSubnetsAreExplicit() && noRangeParsingAllowed)) { // with explicit subnets strings look like 1.2.*.*/16

			// now do testing on the prefix block, allowing us to test prefixContains
			wstr = t.createAddress(wstr.GetAddress().ToPrefixBlock().String())
			w2str = t.createAddress(w2str.GetAddress().ToPrefixBlock().String())
			prefContains = wstr.PrefixContains(w2str)

			wstr.IsValid()
			w2str.IsValid()
			prefContains2 := wstr.PrefixContains(w2str)

			w = wstr.GetAddress()
			w2 = w2str.GetAddress()
			origContains := w.Contains(w2)
			prefContains3 := wstr.PrefixContains(w2str)
			if !origContains {
				// if the prefix block does not contain, then prefix should also not contain other prefix
				if prefContains {
					t.addFailure(newIPAddrFailure("str prefix containment failed "+w2.String(), w))
				}
				if prefContains2 {
					t.addFailure(newIPAddrFailure("str prefix containment failed "+w2.String(), w))
				}
				if prefContains3 {
					t.addFailure(newIPAddrFailure("str prefix containment failed "+w2.String(), w))
				}
			} else {
				// if contains, then prefix should also contain other prefix
				if !prefContains {
					t.addFailure(newIPAddrFailure("str prefix containment failed "+w2.String(), w))
				}
				if !prefContains2 {
					t.addFailure(newIPAddrFailure("str prefix containment failed "+w2.String(), w))
				}
				if !prefContains3 {
					t.addFailure(newIPAddrFailure("str prefix containment failed "+w2.String(), w))
				}
			}

			// again do testing on the prefix block, allowing us to test prefixEquals
			wstr = t.createAddress(wstr.GetAddress().ToPrefixBlock().String())
			w2str = t.createAddress(w2str.GetAddress().ToPrefixBlock().String())
			prefEquals := wstr.PrefixEquals(w2str)

			wstr.IsValid()
			w2str.IsValid()
			prefEquals2 := wstr.PrefixEquals(w2str)

			w = wstr.GetAddress()
			w2 = w2str.GetAddress()
			origEquals := w.PrefixEquals(w2)
			prefEquals3 := wstr.PrefixEquals(w2str)
			if !origEquals {
				// if the prefix block does not contain, then prefix should also not contain other prefix
				if prefEquals {
					t.addFailure(newIPAddrFailure("str prefix equality failed "+w2.String(), w))
				}
				if prefEquals2 {
					t.addFailure(newIPAddrFailure("str prefix equality failed "+w2.String(), w))
				}
				if prefEquals3 {
					t.addFailure(newIPAddrFailure("str prefix equality failed "+w2.String(), w))
				}
			} else {
				// if prefix blocks are equal, then prefix should also equal other prefix
				if !prefEquals {
					fmt.Printf("prefix equals: %v %v\n", w, w2)
					w.PrefixEquals(w2)
					t.addFailure(newIPAddrFailure("str prefix equality failed "+w2.String(), w))
				}
				if !prefEquals2 {
					t.addFailure(newIPAddrFailure("str prefix equality failed "+w2.String(), w))
				}
				if !prefEquals3 {
					t.addFailure(newIPAddrFailure("str prefix equality failed "+w2.String(), w))
				}
			}
		}
	}
	//} catch(AddressStringException e) {
	//	addFailure(new Failure("failed " + e));
	//}
	t.incrementTestCount()
}

func (t ipAddressTester) testStringContains(result, equal bool, wstr, w2str *ipaddr.IPAddressString) {
	if !wstr.Contains(w2str) {
		if result {
			t.addFailure(newFailure("containment failed "+w2str.String(), wstr))
		}
	} else {
		if !result {
			t.addFailure(newFailure("containment passed "+w2str.String(), wstr))
		} else {
			if equal {
				if !w2str.Contains(wstr) {
					t.addFailure(newFailure("failed "+wstr.String(), w2str))
				}
			} else {
				if w2str.Contains(wstr) {
					t.addFailure(newFailure("failed "+wstr.String(), w2str))
				}
			}

		}
	}
}

var conv = ipaddr.DefaultAddressConverter{}

func conversionContains(h1, h2 *ipaddr.IPAddress) bool {
	if h1.IsIPv4() {
		if !h2.IsIPv4() {
			if conv.IsIPv4Convertible(h2) {
				return h1.Contains(conv.ToIPv4(h2))
			}
		}
	} else if h1.IsIPv6() {
		if !h2.IsIPv6() {
			if conv.IsIPv6Convertible(h2) {
				return h1.Contains(conv.ToIPv6(h2))
			}
		}
	}
	return false
}

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
