package test

import (
	"bytes"
	"fmt"
	"github.com/seancfoley/ipaddress/ipaddress-go/ipaddr"
	"github.com/seancfoley/ipaddress/ipaddress-go/ipaddr/addrformat"
	"math"
	"math/big"
	//"math/bits"
	"net"
	"strconv"
	"strings"
)

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

	var bcneg1, bc0, bc1, bc8, bc16, bc32 ipaddr.BitCount = -1, 0, 1, 8, 16, 32

	t.testBitwiseOr("1.2.0.0", nil, "0.0.3.4", "1.2.3.4")
	t.testBitwiseOr("1.2.0.0", nil, "0.0.0.0", "1.2.0.0")
	t.testBitwiseOr("1.2.0.0", nil, "255.255.255.255", "255.255.255.255")
	t.testBitwiseOr("1.0.0.0/8", &bc16, "0.2.3.0", "1.2.3.0/24") //note the prefix length is dropped to become "1.2.3.*", but equality still holds
	t.testBitwiseOr("1.2.0.0/16", &bc8, "0.0.3.0", "1.2.3.0/24") //note the prefix length is dropped to become "1.2.3.*", but equality still holds

	t.testBitwiseOr("0.0.0.0", nil, "1.2.3.4", "1.2.3.4")
	t.testBitwiseOr("0.0.0.0", &bc1, "1.2.3.4", "1.2.3.4")
	t.testBitwiseOr("0.0.0.0", &bcneg1, "1.2.3.4", "1.2.3.4")
	t.testBitwiseOr("0.0.0.0", &bc0, "1.2.3.4", "1.2.3.4")
	t.testBitwiseOr("0.0.0.0/0", &bcneg1, "1.2.3.4", "")
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
	t.testBitwiseOr("1::/16", &bc32, "0:2:3::", "1:2:3::/48")   //note the prefix length is dropped to become "1.2.3.*", but equality still holds
	t.testBitwiseOr("1:2::/32", &bc16, "0:0:3::", "1:2:3::/48") //note the prefix length is dropped to become "1.2.3.*", but equality still holds

	t.testBitwiseOr("::", nil, "::1:2:3:4", "::1:2:3:4")
	t.testBitwiseOr("::", &bc1, "::1:2:3:4", "::1:2:3:4")
	t.testBitwiseOr("::", &bcneg1, "::1:2:3:4", "::1:2:3:4")
	t.testBitwiseOr("::", &bc0, "::1:2:3:4", "::1:2:3:4")
	t.testBitwiseOr("::/0", &bcneg1, "::1:2:3:4", "")
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

	allowsIPv4PrefixBeyondAddressSize := t.createAddress("1.2.3.4").GetValidationOptions().GetIPv4Parameters().AllowsPrefixesBeyondAddressSize()
	allowsIPv6PrefixBeyondAddressSize := t.createAddress("1.2.3.4").GetValidationOptions().GetIPv6Parameters().AllowsPrefixesBeyondAddressSize()

	//test some valid and invalid prefixes
	t.ipv4test(true, "1.2.3.4/1")
	t.ipv4test(false, "1.2.3.4/ 1")
	t.ipv4test(false, "1.2.3.4/-1")
	t.ipv4test(false, "1.2.3.4/+1")
	t.ipv4test(false, "1.2.3.4/")
	t.ipv4test(true, "1.2.3.4/1.2.3.4")
	t.ipv4test(false, "1.2.3.4/x")
	t.ipv4test(allowsIPv4PrefixBeyondAddressSize, "1.2.3.4/33") //we are not allowing extra-large prefixes
	t.ipv6test(true, "1::1/1")
	t.ipv6test(false, "1::1/-1")
	t.ipv6test(false, "1::1/")
	t.ipv6test(false, "1::1/x")
	t.ipv6test(allowsIPv6PrefixBeyondAddressSize, "1::1/129") //we are not allowing extra-large prefixes
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

	t.testContains("1.0.0.0/16", "1.0.0.0/24", false)

	t.testContains("5.62.62.0/23", "5.62.63.1", false)

	t.testNotContains("5.62.62.0/23", "5.62.64.1")
	t.testNotContains("5.62.62.0/23", "5.62.68.1")
	t.testNotContains("5.62.62.0/23", "5.62.78.1")

	t.testNetmasks(0, "0.0.0.0/0", "0.0.0.0", "255.255.255.255", "::/0", "::", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff") //test that the given prefix gives ipv4 and ipv6 addresses matching the netmasks
	t.testNetmasks(1, "128.0.0.0/1", "128.0.0.0", "127.255.255.255", "8000::/1", "8000::", "7fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")
	t.testNetmasks(15, "255.254.0.0/15", "255.254.0.0", "0.1.255.255", "fffe::/15", "fffe::", "1:ffff:ffff:ffff:ffff:ffff:ffff:ffff")
	t.testNetmasks(16, "255.255.0.0/16", "255.255.0.0", "0.0.255.255", "ffff::/16", "ffff::", "::ffff:ffff:ffff:ffff:ffff:ffff:ffff")
	t.testNetmasks(17, "255.255.128.0/17", "255.255.128.0", "0.0.127.255", "ffff:8000::/17", "ffff:8000::", "::7fff:ffff:ffff:ffff:ffff:ffff:ffff")
	t.testNetmasks(31, "255.255.255.254/31", "255.255.255.254", "0.0.0.1", "ffff:fffe::/31", "ffff:fffe::", "::1:ffff:ffff:ffff:ffff:ffff:ffff")
	t.testNetmasks(32, "255.255.255.255/32", "255.255.255.255", "0.0.0.0", "ffff:ffff::/32", "ffff:ffff::", "::ffff:ffff:ffff:ffff:ffff:ffff")
	t.testNetmasks(127, "255.255.255.255/127", "", "0.0.0.0", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe/127", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe", "::1")

	t.testNetmasks(128, "255.255.255.255/128", "", "0.0.0.0", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "::")
	t.testNetmasks(129, "255.255.255.255/129", "", "0.0.0.0", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/129", "", "::")

	t.checkNotMask("254.255.0.0")
	t.checkNotMask("255.255.0.1")
	t.checkNotMask("0.1.0.0")
	t.checkNotMask("0::10")
	t.checkNotMask("1::0")

	//Some mask/address combinations do not result in a contiguous range and thus don't work
	//The underlying rule is that mask bits that are 0 must be above the resulting segment range.
	//Any bit in the mask that is 0 must not fall below any bit in the masked segment range that is different between low and high
	//Any network mask must eliminate the entire range in the segment
	//Any host mask is fine

	t.testSubnet("1.2.0.0", "0.0.255.255", 16 /* mask is valid with prefix */, "0.0.0.0/16" /* mask is valid alone */, "0.0.0.0", "1.2.0.0/16" /* prefix alone */)
	t.testSubnet("1.2.0.0", "0.0.255.255", 17, "0.0.0.0/17", "0.0.0.0", "1.2.0.0/17")
	t.testSubnet("1.2.128.0", "0.0.255.255", 17, "0.0.128.0/17", "0.0.128.0", "1.2.128.0/17")
	t.testSubnet("1.2.0.0", "0.0.255.255", 15, "0.0.0.0/15", "0.0.0.0", "1.2.0.0/15")
	t.testSubnet("1.2.0.0", "0.0.255.255", 15, "0.0.0.0/15", "0.0.0.0", "1.2.0.0/15")

	t.testSubnet("1.2.0.0/15", "0.0.255.255", 16, "0.0.0.0/16", "0.0.*.*", "1.2.0.0/15") //
	t.testSubnet("1.2.0.0/15", "0.0.255.255", 15, "0.0.0.0/15", "0.0.*.*", "1.2.0.0/15")
	t.testSubnet("1.2.0.0/15", "0.0.255.255", 15, "0.0.0.0/15", "0.0.*.*", "1.2.0.0/15")
	t.testSubnet("1.0.0.0/15", "0.1.255.255", 15, "0.0.0.0/15", "0.0-1.*.*", "1.0.0.0/15")

	t.testSubnet("1.2.0.0/17", "0.0.255.255", 16, "0.0.0-127.*/16", "0.0.0-127.*", "1.2.0-127.*/16")
	t.testSubnet("1.2.0.0/17", "0.0.255.255", 17, "0.0.0.0/17", "0.0.0-127.*", "1.2.0.0/17")
	t.testSubnet("1.2.128.0/17", "0.0.255.255", 17, "0.0.128.0/17", "0.0.128-255.*", "1.2.128.0/17")
	t.testSubnet("1.2.0.0/17", "0.0.255.255", 15, "0.0.0-127.*/15", "0.0.0-127.*", "1.2.0-127.*/15")       //
	t.testSubnet("1.3.128.0/17", "0.0.255.255", 15, "0.1.128-255.*/15", "0.0.128-255.*", "1.2.0-127.*/15") //
	t.testSubnet("1.3.128.0/17", "255.255.255.255", 15, ("1.3.128-255.*/15"), "1.3.128-255.*", "1.2.0-127.*/15")
	t.testSubnet("1.3.0.0/16", "255.255.255.255", 8, ("1.3.*.*/8"), "1.3.*.*", "1.0.*.*/8")
	t.testSubnet("1.0.0.0/16", "255.255.255.255", 8, "1.0.*.*/8", "1.0.*.*", "1.0.*.*/8")
	t.testSubnet("1.0.0.0/18", "255.255.255.255", 16, "1.0.0-63.*/16", "1.0.0-63.*", "1.0.0-63.*/16")

	t.testSubnet("1.2.0.0", "255.255.0.0", 16, "1.2.0.0/16", "1.2.0.0", "1.2.0.0/16")
	t.testSubnet("1.2.0.0", "255.255.0.0", 17, "1.2.0.0/17", "1.2.0.0", "1.2.0.0/17")
	t.testSubnet("1.2.128.0", "255.255.0.0", 17, "1.2.0.0/17", "1.2.0.0", "1.2.128.0/17")
	t.testSubnet("1.2.128.0", "255.255.128.0", 17, "1.2.128.0/17", "1.2.128.0", "1.2.128.0/17")
	t.testSubnet("1.2.0.0", "255.255.0.0", 15, "1.2.0.0/15", "1.2.0.0", "1.2.0.0/15")

	t.testSubnet("1.2.0.0/17", "255.255.0.0", 16, "1.2.0-127.*/16", "1.2.0.0", "1.2.0-127.*/16")
	t.testSubnet("1.2.0.0/17", "255.255.0.0", 17, "1.2.0.0/17", "1.2.0.0", "1.2.0.0/17")
	t.testSubnet("1.2.128.0/17", "255.255.0.0", 17, "1.2.0.0/17", "1.2.0.0", "1.2.128.0/17")
	t.testSubnet("1.2.128.0/17", "255.255.128.0", 17, "1.2.128.0/17", "1.2.128.0", "1.2.128.0/17")
	t.testSubnet("1.2.0.0/17", "255.255.0.0", 15, "1.2.0-127.*/15", "1.2.0.0", "1.2.0-127.*/15")

	t.testSubnet("1.2.0.0/16", "255.255.0.0", 16, "1.2.0.0/16", "1.2.0.0", "1.2.0.0/16")
	t.testSubnet("1.2.0.0/16", "255.255.0.0", 17, "1.2.0.0/17", "1.2.0.0", "1.2.0.0/16")
	t.testSubnet("1.2.0.0/16", "255.255.0.0", 17, "1.2.0.0/17", "1.2.0.0", "1.2.0.0/16")
	t.testSubnet("1.2.0.0/16", "255.255.128.0", 17, "1.2.0-128.0/17", "", "1.2.0.0/16")
	t.testSubnet("1.2.0.0/16", "255.255.0.0", 15, "1.2.*.*/15", "1.2.0.0", "1.2.*.*/15")

	t.testSubnet("1.2.0.0/15", "255.255.0.0", 16, "1.2-3.0.0/16", "1.2-3.0.0", "1.2.0.0/15")
	t.testSubnet("1.2.0.0/15", "255.255.0.0", 17, "1.2-3.0.0/17", "1.2-3.0.0", "1.2.0.0/15")
	t.testSubnet("1.2.0.0/15", "255.255.128.0", 17, "1.2-3.0-128.0/17", "", "1.2.0.0/15")
	t.testSubnet("1.2.0.0/15", "255.255.128.0", 18, "", "", "1.2.0.0/15")
	t.testSubnet("1.2.0.0/15", "255.255.192.0", 18, "1.2-3.0-192.0/18", "", "1.2.0.0/15")

	t.testSubnet("1.0.0.0/12", "255.254.0.0", 16, "", "", "1.0.0.0/12")
	t.testSubnet("1.0.0.0/12", "255.243.0.255", 16, "1.0-3.0.0/16", "1.0-3.0.*", "1.0.0.0/12")
	t.testSubnet("1.0.0.0/12", "255.255.0.0", 16, "1.0-15.0.0/16", "1.0-15.0.0", "1.0.0.0/12")
	t.testSubnet("1.0.0.0/12", "255.240.0.0", 16, "1.0.0.0/16", "1.0.0.0", "1.0.0.0/12")
	t.testSubnet("1.0.0.0/12", "255.248.0.0", 13, "1.0-8.0.0/13", "", "1.0.0.0/12")

	t.testSubnet("1.2.0.0/15", "255.254.128.0", 17, "1.2.0-128.0/17", "", "1.2.0.0/15")
	t.testSubnet("1.2.0.0/15", "255.255.128.0", 17, "1.2-3.0-128.0/17", "", "1.2.0.0/15")
	t.testSubnet("1.2.0.0/15", "255.252.128.0", 17, "1.0.0-128.0/17", "", "1.2.0.0/15")
	t.testSubnet("1.2.0.0/15", "255.252.128.0", 18, "", "", "1.2.0.0/15")
	t.testSubnet("1.2.0.0/15", "255.255.127.0", 15, "1.2.0.0/15", "1.2-3.0-127.0", "1.2.0.0/15")
	t.testSubnet("1.2.0.0/15", "255.255.0.255", 15, "1.2.0.0/15", "1.2-3.0.*", "1.2.0.0/15")

	t.testSubnet("1.2.128.1/17", "0.0.255.255", 17, "0.0.128.1/17", "0.0.128.1", "1.2.128.1/17")

	t.testSubnet("1.2.3.4", "0.0.255.255", 16 /* mask is valid with prefix */, "0.0.3.4/16" /* mask is valid alone */, "0.0.3.4", "1.2.3.4/16" /* prefix alone */)
	t.testSubnet("1.2.3.4", "0.0.255.255", 17, "0.0.3.4/17", "0.0.3.4", "1.2.3.4/17")
	t.testSubnet("1.2.128.4", "0.0.255.255", 17, "0.0.128.4/17", "0.0.128.4", "1.2.128.4/17")
	t.testSubnet("1.2.3.4", "0.0.255.255", 15, "0.0.3.4/15", "0.0.3.4", "1.2.3.4/15")
	t.testSubnet("1.1.3.4", "0.0.255.255", 15, "0.1.3.4/15", "0.0.3.4", "1.1.3.4/15")
	t.testSubnet("1.2.128.4", "0.0.255.255", 15, "0.0.128.4/15", "0.0.128.4", "1.2.128.4/15")

	t.testSubnet("1.2.3.4/15", "0.0.255.255", 16, "0.0.3.4/16", "0.0.3.4", "1.2.3.4/15") //second to last is 0.0.0.0/15 and I don't know why. we are applying the mask only.  I can see how the range becomes /16 but why the string look ike that?
	t.testSubnet("1.2.3.4/15", "0.0.255.255", 17, "0.0.3.4/17", "0.0.3.4", "1.2.3.4/15")
	t.testSubnet("1.2.128.4/15", "0.0.255.255", 17, "0.0.128.4/17", "0.0.128.4", "1.2.128.4/15")
	t.testSubnet("1.2.3.4/15", "0.0.255.255", 15, "0.0.3.4/15", "0.0.3.4", "1.2.3.4/15")
	t.testSubnet("1.1.3.4/15", "0.0.255.255", 15, "0.1.3.4/15", "0.0.3.4", "1.1.3.4/15")
	t.testSubnet("1.2.128.4/15", "0.0.255.255", 15, "0.0.128.4/15", "0.0.128.4", "1.2.128.4/15")
	t.testSubnet("1.1.3.4/15", "0.1.255.255", 15, "0.1.3.4/15", "0.1.3.4", "1.1.3.4/15")
	t.testSubnet("1.0.3.4/15", "0.1.255.255", 15, "0.0.3.4/15", "0.0.3.4", "1.0.3.4/15")

	t.testSubnet("1.2.3.4/17", "0.0.255.255", 16, "0.0.3.4/16", "0.0.3.4", "1.2.3.4/16")
	t.testSubnet("1.2.3.4/17", "0.0.255.255", 17, "0.0.3.4/17", "0.0.3.4", "1.2.3.4/17")
	t.testSubnet("1.2.128.4/17", "0.0.255.255", 17, "0.0.128.4/17", "0.0.128.4", "1.2.128.4/17")
	t.testSubnet("1.2.3.4/17", "0.0.255.255", 15, "0.0.3.4/15", "0.0.3.4", "1.2.3.4/15")
	t.testSubnet("1.1.3.4/17", "0.0.255.255", 15, "0.1.3.4/15", "0.0.3.4", "1.0.3.4/15")
	t.testSubnet("1.2.128.4/17", "0.0.255.255", 15, "0.0.128.4/15", "0.0.128.4", "1.2.0.4/15")

	t.testSubnet("1.2.3.4", "255.255.0.0", 16, "1.2.3.4/16", "1.2.0.0", "1.2.3.4/16")
	t.testSubnet("1.2.3.4", "255.255.0.0", 17, "1.2.3.4/17", "1.2.0.0", "1.2.3.4/17")
	t.testSubnet("1.2.128.4", "255.255.0.0", 17, "1.2.0.4/17", "1.2.0.0", "1.2.128.4/17")
	t.testSubnet("1.2.128.4", "255.255.128.0", 17, "1.2.128.4/17", "1.2.128.0", "1.2.128.4/17")
	t.testSubnet("1.2.3.4", "255.255.0.0", 15, "1.2.3.4/15", "1.2.0.0", "1.2.3.4/15")
	t.testSubnet("1.1.3.4", "255.255.0.0", 15, "1.1.3.4/15", "1.1.0.0", "1.1.3.4/15")
	t.testSubnet("1.2.128.4", "255.255.0.0", 15, "1.2.128.4/15", "1.2.0.0", "1.2.128.4/15")

	t.testSubnet("1.2.3.4/17", "255.255.0.0", 16, "1.2.3.4/16", "1.2.0.0", "1.2.3.4/16")
	t.testSubnet("1.2.3.4/17", "255.255.0.0", 17, "1.2.3.4/17", "1.2.0.0", "1.2.3.4/17")
	t.testSubnet("1.2.128.4/17", "255.255.0.0", 17, "1.2.0.4/17", "1.2.0.0", "1.2.128.4/17")
	t.testSubnet("1.2.128.4/17", "255.255.128.0", 17, "1.2.128.4/17", "1.2.128.0", "1.2.128.4/17")
	t.testSubnet("1.2.3.4/17", "255.255.0.0", 15, "1.2.3.4/15", "1.2.0.0", "1.2.3.4/15")
	t.testSubnet("1.1.3.4/17", "255.255.0.0", 15, "1.1.3.4/15", "1.1.0.0", "1.0.3.4/15")
	t.testSubnet("1.2.128.4/17", "255.255.0.0", 15, "1.2.128.4/15", "1.2.0.0", "1.2.0.4/15")

	t.testSubnet("1.2.3.4/16", "255.255.0.0", 16, "1.2.3.4/16", "1.2.0.0", "1.2.3.4/16")
	t.testSubnet("1.2.3.4/16", "255.255.0.0", 17, "1.2.3.4/17", "1.2.0.0", "1.2.3.4/16")
	t.testSubnet("1.2.128.4/16", "255.255.0.0", 17, "1.2.0.4/17", "1.2.0.0", "1.2.128.4/16")
	t.testSubnet("1.2.128.4/16", "255.255.128.0", 17, "1.2.128.4/17", "1.2.128.0", "1.2.128.4/16")
	t.testSubnet("1.2.3.4/16", "255.255.0.0", 15, "1.2.3.4/15", "1.2.0.0", "1.2.3.4/15")
	t.testSubnet("1.1.3.4/16", "255.255.0.0", 15, "1.1.3.4/15", "1.1.0.0", "1.0.3.4/15")
	t.testSubnet("1.2.128.4/16", "255.255.0.0", 15, "1.2.128.4/15", "1.2.0.0", "1.2.128.4/15")

	t.testSubnet("1.2.3.4/15", "255.255.0.0", 16, "1.2.3.4/16", "1.2.0.0", "1.2.3.4/15")
	t.testSubnet("1.2.3.4/15", "255.255.0.0", 17, "1.2.3.4/17", "1.2.0.0", "1.2.3.4/15")
	t.testSubnet("1.2.128.4/15", "255.255.0.0", 17, "1.2.0.4/17", "1.2.0.0", "1.2.128.4/15")
	t.testSubnet("1.2.128.4/15", "255.255.128.0", 17, "1.2.128.4/17", "1.2.128.0", "1.2.128.4/15")
	t.testSubnet("1.2.128.4/15", "255.255.128.0", 18, "1.2.128.4/18", "1.2.128.0", "1.2.128.4/15")
	t.testSubnet("1.2.128.4/15", "255.255.192.0", 18, "1.2.128.4/18", "1.2.128.0", "1.2.128.4/15")

	t.testSubnet("1.2.3.4/12", "255.254.0.0", 16, "1.2.3.4/16", "1.2.0.0", "1.2.3.4/12")
	t.testSubnet("1.2.3.4/12", "255.243.0.255", 16, "1.2.3.4/16", "1.2.0.4", "1.2.3.4/12")
	t.testSubnet("1.2.3.4/12", "255.255.0.0", 16, "1.2.3.4/16", "1.2.0.0", "1.2.3.4/12")
	t.testSubnet("1.2.3.4/12", "255.240.0.0", 16, "1.0.3.4/16", "1.0.0.0", "1.2.3.4/12")
	t.testSubnet("1.2.3.4/12", "255.248.0.0", 13, "1.2.3.4/13", "1.0.0.0", "1.2.3.4/12")

	t.testSubnet("1.2.128.4/15", "255.254.128.0", 17, "1.2.128.4/17", "1.2.128.0", "1.2.128.4/15")
	t.testSubnet("1.2.128.4/15", "255.255.128.0", 17, "1.2.128.4/17", "1.2.128.0", "1.2.128.4/15")
	t.testSubnet("1.2.128.4/15", "255.252.128.0", 17, "1.0.128.4/17", "1.0.128.0", "1.2.128.4/15")
	t.testSubnet("1.2.128.4/15", "255.252.128.0", 18, "1.0.128.4/18", "1.0.128.0", "1.2.128.4/15")
	t.testSubnet("1.2.3.4/15", "255.255.127.0", 15, "1.2.3.4/15", "1.2.3.0", "1.2.3.4/15")
	t.testSubnet("1.1.3.4/15", "255.255.0.0", 15, "1.1.3.4/15", "1.1.0.0", "1.1.3.4/15")
	t.testSubnet("1.2.128.4/15", "255.255.0.255", 15, "1.2.128.4/15", "1.2.0.4", "1.2.128.4/15")

	t.testSubnet("::/8", "ffff::", 128, "0-ff:0:0:0:0:0:0:0/128", "0-ff:0:0:0:0:0:0:0", "0:0:0:0:0:0:0:0/8")
	t.testSubnet("::/8", "fff0::", 128, "", "", "0:0:0:0:0:0:0:0/8")
	/*x*/ t.testSubnet("::/8", "fff0::", 12, "0-f0:0:0:0:0:0:0:0/12", "", "0:0:0:0:0:0:0:0/8")

	t.testSubnet("1.2.0.0/16", "255.255.0.1", 24, "1.2.0.0/24", "1.2.0.0-1", "1.2.0.0/16")
	t.testSubnet("1.2.0.0/16", "255.255.0.3", 24, "1.2.0.0/24", "1.2.0.0-3", "1.2.0.0/16")
	t.testSubnet("1.2.0.0/16", "255.255.3.3", 24, "1.2.0-3.0/24", "1.2.0-3.0-3", "1.2.0.0/16")

	t.testSplit("9.129.237.26", 0, "", "", "", 1, "9.129.237.26", 2) //compare the two for equality.  compare the bytes of the second one with the bytes of the second one having no mask.
	t.testSplit("9.129.237.26", 8, "9", "9", "9/8", 2, "129.237.26", 2)
	t.testSplit("9.129.237.26", 16, "9.129", "9.129", "9.129/16", 2, "237.26", 2)

	t.testSplit("9.129.237.26", 31, "9.129.237.26-27", "9.129.237.26", "9.129.237.26/31", 2, "0", 2)
	t.testSplit("9.129.237.26", 32, "9.129.237.26", "9.129.237.26", "9.129.237.26/32", 2, "", 1)

	t.testSplit("1.2.3.4", 4, "0-15", "0", "0/4", 2, "1.2.3.4", 2)
	t.testSplit("255.2.3.4", 4, "240-255", "240", "240/4", 1, "15.2.3.4", 2)

	t.testSplit("9:129::237:26", 0, "", "", "", 1, "9:129:0:0:0:0:237:26", 12) //compare the two for equality.  compare the bytes of the second one with the bytes of the second one having no mask.
	t.testSplit("9:129::237:26", 16, "9", "9", "9/16", 2, "129:0:0:0:0:237:26", 12)
	t.testSplit("9:129::237:26", 31, "9:128-129", "9:128", "9:128/31", 2, "1:0:0:0:0:237:26", 12)

	t.testSplit("9:129::237:26", 32, "9:129", "9:129", "9:129/32", 2, "0:0:0:0:237:26", 10)
	t.testSplit("9:129::237:26", 33, "9:129:0-7fff", "9:129:0", "9:129:0/33", 2, "0:0:0:0:237:26", 10)
	t.testSplit("9:129::237:26", 63, "9:129:0:0-1", "9:129:0:0", "9:129:0:0/63", 4, "0:0:0:237:26", 10)
	t.testSplit("9:129::237:26", 64, "9:129:0:0", "9:129:0:0", "9:129:0:0/64", 4, "0:0:237:26", 10)
	t.testSplit("9:129::237:26", 96, "9:129:0:0:0:0", "9:129:0:0:0:0", "9:129:0:0:0:0/96", 4, "237:26", 4)
	t.testSplit("9:129::237:26", 111, "9:129:0:0:0:0:236-237", "9:129:0:0:0:0:236", "9:129:0:0:0:0:236/111", 12, "1:26", 4)
	t.testSplit("9:129::237:26", 112, "9:129:0:0:0:0:237", "9:129:0:0:0:0:237", "9:129:0:0:0:0:237/112", 12, "26", 4)
	t.testSplit("9:129::237:26", 113, "9:129:0:0:0:0:237:0-7fff", "9:129:0:0:0:0:237:0", "9:129:0:0:0:0:237:0/113", 12, "26", 4)
	t.testSplit("9:129::237:ffff", 113, "9:129:0:0:0:0:237:8000-ffff", "9:129:0:0:0:0:237:8000", "9:129:0:0:0:0:237:8000/113", 12, "7fff", 3)
	t.testSplit("9:129::237:26", 127, "9:129:0:0:0:0:237:26-27", "9:129:0:0:0:0:237:26", "9:129:0:0:0:0:237:26/127", 12, "0", 5) //previously when splitting host we would have just one ipv4 segment, but now we have two ipv4 segments
	t.testSplit("9:129::237:26", 128, "9:129:0:0:0:0:237:26", "9:129:0:0:0:0:237:26", "9:129:0:0:0:0:237:26/128", 12, "", 1)

	USE_UPPERCASE := 2

	t.testSplit("a:b:c:d:e:f:a:b", 4, "0-fff", "0", "0/4", 2, "a:b:c:d:e:f:a:b", 6*USE_UPPERCASE)
	t.testSplit("ffff:b:c:d:e:f:a:b", 4, "f000-ffff", "f000", "f000/4", 1*USE_UPPERCASE, "fff:b:c:d:e:f:a:b", 6*USE_UPPERCASE)
	t.testSplit("ffff:b:c:d:e:f:a:b", 2, "c000-ffff", "c000", "c000/2", 1*USE_UPPERCASE, "3fff:b:c:d:e:f:a:b", 6*USE_UPPERCASE)

	t.testURL("http://1.2.3.4")
	t.testURL("http://[a:a:a:a:b:b:b:b]")
	t.testURL("http://a:a:a:a:b:b:b:b")

	//TODO LATER maybe - testSections works with getStartsWithSQLClause
	//testSections("9.129.237.26", 0, 1)
	//testSections("9.129.237.26", 8, 1 /* 2 */)
	//testSections("9.129.237.26", 16, 1 /* 2 */)
	//testSections("9.129.237.26", 24, 1 /* 2 */)
	//testSections("9.129.237.26", 32, 1 /* 2 */)
	//testSections("9:129::237:26", 0, 1)
	//testSections("9:129::237:26", 16, 1 /* 2 */)
	//testSections("9:129::237:26", 64, 2 /* 4 */)
	//testSections("9:129::237:26", 80, 2 /* 4 */)
	//testSections("9:129::237:26", 96, 2 /* 4 */)
	//testSections("9:129::237:26", 112, 2 /* 12 */)
	//testSections("9:129::237:26", 128, 2 /* 12 */)
	//
	//testSections("9.129.237.26", 7, 2 /* 4 */)
	//testSections("9.129.237.26", 9, 128 /* 256 */) //129 is 10000001
	//testSections("9.129.237.26", 10, 64 /* 128 */)
	//testSections("9.129.237.26", 11, 32 /* 64 */)
	//testSections("9.129.237.26", 12, 16 /* 32 */)
	//testSections("9.129.237.26", 13, 8 /* 16 */)
	//testSections("9.129.237.26", 14, 4 /* 8 */) //10000000 to 10000011 (128 to 131)
	//testSections("9.129.237.26", 15, 2 /* 4 */) //10000000 to 10000001 (128 to 129)

	// TODO LATER testVariantCounts works with string collections
	////test that the given address has the given number of standard variants and total variants
	//testVariantCounts("::", 2, 2, 9, 1297);
	//testVariantCounts("::1", 2, 2, 10, 1298);
	////testVariantCounts("::1", 2, 2, IPv6Address.network().getStandardLoopbackStrings().length, 1298);//this confirms that IPv6Address.getStandardLoopbackStrings() is being initialized properly
	//testVariantCounts("::ffff:1.2.3.4", 6, 4, 20, 1410, 1320);//ipv4 mapped
	//testVariantCounts("::fffe:1.2.3.4", 2, 4, 20, 1320, 1320);//almost identical but not ipv4 mapped
	//testVariantCounts("::ffff:0:0", 6, 4, 24, 1474, 1384);//ipv4 mapped
	//testVariantCounts("::fffe:0:0", 2, 4, 24, 1384, 1384);//almost identical but not ipv4 mapped
	//testVariantCounts("2:2:2:2:2:2:2:2", 2, 1, 6, 1280);
	//testVariantCounts("2:0:0:2:0:2:2:2", 2, 2, 18, 2240);
	//testVariantCounts("a:b:c:0:d:e:f:1", 2, 4, 12 * USE_UPPERCASE, 1920 * USE_UPPERCASE);
	//testVariantCounts("a:b:c:0:0:d:e:f", 2, 4, 12 * USE_UPPERCASE, 1600 * USE_UPPERCASE);
	//testVariantCounts("a:b:c:d:e:f:0:1", 2, 4, 8 * USE_UPPERCASE, 1408 * USE_UPPERCASE);
	//testVariantCounts("a:b:c:d:e:f:0:0", 2, 4, 8 * USE_UPPERCASE, 1344 * USE_UPPERCASE);
	//testVariantCounts("a:b:c:d:e:f:a:b", 2, 2, 6 * USE_UPPERCASE, 1280 * USE_UPPERCASE);
	//testVariantCounts("aaaa:bbbb:cccc:dddd:eeee:ffff:aaaa:bbbb", 2, 2, 2 * USE_UPPERCASE, 2 * USE_UPPERCASE);
	//testVariantCounts("a111:1111:1111:1111:1111:1111:9999:9999", 2, 2, 2 * USE_UPPERCASE, 2 * USE_UPPERCASE);
	//testVariantCounts("1a11:1111:1111:1111:1111:1111:9999:9999", 2, 2, 2 * USE_UPPERCASE, 2 * USE_UPPERCASE);
	//testVariantCounts("11a1:1111:1111:1111:1111:1111:9999:9999", 2, 2, 2 * USE_UPPERCASE, 2 * USE_UPPERCASE);
	//testVariantCounts("111a:1111:1111:1111:1111:1111:9999:9999", 2, 2, 2 * USE_UPPERCASE, 2 * USE_UPPERCASE);
	//testVariantCounts("aaaa:b:cccc:dddd:eeee:ffff:aaaa:bbbb", 2, 2, 4 * USE_UPPERCASE, 4 * USE_UPPERCASE);
	//testVariantCounts("aaaa:b:cc:dddd:eeee:ffff:aaaa:bbbb", 2, 2, 4 * USE_UPPERCASE, 8 * USE_UPPERCASE);
	//testVariantCounts("1.2.3.4", 6, 1, 2, 420, 90, 16);
	//testVariantCounts("0.0.0.0", 6, 1, 2, 484, 90, 16);
	//testVariantCounts("1111:2222:aaaa:4444:5555:6666:7070:700a", 2,  1 * USE_UPPERCASE, 1 * USE_UPPERCASE + 2 * USE_UPPERCASE, 1 * USE_UPPERCASE + 2 * USE_UPPERCASE);//this one can be capitalized when mixed
	//testVariantCounts("1111:2222:3333:4444:5555:6666:7070:700a", 2, 2, 1 * USE_UPPERCASE + 2, 1 * USE_UPPERCASE + 2);//this one can only be capitalized when not mixed, so the 2 mixed cases are not doubled

	t.testReverseHostAddress("1.2.0.0/20")
	t.testReverseHostAddress("1.2.3.4")
	t.testReverseHostAddress("1:f000::/20")

	b1 := -1
	t.testFromBytes([]byte{byte(b1), byte(b1), byte(b1), byte(b1)}, "255.255.255.255")
	t.testFromBytes([]byte{1, 2, 3, 4}, "1.2.3.4")
	b := [16]byte{}
	t.testFromBytes(b[:], "::")
	t.testFromBytes([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, "::1")
	t.testFromBytes([]byte{0, 10, 0, 11, 0, 12, 0, 13, 0, 14, 0, 15, 0, 1, 0, 2}, "a:b:c:d:e:f:1:2")

	if t.fullTest && runDNS {
		//t.testResolved("espn.com", "199.181.132.250")
		//t.testResolved("instapundit.com", "72.32.173.45")
		t.testResolved("espn.com", "::ffff:df9:b87b")
		t.testResolved("instapundit.com", "::ffff:ac43:b0af")
	}
	t.testResolved("9.32.237.26", "9.32.237.26")
	t.testResolved("9.70.146.84", "9.70.146.84")

	t.testNormalized("1.2.3.4", "1.2.3.4")
	t.testNormalized("1.2.00.4", "1.2.0.4")
	t.testNormalized("000.2.00.4", "0.2.0.4")
	t.testNormalized("00.2.00.000", "0.2.0.0")
	t.testNormalized("000.000.000.000", "0.0.0.0")

	t.testNormalized("A:B:C:D:E:F:A:B", "a:b:c:d:e:f:a:b")
	t.testNormalized("ABCD:ABCD:CCCC:Dddd:EeEe:fFfF:aAAA:Bbbb", "abcd:abcd:cccc:dddd:eeee:ffff:aaaa:bbbb")
	t.testNormalized("AB12:12CD:CCCC:Dddd:EeEe:fFfF:aAAA:Bbbb", "ab12:12cd:cccc:dddd:eeee:ffff:aaaa:bbbb")
	t.testNormalized("ABCD::CCCC:Dddd:EeEe:fFfF:aAAA:Bbbb", "abcd::cccc:dddd:eeee:ffff:aaaa:bbbb")
	t.testNormalized("::ABCD:CCCC:Dddd:EeEe:fFfF:aAAA:Bbbb", "::abcd:cccc:dddd:eeee:ffff:aaaa:bbbb")
	t.testNormalized("ABCD:ABCD:CCCC:Dddd:EeEe:fFfF:aAAA::", "abcd:abcd:cccc:dddd:eeee:ffff:aaaa::")
	t.testNormalized("::ABCD:Dddd:EeEe:fFfF:aAAA:Bbbb", "::abcd:dddd:eeee:ffff:aaaa:bbbb")
	t.testNormalized("ABCD:ABCD:CCCC:Dddd:fFfF:aAAA::", "abcd:abcd:cccc:dddd:ffff:aaaa::")
	t.testNormalized("::ABCD", "::abcd")
	t.testNormalized("aAAA::", "aaaa::")

	t.testNormalized("0:0:0:0:0:0:0:0", "::")
	t.testNormalized("0000:0000:0000:0000:0000:0000:0000:0000", "::")
	t.testNormalizedMC("0000:0000:0000:0000:0000:0000:0000:0000", "0:0:0:0:0:0:0:0", true, false)
	t.testNormalized("0:0:0:0:0:0:0:1", "::1")
	t.testNormalizedMC("0:0:0:0:0:0:0:1", "0:0:0:0:0:0:0:1", true, false)
	t.testNormalizedMC("0:0:0:0::0:0:1", "0:0:0:0:0:0:0:1", true, false)
	t.testNormalized("0000:0000:0000:0000:0000:0000:0000:0001", "::1")
	t.testNormalized("1:0:0:0:0:0:0:0", "1::")
	t.testNormalized("0001:0000:0000:0000:0000:0000:0000:0000", "1::")
	t.testNormalized("1:0:0:0:0:0:0:1", "1::1")
	t.testNormalized("0001:0000:0000:0000:0000:0000:0000:0001", "1::1")
	t.testNormalized("1:0:0:0::0:0:1", "1::1")
	t.testNormalized("0001::0000:0000:0000:0000:0000:0001", "1::1")
	t.testNormalized("0001:0000:0000:0000:0000:0000::0001", "1::1")
	t.testNormalized("::0000:0000:0000:0000:0000:0001", "::1")
	t.testNormalized("0001:0000:0000:0000:0000:0000::", "1::")
	t.testNormalized("1:0::1", "1::1")
	t.testNormalized("0001:0000::0001", "1::1")
	t.testNormalized("0::", "::")
	t.testNormalized("0000::", "::")
	t.testNormalized("::0", "::")
	t.testNormalized("::0000", "::")
	t.testNormalized("0:0:0:0:1:0:0:0", "::1:0:0:0")
	t.testNormalized("0000:0000:0000:0000:0001:0000:0000:0000", "::1:0:0:0")
	t.testNormalized("0:0:0:1:0:0:0:0", "0:0:0:1::")
	t.testNormalized("0000:0000:0000:0001:0000:0000:0000:0000", "0:0:0:1::")
	t.testNormalized("0:1:0:1:0:1:0:1", "::1:0:1:0:1:0:1")
	t.testNormalized("0000:0001:0000:0001:0000:0001:0000:0001", "::1:0:1:0:1:0:1")
	t.testNormalized("1:1:0:1:0:1:0:1", "1:1::1:0:1:0:1")
	t.testNormalized("0001:0001:0000:0001:0000:0001:0000:0001", "1:1::1:0:1:0:1")

	t.testNormalizedMC("A:B:C:D:E:F:000.000.000.000", "a:b:c:d:e:f::", true, true)
	t.testNormalizedMC("A:B:C:D:E::000.000.000.000", "a:b:c:d:e::", true, true)
	t.testNormalizedMC("::B:C:D:E:F:000.000.000.000", "0:b:c:d:e:f::", true, true)
	t.testNormalizedMC("A:B:C:D::000.000.000.000", "a:b:c:d::", true, true)
	t.testNormalizedMC("::C:D:E:F:000.000.000.000", "::c:d:e:f:0.0.0.0", true, true)
	t.testNormalizedMC("::C:D:E:F:000.000.000.000", "0:0:c:d:e:f:0.0.0.0", true, false)
	t.testNormalizedMC("A:B:C::E:F:000.000.000.000", "a:b:c:0:e:f::", true, true)
	t.testNormalizedMC("A:B::E:F:000.000.000.000", "a:b::e:f:0.0.0.0", true, true)

	t.testNormalizedMC("A:B:C:D:E:F:000.000.000.001", "a:b:c:d:e:f:0.0.0.1", true, true)
	t.testNormalizedMC("A:B:C:D:E::000.000.000.001", "a:b:c:d:e::0.0.0.1", true, true)
	t.testNormalizedMC("::B:C:D:E:F:000.000.000.001", "::b:c:d:e:f:0.0.0.1", true, true)
	t.testNormalizedMC("A:B:C:D::000.000.000.001", "a:b:c:d::0.0.0.1", true, true)
	t.testNormalizedMC("::C:D:E:F:000.000.000.001", "::c:d:e:f:0.0.0.1", true, true)
	t.testNormalizedMC("::C:D:E:F:000.000.000.001", "0:0:c:d:e:f:0.0.0.1", true, false)
	t.testNormalizedMC("A:B:C::E:F:000.000.000.001", "a:b:c::e:f:0.0.0.1", true, true)
	t.testNormalizedMC("A:B::E:F:000.000.000.001", "a:b::e:f:0.0.0.1", true, true)

	t.testNormalizedMC("A:B:C:D:E:F:001.000.000.000", "a:b:c:d:e:f:1.0.0.0", true, true)
	t.testNormalizedMC("A:B:C:D:E::001.000.000.000", "a:b:c:d:e::1.0.0.0", true, true)
	t.testNormalizedMC("::B:C:D:E:F:001.000.000.000", "::b:c:d:e:f:1.0.0.0", true, true)
	t.testNormalizedMC("A:B:C:D::001.000.000.000", "a:b:c:d::1.0.0.0", true, true)
	t.testNormalizedMC("::C:D:E:F:001.000.000.000", "::c:d:e:f:1.0.0.0", true, true)
	t.testNormalizedMC("::C:D:E:F:001.000.000.000", "0:0:c:d:e:f:1.0.0.0", true, false)
	t.testNormalizedMC("A:B:C::E:F:001.000.000.000", "a:b:c::e:f:1.0.0.0", true, true)
	t.testNormalizedMC("A:B::E:F:001.000.000.000", "a:b::e:f:1.0.0.0", true, true)

	t.testCanonical("0001:0000:0000:000F:0000:0000:0001:0001", "1::f:0:0:1:1")    //must be leftmost
	t.testCanonical("0001:0001:0000:000F:0000:0001:0000:0001", "1:1:0:f:0:1:0:1") //but singles not compressed
	t.testMixed("0001:0001:0000:000F:0000:0001:0000:0001", "1:1::f:0:1:0.0.0.1")  //singles compressed in mixed
	t.testCompressed("a.b.c.d", "a.b.c.d")

	t.testCompressed("1:0:1:1:1:1:1:1", "1::1:1:1:1:1:1")
	t.testCanonical("1:0:1:1:1:1:1:1", "1:0:1:1:1:1:1:1")
	t.testMixed("1:0:1:1:1:1:1:1", "1::1:1:1:1:0.1.0.1")

	t.testMixedNoComp("::", "::", "::0.0.0.0")
	t.testMixed("::1", "::0.0.0.1")

	t.testMask("1.2.3.4", "0.0.2.0", "0.0.2.0")
	t.testMask("1.2.3.4", "0.0.1.0", "0.0.1.0")
	t.testMask("A:B:C:D:E:F:A:B", "A:0:C:0:E:0:A:0", "A:0:C:0:E:0:A:0")
	t.testMask("A:B:C:D:E:F:A:B", "FFFF:FFFF:FFFF:FFFF::", "A:B:C:D::")
	t.testMask("A:B:C:D:E:F:A:B", "::FFFF:FFFF:FFFF:FFFF", "::E:F:A:B")

	t.testRadices("255.127.254.2", "11111111.1111111.11111110.10", 2)
	t.testRadices("2.254.127.255", "10.11111110.1111111.11111111", 2)
	t.testRadices("1.12.4.8", "1.1100.100.1000", 2)
	t.testRadices("8.4.12.1", "1000.100.1100.1", 2)
	t.testRadices("10.5.10.5", "1010.101.1010.101", 2)
	t.testRadices("5.10.5.10", "101.1010.101.1010", 2)
	t.testRadices("0.1.0.1", "0.1.0.1", 2)
	t.testRadices("1.0.1.0", "1.0.1.0", 2)

	t.testRadices("255.127.254.2", "513.241.512.2", 7)
	t.testRadices("2.254.127.255", "2.512.241.513", 7)
	t.testRadices("0.1.0.1", "0.1.0.1", 7)
	t.testRadices("1.0.1.0", "1.0.1.0", 7)

	t.testRadices("255.127.254.2", "120.87.11e.2", 15)
	t.testRadices("2.254.127.255", "2.11e.87.120", 15)
	t.testRadices("0.1.0.1", "0.1.0.1", 15)
	t.testRadices("1.0.1.0", "1.0.1.0", 15)

	var ninePrefs [9]ipaddr.PrefixLen

	t.testInsertAndAppendPrefs("a:b:c:d:e:f:aa:bb", "1:2:3:4:5:6:7:8", ninePrefs[:])
	t.testInsertAndAppendPrefs("1.2.3.4", "5.6.7.8", ninePrefs[:5])

	t.testReplace("a:b:c:d:e:f:aa:bb", "1:2:3:4:5:6:7:8")
	t.testReplace("1.2.3.4", "5.6.7.8")

	//testSQLMatching();

	t.testInvalidIpv4Values()

	t.testInvalidIpv6Values()

	t.testIPv4Values([]int{1, 2, 3, 4}, "16909060")
	t.testIPv4Values([]int{0, 0, 0, 0}, "0")
	t.testIPv4Values([]int{255, 255, 255, 255}, strconv.FormatUint(0xffffffff, 10))

	t.testIPv6Values([]int{1, 2, 3, 4, 5, 6, 7, 8}, "5192455318486707404433266433261576")
	t.testIPv6Values([]int{0, 0, 0, 0, 0, 0, 0, 0}, "0")
	t.testIPv6Values([]int{0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff}, one28().String())

	t.testSub("10.0.0.0/22", "10.0.1.0/24", []string{"10.0.0.0/24", "10.0.2.0/23"})

	t.testIntersect("1:1::/32", "1:1:1:1:1:1:1:1", "1:1:1:1:1:1:1:1") //1:1:0:0:0:0:0:0/32
	t.testIntersectLowest("1:1::/32", "1:1::/16", "1:1::/32", true)   //1:1::/16 1:1:0:0:0:0:0:0/32
	t.testIntersect("1:1::/32", "1:1::/48", "1:1::/48")
	t.testIntersect("1:1::/32", "1:1::/64", "1:1::/64")
	t.testIntersect("1:1::/32", "1:1:2:2::/64", "1:1:2:2::/64")
	t.testIntersect("1:1::/32", "1:0:2:2::/64", "")
	t.testIntersect("10.0.0.0/22", "10.0.0.0/24", "10.0.0.0/24") //[10.0.0.0/24, 10.0.2.0/23]
	t.testIntersect("10.0.0.0/22", "10.0.1.0/24", "10.0.1.0/24") //[10.0.1-3.0/24]

	t.testToPrefixBlock("1:3::3:4", "1:3::3:4")
	t.testToPrefixBlock("1.3.3.4", "1.3.3.4")

	t.testMaxHost("1.2.3.4", "255.255.255.255/0")
	t.testMaxHost("1.2.255.255/16", "1.2.255.255/16")

	t.testMaxHost("1:2:3:4:5:6:7:8", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/0")
	t.testMaxHost("1:2:ffff:ffff:ffff:ffff:ffff:ffff/64", "1:2:ffff:ffff:ffff:ffff:ffff:ffff/64")
	t.testMaxHost("1:2:3:4:5:6:7:8/64", "1:2:3:4:ffff:ffff:ffff:ffff/64")
	t.testMaxHost("1:2:3:4:5:6:7:8/128", "1:2:3:4:5:6:7:8/128")

	t.testZeroHost("1.2.3.4", "0.0.0.0/0")
	t.testZeroHost("1.2.0.0/16", "1.2.0.0/16")

	t.testZeroHost("1:2:3:4:5:6:7:8", "::/0")
	t.testZeroHost("1:2::/64", "1:2::/64")
	t.testZeroHost("1:2:3:4:5:6:7:8/64", "1:2:3:4::/64")
	t.testZeroHost("1:2:3:4:5:6:7:8/128", "1:2:3:4:5:6:7:8/128")

	t.testZeroNetwork("1.2.3.4", "0.0.0.0")
	t.testZeroNetwork("1.2.0.0/16", "0.0.0.0/16")

	t.testZeroNetwork("1:2:3:4:5:6:7:8", "::")
	t.testZeroNetwork("1:2::/64", "::/64")
	t.testZeroNetwork("1:2:3:4:5:6:7:8/64", "::5:6:7:8/64")
	t.testZeroNetwork("1:2:3:4:5:6:7:8/128", "::/128")

	t.testIsPrefixBlock("1.2.3.4", false, false)
	t.testIsPrefixBlock("1.2.3.4/16", false, false)
	t.testIsPrefixBlock("1.2.0.0/16", true, true)
	t.testIsPrefixBlock("1.2.3.4/0", false, false)
	t.testIsPrefixBlock("1.2.3.3/31", false, false)
	t.testIsPrefixBlock("1.2.3.4/31", true, true)
	t.testIsPrefixBlock("1.2.3.4/32", true, true)

	t.testPrefixBlocks("1.2.3.4", 8, false, false)
	t.testPrefixBlocks("1.2.3.4/16", 8, false, false)
	t.testPrefixBlocks("1.2.0.0/16", 8, false, false)
	t.testPrefixBlocks("1.2.3.4/0", 8, false, false)
	t.testPrefixBlocks("1.2.3.4/8", 8, false, false)
	t.testPrefixBlocks("1.2.3.4/31", 8, false, false)
	t.testPrefixBlocks("1.2.3.4/32", 8, false, false)

	t.testPrefixBlocks("1.2.3.4", 24, false, false)
	t.testPrefixBlocks("1.2.3.4/16", 24, false, false)
	t.testPrefixBlocks("1.2.0.0/16", 24, true, false)
	t.testPrefixBlocks("1.2.3.4/0", 24, false, false)
	t.testPrefixBlocks("1.2.3.4/24", 24, false, false)
	t.testPrefixBlocks("1.2.3.4/31", 24, false, false)
	t.testPrefixBlocks("1.2.3.4/32", 24, false, false)

	t.testIsPrefixBlock("a:b:c:d:e:f:a:b", false, false)
	t.testIsPrefixBlock("a:b:c:d:e:f:a:b/64", false, false)
	t.testIsPrefixBlock("a:b:c:d::/64", true, true)
	t.testIsPrefixBlock("a:b:c:d:e::/64", false, false)
	t.testIsPrefixBlock("a:b:c::/64", true, true)
	t.testIsPrefixBlock("a:b:c:d:e:f:a:b/0", false, false)
	t.testIsPrefixBlock("a:b:c:d:e:f:a:b/127", false, false)
	t.testIsPrefixBlock("a:b:c:d:e:f:a:b/128", true, true)

	t.testPrefixBlocks("a:b:c:d:e:f:a:b", 0, false, false)
	t.testPrefixBlocks("a:b:c:d:e:f:a:b/64", 0, false, false)
	t.testPrefixBlocks("a:b:c:d::/64", 0, false, false)
	t.testPrefixBlocks("a:b:c:d:e::/64", 0, false, false)
	t.testPrefixBlocks("a:b:c::/64", 0, false, false)
	t.testPrefixBlocks("a:b:c:d:e:f:a:b/0", 0, false, false)
	t.testPrefixBlocks("a:b:c:d:e:f:a:b/127", 0, false, false)
	t.testPrefixBlocks("a:b:c:d:e:f:a:b/128", 0, false, false)

	t.testPrefixBlocks("a:b:c:d:e:f:a:b", 63, false, false)
	t.testPrefixBlocks("a:b:c:d:e:f:a:b/64", 63, false, false)
	t.testPrefixBlocks("a:b:c:d::/64", 63, false, false)
	t.testPrefixBlocks("a:b:c:d:e::/64", 63, false, false)
	t.testPrefixBlocks("a:b:c::/64", 63, false, false)
	t.testPrefixBlocks("a:b:c:d:e:f:a:b/0", 63, false, false)
	t.testPrefixBlocks("a:b:c:d:e:f:a:b/127", 63, false, false)
	t.testPrefixBlocks("a:b:c:d:e:f:a:b/128", 63, false, false)

	t.testPrefixBlocks("a:b:c:d:e:f:a:b", 64, false, false)
	t.testPrefixBlocks("a:b:c:d:e:f:a:b/64", 64, false, false)
	t.testPrefixBlocks("a:b:c:d::/64", 64, true, true)
	t.testPrefixBlocks("a:b:c:d:e::/64", 64, false, false)
	t.testPrefixBlocks("a:b:c::/64", 64, true, true)
	t.testPrefixBlocks("a:b:c:d:e:f:a:b/0", 64, false, false)
	t.testPrefixBlocks("a:b:c:d:e:f:a:b/127", 64, false, false)
	t.testPrefixBlocks("a:b:c:d:e:f:a:b/128", 64, false, false)

	t.testPrefixBlocks("a:b:c:d:e:f:a:b", 65, false, false)
	t.testPrefixBlocks("a:b:c:d:e:f:a:b/64", 65, false, false)
	t.testPrefixBlocks("a:b:c:d::/64", 65, true, false)
	t.testPrefixBlocks("a:b:c:d:e::/64", 65, false, false)
	t.testPrefixBlocks("a:b:c::/64", 65, true, false)
	t.testPrefixBlocks("a:b:c:d:e:f:a:b/0", 65, false, false)
	t.testPrefixBlocks("a:b:c:d:e:f:a:b/127", 65, false, false)
	t.testPrefixBlocks("a:b:c:d:e:f:a:b/128", 65, false, false)

	t.testPrefixBlocks("a:b:c:d:e:f:a:b", 128, true, true)
	t.testPrefixBlocks("a:b:c:d:e:f:a:b/64", 128, true, !false)
	t.testPrefixBlocks("a:b:c:d::/64", 128, true, !true)
	t.testPrefixBlocks("a:b:c:d:e::/64", 128, true, !false)
	t.testPrefixBlocks("a:b:c::/64", 128, true, !true)
	t.testPrefixBlocks("a:b:c:d:e:f:a:b/0", 128, true, !false)
	t.testPrefixBlocks("a:b:c:d:e:f:a:b/127", 128, true, !false)
	t.testPrefixBlocks("a:b:c:d:e:f:a:b/128", 128, true, true)

	t.testSplitBytes("1.2.3.4")
	t.testSplitBytes("1.2.3.4/16")
	t.testSplitBytes("1.2.3.4/0")
	t.testSplitBytes("1.2.3.4/32")
	t.testSplitBytes("ffff:2:3:4:eeee:dddd:cccc:bbbb")
	t.testSplitBytes("ffff:2:3:4:eeee:dddd:cccc:bbbb/64")
	t.testSplitBytes("ffff:2:3:4:eeee:dddd:cccc:bbbb/0")
	t.testSplitBytes("ffff:2:3:4:eeee:dddd:cccc:bbbb/128")

	t.testByteExtension("255.255.255.255", [][]byte{
		{0, 0, 255, 255, 255, 255},
		{0, 255, 255, 255, 255},
		{255, 255, 255, 255},
	})

	t.testByteExtension("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", [][]byte{
		{0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		{0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		{0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		{0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
	})
	t.testByteExtension("0.0.0.255", [][]byte{
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 255},
		{0, 0, 0, 0, 0, 0, 0, 0, 255},
		{0, 0, 0, 0, 255},
		{0, 0, 0, 255},
	})
	t.testByteExtension("::ff", [][]byte{
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff},
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff},
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff},
		{0, 0xff},
		{0xff},
	})
	t.testByteExtension("0.0.0.127", [][]byte{
		{0, 0, 0, 0, 0, 127},
		{0, 0, 0, 0, 127},
		{0, 0, 0, 127},
		{0, 127},
		{127},
	})
	t.testByteExtension("::7f", [][]byte{
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 127},
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 127},
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 127},
		{0, 0, 127},
		{0, 127},
		{127},
	})
	t.testByteExtension("255.255.255.128", [][]byte{
		{0, 0, 0, 0, 0, 0, 255, 255, 255, 128},
		{0, 255, 255, 255, 128},
		{0, 0, 255, 255, 255, 128},
		{0, 255, 255, 255, 128},
		{255, 255, 255, 128},
	})
	t.testByteExtension("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ff80", [][]byte{
		{0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x80},
		{0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x80},
		{0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x80},
		{0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x80},
		{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x80},
	})
	t.testByteExtension("ffff:ffff:ffff:ffff:ffff:ffff:ffff:8000", [][]byte{
		{0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x80, 0},
		{0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x80, 0},
		{0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x80, 0},
		{0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x80, 0},
		{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x80, 0},
	})
	t.testByteExtension("1.2.3.4", [][]byte{
		{1, 2, 3, 4},
		{0, 1, 2, 3, 4},
	})
	t.testByteExtension("102:304:506:708:90a:b0c:d0e:f10", [][]byte{
		{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
	})

	//TODO LATER when we have large divisions
	//testLargeDivs(new byte[][] {
	//	new byte[] {1, 2, 3, 4, 5},
	//	new byte[] {6, 7, 8, 9, 10, 11, 12},
	//	new byte[] {13, 14, 15, 16}
	//});
	//testLargeDivs(new byte[][] {
	//	new byte[] {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	//});
	//testLargeDivs(new byte[][] {
	//	new byte[] {1, 2, 3, 4, 5},
	//	//new byte[] {},
	//	new byte[] {6, 7, 8, 9, 10, 11, 12},
	//	new byte[] {13, 14, 15, 16}
	//});
	//testLargeDivs(new byte[][] {
	//	new byte[] {1}, new byte[] {2}, new byte[] {3}, new byte[] {4}, new byte[] {5},
	//	new byte[] {6, 7}, new byte[] {8}, new byte[] {9}, new byte[] {10}, new byte[] {11}, new byte[] {12},
	//	new byte[] {13}, new byte[] {14}, new byte[] {15}, new byte[] {16}
	//});
	//testLargeDivs(new byte[][] {
	//	new byte[] {1},
	//	new byte[] {2, 3},
	//	new byte[] {4}
	//});

	t.testIncrement("1.2.3.4", 0, "1.2.3.4")
	t.testIncrement("1.2.3.4", 1, "1.2.3.5")
	t.testIncrement("1.2.3.4", -1, "1.2.3.3")
	t.testIncrement("1.2.3.4", -4, "1.2.3.0")
	t.testIncrement("1.2.3.4", -5, "1.2.2.255")
	t.testIncrement("0.0.0.4", -5, "")
	t.testIncrement("1.2.3.4", 251, "1.2.3.255")
	t.testIncrement("1.2.3.4", 252, "1.2.4.0")
	t.testIncrement("1.2.3.4", 256, "1.2.4.4")
	t.testIncrement("1.2.3.4", 256, "1.2.4.4")
	t.testIncrement("1.2.3.4", 65536, "1.3.3.4")
	t.testIncrement("1.2.3.4", 16777216, "2.2.3.4")
	t.testIncrement("1.2.3.4", 4261412864, "255.2.3.4")
	t.testIncrement("1.2.3.4", 4278190080, "")
	t.testIncrement("1.2.3.4", 4278058236, "")
	t.testIncrement("1.2.3.4", 4278058237, "")
	t.testIncrement("1.2.3.4", 4278058235, "255.255.255.255")
	t.testIncrement("255.0.0.4", -4278190084, "0.0.0.0")
	t.testIncrement("255.0.0.4", -4278190085, "")

	t.testIncrement("ffff:ffff:ffff:ffff:f000::0", 1, "ffff:ffff:ffff:ffff:f000::1")
	t.testIncrement("ffff:ffff:ffff:ffff:f000::0", -1, "ffff:ffff:ffff:ffff:efff:ffff:ffff:ffff")
	t.testIncrement("ffff:ffff:ffff:ffff:8000::", math.MinInt64, "ffff:ffff:ffff:ffff::")
	t.testIncrement("ffff:ffff:ffff:ffff:7fff:ffff:ffff:ffff", math.MinInt64, "ffff:ffff:ffff:fffe:ffff:ffff:ffff:ffff")
	t.testIncrement("ffff:ffff:ffff:ffff:7fff:ffff:ffff:fffe", math.MinInt64, "ffff:ffff:ffff:fffe:ffff:ffff:ffff:fffe")
	t.testIncrement("::8000:0:0:0", math.MinInt64, "::")
	t.testIncrement("::7fff:ffff:ffff:ffff", math.MinInt64, "")
	t.testIncrement("::7fff:ffff:ffff:ffff", math.MinInt64, "")
	t.testIncrement("::7fff:ffff:ffff:fffe", math.MinInt64, "")
	t.testIncrement("ffff:ffff:ffff:ffff:8000::0", math.MaxInt64, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")
	t.testIncrement("ffff:ffff:ffff:ffff:8000::1", math.MaxInt64, "")
	t.testIncrement("::1", 1, "::2")
	t.testIncrement("::1", 0, "::1")
	t.testIncrement("::1", -1, "::")
	t.testIncrement("::1", -2, "")
	t.testIncrement("::2", 1, "::3")
	t.testIncrement("::2", -1, "::1")
	t.testIncrement("::2", -2, "::")
	t.testIncrement("::2", -3, "")

	t.testIncrement("1::1", 0, "1::1")
	t.testIncrement("1::1", 1, "1::2")
	t.testIncrement("1::1", -1, "1::")
	t.testIncrement("1::1", -2, "::ffff:ffff:ffff:ffff:ffff:ffff:ffff")
	t.testIncrement("1::2", 1, "1::3")
	t.testIncrement("1::2", -1, "1::1")
	t.testIncrement("1::2", -2, "1::")
	t.testIncrement("1::2", -3, "::ffff:ffff:ffff:ffff:ffff:ffff:ffff")

	t.testIncrement("::fffe", 2, "::1:0")
	t.testIncrement("::ffff", 2, "::1:1")
	t.testIncrement("::1:ffff", 2, "::2:1")
	t.testIncrement("::1:ffff", -2, "::1:fffd")
	t.testIncrement("::1:ffff", -0x10000, "::ffff")
	t.testIncrement("::1:ffff", -0x10001, "::fffe")

	t.testLeadingZeroAddr("00.1.2.3", true)
	t.testLeadingZeroAddr("1.00.2.3", true)
	t.testLeadingZeroAddr("1.2.00.3", true)
	t.testLeadingZeroAddr("1.2.3.00", true)
	t.testLeadingZeroAddr("01.1.2.3", true)
	t.testLeadingZeroAddr("1.01.2.3", true)
	t.testLeadingZeroAddr("1.2.01.3", true)
	t.testLeadingZeroAddr("1.2.3.01", true)
	t.testLeadingZeroAddr("0.1.2.3", false)
	t.testLeadingZeroAddr("1.0.2.3", false)
	t.testLeadingZeroAddr("1.2.0.3", false)
	t.testLeadingZeroAddr("1.2.3.0", false)

	// octal and hex addresses are not allowed when we disallow leading zeros.
	// if we allow leading zeros, the inet aton settings determine if hex is allowed,
	// or whether leading zeros are interpreted as octal.
	// We can also disallow octal leading zeros, which are extra zeros after the 0x for hex or the 0 for octal.
	// We never allow 00x regardless of the settings.
	// Note that having a flag to disallow leading zeros and then seeing 1.02.3.4 being allowed, that would be annoying, so we do not do that anymore.
	t.testInetAtonLeadingZeroAddr("11.1.2.3", false, false, false) // boolean are (a) has a leading zero (b) has a leading zero following 0x or 0 and (c) the leading zeros are octal (not hex)
	t.testInetAtonLeadingZeroAddr("0.1.2.3", false, false, false)
	t.testInetAtonLeadingZeroAddr("1.0.2.3", false, false, false)
	t.testInetAtonLeadingZeroAddr("1.2.0.3", false, false, false)
	t.testInetAtonLeadingZeroAddr("1.2.3.0", false, false, false)
	t.testInetAtonLeadingZeroAddr("0x1.1.2.3", true, false, false)
	t.testInetAtonLeadingZeroAddr("1.0x1.2.3", true, false, false)
	t.testInetAtonLeadingZeroAddr("1.2.0x1.3", true, false, false)
	t.testInetAtonLeadingZeroAddr("1.2.3.0x1", true, false, false)
	t.testInetAtonLeadingZeroAddr("0x01.1.2.3", true, true, false)
	t.testInetAtonLeadingZeroAddr("1.0x01.2.3", true, true, false)
	t.testInetAtonLeadingZeroAddr("1.2.0x01.3", true, true, false)
	t.testInetAtonLeadingZeroAddr("1.2.3.0x01", true, true, false)
	t.testInetAtonLeadingZeroAddr("01.1.2.3", true, false, true)
	t.testInetAtonLeadingZeroAddr("1.01.2.3", true, false, true)
	t.testInetAtonLeadingZeroAddr("1.2.01.3", true, false, true)
	t.testInetAtonLeadingZeroAddr("1.2.3.01", true, false, true)
	t.testInetAtonLeadingZeroAddr("010.1.2.3", true, false, true)
	t.testInetAtonLeadingZeroAddr("1.010.2.3", true, false, true)
	t.testInetAtonLeadingZeroAddr("1.2.010.3", true, false, true)
	t.testInetAtonLeadingZeroAddr("1.2.3.010", true, false, true)
	t.testInetAtonLeadingZeroAddr("001.1.2.3", true, true, true)
	t.testInetAtonLeadingZeroAddr("1.001.2.3", true, true, true)
	t.testInetAtonLeadingZeroAddr("1.2.001.3", true, true, true)
	t.testInetAtonLeadingZeroAddr("1.2.3.001", true, true, true)

	t.testLeadingZeroAddr("00:1:2:3::", true)
	t.testLeadingZeroAddr("1:00:2:3::", true)
	t.testLeadingZeroAddr("1:2:00:3::", true)
	t.testLeadingZeroAddr("1:2:3:00::", true)
	t.testLeadingZeroAddr("01:1:2:3::", true)
	t.testLeadingZeroAddr("1:01:2:3::", true)
	t.testLeadingZeroAddr("1:2:01:3::", true)
	t.testLeadingZeroAddr("1:2:3:01::", true)
	t.testLeadingZeroAddr("0:1:2:3::", false)
	t.testLeadingZeroAddr("1:0:2:3::", false)
	t.testLeadingZeroAddr("1:2:0:3::", false)
	t.testLeadingZeroAddr("1:2:3:0::", false)

	//a b x y
	t.testRangeJoin("1.2.3.4", "1.2.4.3", "1.2.4.5", "1.2.5.6", "", "")
	t.testRangeIntersect("1.2.3.4", "1.2.4.3", "1.2.4.5", "1.2.5.6", "", "")
	t.testRangeSubtract("1.2.3.4", "1.2.4.3", "1.2.4.5", "1.2.5.6", "1.2.3.4", "1.2.4.3")

	t.testRangeExtend("1.2.3.4", "1.2.4.3", "1.2.4.5", "1.2.5.6", "1.2.3.4", "1.2.5.6")
	t.testRangeExtend("1.2.3.4", "", "1.2.5.6", "", "1.2.3.4", "1.2.5.6")
	t.testRangeExtend("1.2.3.4", "1.2.4.3", "1.2.5.6", "", "1.2.3.4", "1.2.5.6")

	//a x b y
	t.testRangeJoin("1.2.3.4", "1.2.4.5", "1.2.4.3", "1.2.5.6", "1.2.3.4", "1.2.5.6")
	t.testRangeIntersect("1.2.3.4", "1.2.4.5", "1.2.4.3", "1.2.5.6", "1.2.4.3", "1.2.4.5")
	t.testRangeSubtract("1.2.3.4", "1.2.4.5", "1.2.4.3", "1.2.5.6", "1.2.3.4", "1.2.4.2")

	t.testRangeExtend("1.2.3.4", "1.2.4.5", "1.2.4.3", "1.2.5.6", "1.2.3.4", "1.2.5.6")
	t.testRangeExtend("1.2.3.4", "", "1.2.5.6", "", "1.2.3.4", "1.2.5.6")
	t.testRangeExtend("1.2.3.4", "1.2.4.5", "1.2.5.6", "", "1.2.3.4", "1.2.5.6")

	//a x y b
	t.testRangeJoin("1.2.3.4", "1.2.5.6", "1.2.4.3", "1.2.4.5", "1.2.3.4", "1.2.5.6")
	t.testRangeIntersect("1.2.3.4", "1.2.5.6", "1.2.4.3", "1.2.4.5", "1.2.4.3", "1.2.4.5")
	t.testRangeSubtract("1.2.3.4", "1.2.5.6", "1.2.4.3", "1.2.4.5", "1.2.3.4", "1.2.4.2", "1.2.4.6", "1.2.5.6")

	t.testRangeExtend("1.2.3.4", "1.2.5.6", "1.2.4.3", "1.2.4.5", "1.2.3.4", "1.2.5.6")
	t.testRangeExtend("1.2.3.4", "1.2.5.6", "1.2.4.3", "", "1.2.3.4", "1.2.5.6")

	//a b x y
	t.testRangeJoin("1:2:3:4::", "1:2:4:3::", "1:2:4:5::", "1:2:5:6::", "", "")
	t.testRangeIntersect("1:2:3:4::", "1:2:4:3::", "1:2:4:5::", "1:2:5:6::", "", "")
	t.testRangeSubtract("1:2:3:4::", "1:2:4:3::", "1:2:4:5::", "1:2:5:6::", "1:2:3:4::", "1:2:4:3::")

	t.testRangeExtend("1:2:3:4::", "1:2:4:3::", "1:2:4:5::", "1:2:5:6::", "1:2:3:4::", "1:2:5:6::")
	t.testRangeExtend("1:2:3:4::", "", "1:2:5:6::", "", "1:2:3:4::", "1:2:5:6::")
	t.testRangeExtend("1:2:3:4::", "1:2:4:3::", "1:2:5:6::", "", "1:2:3:4::", "1:2:5:6::")

	//a x b y
	t.testRangeJoin("1:2:3:4::", "1:2:4:5::", "1:2:4:3::", "1:2:5:6::", "1:2:3:4::", "1:2:5:6::")
	t.testRangeIntersect("1:2:3:4::", "1:2:4:5::", "1:2:4:3::", "1:2:5:6::", "1:2:4:3::", "1:2:4:5::")
	t.testRangeSubtract("1:2:3:4::", "1:2:4:5::", "1:2:4:3::", "1:2:5:6::", "1:2:3:4::", "1:2:4:2:ffff:ffff:ffff:ffff")

	t.testRangeExtend("1:2:3:4::", "1:2:4:5::", "1:2:4:3::", "1:2:5:6::", "1:2:3:4::", "1:2:5:6::")
	t.testRangeExtend("1:2:3:4::", "", "1:2:5:6::", "", "1:2:3:4::", "1:2:5:6::")
	t.testRangeExtend("1:2:3:4::", "1:2:4:5::", "1:2:5:6::", "", "1:2:3:4::", "1:2:5:6::")

	//a x y b
	t.testRangeJoin("1:2:3:4::", "1:2:5:6::", "1:2:4:3::", "1:2:4:5::", "1:2:3:4::", "1:2:5:6::")
	t.testRangeIntersect("1:2:3:4::", "1:2:5:6::", "1:2:4:3::", "1:2:4:5::", "1:2:4:3::", "1:2:4:5::")
	t.testRangeSubtract("1:2:3:4::", "1:2:5:6::", "1:2:4:3::", "1:2:4:5::", "1:2:3:4::", "1:2:4:2:ffff:ffff:ffff:ffff", "1:2:4:5::1", "1:2:5:6::")

	t.testRangeExtend("1:2:3:4::", "1:2:5:6::", "1:2:4:3::", "1:2:4:5::", "1:2:3:4::", "1:2:5:6::")
	t.testRangeExtend("1:2:5:6::", "", "1:2:3:4::", "", "1:2:3:4::", "1:2:5:6::")
	t.testRangeExtend("1:2:5:6::", "", "1:2:3:4::", "1:2:4:5::", "1:2:3:4::", "1:2:5:6::")

	t.testAddressStringRange1("1.2.3.4", []interface{}{1, 2, 3, 4})
	t.testAddressStringRange1("a:b:cc:dd:e:f:1.2.3.4", []interface{}{0xa, 0xb, 0xcc, 0xdd, 0xe, 0xf, 1, 2, 3, 4})
	t.testAddressStringRange1("1:2:4:5:6:7:8:f", []interface{}{1, 2, 4, 5, 6, 7, 8, 0xf})
	t.testAddressStringRange1("1:2:4:5::", []interface{}{1, 2, 4, 5, 0})
	t.testAddressStringRange1("::1:2:4:5", []interface{}{0, 1, 2, 4, 5})
	t.testAddressStringRange1("1:2:4:5::6", []interface{}{1, 2, 4, 5, 0, 6})

	t.testAddressStringRange1("a:b:c::cc:d:1.255.3.128", []interface{}{0xa, 0xb, 0xc, 0x0, 0xcc, 0xd, 1, 255, 3, 128}) //[a, b, c, 0-ffff, cc, d, e, f]
	t.testAddressStringRange1("a::cc:d:1.255.3.128", []interface{}{0xa, 0x0, 0xcc, 0xd, 1, 255, 3, 128})               //[a, 0-ffffffffffff, cc, d, e, f]
	t.testAddressStringRange1("::cc:d:1.255.3.128", []interface{}{0x0, 0xcc, 0xd, 1, 255, 3, 128})                     //[0-ffffffffffffffff, cc, d, e, f]

	// with prefix lengths

	p15 := cacheTestBits(15)
	p16 := cacheTestBits(16)
	p31 := cacheTestBits(31)
	p63 := cacheTestBits(63)
	p64 := cacheTestBits(64)
	p127 := cacheTestBits(127)

	t.testAddressStringRange("1.2.3.4/31", []interface{}{1, 2, 3, []uint{4, 5}}, p31)
	t.testAddressStringRange("a:b:cc:dd:e:f:1.2.3.4/127", []interface{}{0xa, 0xb, 0xcc, 0xdd, 0xe, 0xf, 1, 2, 3, []uint{4, 5}}, p127)
	t.testAddressStringRange("1:2:4:5::/64", []interface{}{1, 2, 4, 5, []*big.Int{bigZeroConst(), setBigString("ffffffffffffffff", 16)}}, p64)

	t.testAddressStringRange("1.2.3.4/15", []interface{}{1, 2, 3, 4}, p15)
	t.testAddressStringRange("a:b:cc:dd:e:f:1.2.3.4/63", []interface{}{0xa, 0xb, 0xcc, 0xdd, 0xe, 0xf, 1, 2, 3, 4}, p63)
	t.testAddressStringRange("1:2:4:5::/63", []interface{}{1, 2, 4, 5, 0}, p63)
	t.testAddressStringRange("::cc:d:1.255.3.128/16", []interface{}{0x0, 0xcc, 0xd, 1, 255, 3, 128}, p16) //[0-ffffffffffffffff, cc, d, e, f]

	// with masks

	t.testSubnetStringRange2("::aaaa:bbbb:cccc/abcd:dcba:aaaa:bbbb:cccc::dddd",
		"::cccc", "::cccc", []interface{}{0, 0, 0, 0xcccc})
	t.testSubnetStringRange2("::aaaa:bbbb:cccc/abcd:abcd:dcba:aaaa:bbbb:cccc::dddd",
		"::8888:0:cccc", "::8888:0:cccc", []interface{}{0, 0x8888, 0, 0xcccc})
	t.testSubnetStringRange2("aaaa:bbbb::cccc/abcd:dcba:aaaa:bbbb:cccc::dddd",
		"aa88:98ba::cccc", "aa88:98ba::cccc", []interface{}{0xaa88, 0x98ba, 0, 0xcccc})
	t.testSubnetStringRange2("aaaa:bbbb::/abcd:dcba:aaaa:bbbb:cccc::dddd",
		"aa88:98ba::", "aa88:98ba::", []interface{}{0xaa88, 0x98ba, 0})

	t.testSubnetStringRange1("3.3.3.3/175.80.81.83",
		"3.0.1.3", "3.0.1.3",
		[]interface{}{3, 0, 1, 3},
		nil, true)
}

func one28() *big.Int {
	sixty4 := new(big.Int).SetUint64(0xffffffffffffffff)
	sixtyFour := new(big.Int).Set(sixty4)
	sixty4.Or(sixtyFour.Lsh(sixtyFour, 64), sixty4)
	return sixty4
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
	if !equivPrefix.Equal(equiv) {
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
			//fmt.Printf("%v %v %v\n", direct, directAddress.ToNormalizedWildcardString(), prefixed.ToNormalizedWildcardString())
			isFailed = !directAddress.Equal(prefixed) // prefixed is prefix block, directAddress is not
		}
		if isFailed {
			t.addFailure(newIPAddrFailure("failed: prefix expected: "+direct.String(), prefixed))
		} else {
			minPref := h1.GetMinPrefixLenForBlock()
			if minPref != minPrefix {
				t.addFailure(newIPAddrFailure("failed: prefix expected: "+bitCountToString(minPrefix)+" prefix got: "+bitCountToString(minPref), h1))
			} else {
				minPrefixed := h1.AssignMinPrefixForBlock()
				bareHost := host
				index := strings.Index(host, "/")
				if index >= 0 {
					bareHost = host[:index]
				}
				direct = t.createAddress(bareHost + "/" + bitCountToString(minPrefix))
				directAddress = direct.GetAddress()
				if h1.IsPrefixed() && h1.IsPrefixBlock() {
					directAddress = makePrefixSubnet(directAddress)
				}
				//if equiv == nil {
				//	if prefixed != nil {
				//		t.addFailure(newIPAddrFailure("failed: prefix expected: "+direct.String(), minPrefixed))
				//	}
				//} else if !directAddress.Equal(minPrefixed) {
				//	t.addFailure(newIPAddrFailure("failed: prefix expected: "+direct.String(), minPrefixed))
				//}
				if !directAddress.Equal(minPrefixed) {
					// orig "1:2:*::/64" failed: expected match between: 1:2:*::*:*:*/64 and 1:2:*::/64
					t.addFailure(newIPAddrFailure("failed: expected match between: "+directAddress.String()+" and "+minPrefixed.String(), minPrefixed))
				}
			}
		}
	}
	t.incrementTestCount()
}

//var counter int

func (t ipAddressTester) testSubnet(addressStr, maskStr string, prefix ipaddr.BitCount,
	normalizedPrefixSubnetString,
	normalizedSubnetString,
	normalizedPrefixString string) {
	//counter++
	//fmt.Printf("test %v\n", counter)
	t.testHostAddress(addressStr)
	//isValidWithPrefix := normalizedPrefixSubnetString != ""
	isValidMask := normalizedSubnetString != ""
	str := t.createAddress(addressStr)
	maskString := t.createAddress(maskStr)
	//try {
	value := str.GetAddress()
	originalPrefix := value.GetNetworkPrefixLen()
	//try {
	mask := maskString.GetAddress()
	var subnet3 *ipaddr.IPAddress
	if originalPrefix == nil || originalPrefix.Len() > prefix {
		var perr error
		subnet3, perr = value.SetPrefixLenZeroed(prefix)
		if perr != nil {
			t.addFailure(newIPAddrFailure("testSubnet failed setting prefix "+bitCountToString(prefix)+" to: "+value.String()+" error: "+perr.Error(), subnet3))
		}
	} else {
		subnet3 = value
	}
	string3 := subnet3.ToNormalizedString()
	if string3 != normalizedPrefixString {
		t.addFailure(newIPAddrFailure("testSubnet failed normalizedPrefixString: "+string3+" expected: "+normalizedPrefixString, subnet3))
	} else {
		//try {
		//IPAddress subnet = value.maskNetwork(mask, prefix);
		//if(!isValidWithPrefix) {
		//	addFailure(new Failure("testSubnet failed to throw with mask " + mask + " and prefix " + prefix, value));
		//} else {
		//	 string := subnet.toNormalizedString();
		//	if(!string.equals(normalizedPrefixSubnetString)) {
		//		addFailure(new Failure("testSubnet failed: " + string + " expected: " + normalizedPrefixSubnetString, subnet));
		//		//0.0.0.0/16 is normalizedPrefixSubnetString and 0.0.0-127.*/16 is string
		//		//1.2.0.0/17 becomes 1.2.0.0/16 after we apply prefix length.
		//		//Then 1.2.0.0/17 is network-masked with 0.0.255.255 and prefix 16.
		//		// So that becomes 0.0.0-127.*/16.
		//		// That used to be 0.0.0.0/16
		//	} else {
		//try {
		//fmt.Printf("masking %v with %v\n", value, mask) // masking ::/8 with ffff::
		subnet2, err := value.Mask(mask) //here?
		if isValidMask && err != nil {
			t.addFailure(newIPAddrFailure("testSubnet errored with mask "+mask.String(), value))
		} else if !isValidMask && err == nil {
			t.addFailure(newIPAddrFailure("testSubnet failed to error with mask "+mask.String(), value))
		} else if isValidMask {
			subnet2 = subnet2.WithoutPrefixLen()
			string2 := subnet2.ToNormalizedString()
			if string2 != normalizedSubnetString {
				t.addFailure(newIPAddrFailure("testSubnet failed: "+string2+" expected: "+normalizedSubnetString, subnet2))
			} else {
				if subnet2.GetNetworkPrefixLen() != nil {
					t.addFailure(newIPAddrFailure("testSubnet failed, expected null prefix, got: "+subnet2.GetNetworkPrefixLen().String(), subnet2))
				} else {
					subnet4, err := value.Mask(mask) //1.2.0.0/15 masked with 0.0.255.255, does this result in full host or not?  previously I had it that way, but now I wonder why
					if err != nil {
						t.addFailure(newIPAddrFailure("testSubnet errored with mask "+mask.String(), value))
					}
					if !subnet4.GetNetworkPrefixLen().Equal(originalPrefix) {
						t.addFailure(newIPAddrFailure("testSubnet failed, expected "+originalPrefix.String()+" prefix, got: "+subnet4.GetNetworkPrefixLen().String(), subnet2))
					} else {
						if originalPrefix != nil {
							//the prefix will be different, but the addresses will be the same, except for full subnets
							//IPAddress addr = subnet2.setPrefixLength(originalPrefix, false);//0.0.*.* set to have prefix 15
							addr := subnet2.SetPrefixLen(originalPrefix.Len()) //0.0.*.* set to have prefix 15
							if !subnet4.Equal(addr) {
								t.addFailure(newIPAddrFailure("testSubnet failed: "+subnet4.String()+" expected: "+addr.String(), subnet4))
								//subnet2.SetPrefixLen(originalPrefix); //addr second div 0-1,  subnet4 second div 0-0
							}
						} else {
							if !subnet4.Equal(subnet2) {
								t.addFailure(newIPAddrFailure("testSubnet failed: "+subnet4.String()+" expected: "+subnet2.String(), subnet4))
							}
						}
					}
				}
			}
		}
		//} catch(IncompatibleAddressException e) {
		//	if(isValidMask) {
		//		addFailure(new Failure("testSubnet failed with mask " + mask + " " + e, value));
		//	}
		//}
		//}
		//}
		//} catch(IncompatibleAddressException e) {
		//if(isValidWithPrefix) {
		//	addFailure(new Failure("testSubnet failed with mask " + mask + " and prefix " + prefix + ": " + e, value));
		//} else {
		//	try {
		//		IPAddress subnet2 = value.mask(mask);
		//		if(!isValidMask) {
		//			addFailure(new Failure("testSubnet failed to throw with mask " + mask, value));
		//		} else {
		//			String string2 = subnet2.toNormalizedString();
		//			if(!string2.equals(normalizedSubnetString)) {
		//				addFailure(new Failure("testSubnet failed: " + normalizedSubnetString + " expected: " + string2, subnet2));
		//			}
		//		}
		//	} catch(IncompatibleAddressException e2) {
		//		if(isValidMask) {
		//			addFailure(new Failure("testSubnet failed with mask " + mask + " " + e2, value));
		//		}
		//	}
		//	}
		//}
	}
	//} catch(AddressStringException e) {
	//	addFailure(new Failure("t.testSubnet failed " + e, maskString));
	//}
	//} catch(AddressStringException | IncompatibleAddressException e) {
	//	addFailure(new Failure("t.testSubnet failed " + e, str));
	//}
	t.incrementTestCount()
}

func (t ipAddressTester) testHostAddress(addressStr string) {
	str := t.createAddress(addressStr)
	address := str.GetAddress()
	if address != nil {
		hostAddress := str.GetHostAddress()
		prefixIndex := strings.Index(addressStr, ipaddr.PrefixLenSeparatorStr)
		//int prefixIndex = addressStr.indexOf(IPAddress.PREFIX_LEN_SEPARATOR);
		if prefixIndex < 0 {
			if !address.Equal(hostAddress) || !address.Contains(hostAddress) {
				t.addFailure(newFailure("failed host address with no prefix: "+hostAddress.String()+" expected: "+address.String(), str))
			}
		} else {
			substr := addressStr[:prefixIndex]
			str2 := t.createAddress(substr)
			address2 := str2.GetAddress()
			if !address2.Equal(hostAddress) {
				t.addFailure(newFailure("failed host address: "+hostAddress.String()+" expected: "+address2.String(), str))
			}
		}
	}
}

func (t ipAddressTester) testReverse(addressStr string, bitsReversedIsSame, bitsReversedPerByteIsSame bool) {
	str := t.createAddress(addressStr)
	addr := str.GetAddress()
	//try {
	t.testBase.testReverse(addr.ToAddressBase().Wrap(), bitsReversedIsSame, bitsReversedPerByteIsSame)
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
			if !removed.GetSegment(i).Equal(original.GetSegment(i)) {
				t.addFailure(newIPAddrFailure("removed prefix: "+removed.String(), original))
				break
			}
		}
	}
	t.testBase.testPrefixes(original.Wrap(), // OK make it return WrappedAddress
		//t.testBase.testPrefixes(ipaddr.WrappedAddress{original.ToAddressBase()},
		prefix, adjustment,
		t.createAddress(next).GetAddress().Wrap(),
		t.createAddress(previous).GetAddress().Wrap(),
		t.createAddress(adjusted).GetAddress().Wrap(),
		t.createAddress(prefixSet).GetAddress().Wrap(),
		t.createAddress(prefixApplied).GetAddress().Wrap())
	t.incrementTestCount()
}

func (t ipAddressTester) testBitwiseOr(orig string, prefixAdjustment *ipaddr.BitCount, or, expectedResult string) {
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
			if !expectedResultAddr.Equal(result) {
				t.addFailure(newIPAddrFailure("ored expected: "+expectedResultAddr.String()+" actual: "+result.String(), original))
			}
			if !result.GetPrefixLen().Equal(original.GetPrefixLen()) {
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
			if !expectedResultAddr.Equal(result) || !expectedResultAddr.GetPrefixLen().Equal(result.GetPrefixLen()) {
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

	straightMatch := h1.Equal(h2)
	if matches != straightMatch && matches != conversionMatches(h1, h2) {
		//h1.equals(h2);
		//System.out.println(h1 + ": " + h1.getAddress());
		//System.out.println(h2 + ": " + h2.getAddress());
		t.addFailure(newFailure("failed: matching "+h1.String()+" with "+h2.String(), h1))
	} else {
		if matches != h2.Equal(h1) && matches != conversionMatches(h2, h1) {
			t.addFailure(newFailure("failed: match with "+h1.String(), h2))
		} else {
			var failed bool
			if matches {
				failed = h1.Compare(h2) != 0 && conversionCompare(h1, h2) != 0
			} else {
				failed = h1.Compare(h2) == 0
			}
			if failed {
				//if(matches ? (h1.Compare(h2) != 0 && conversionCompare(h1, h2) != 0) : (h1.Compare(h2) == 0)) {
				t.addFailure(newFailure("failed: matching "+h1.String()+" with "+h2.String(), h2))
			} else {
				if matches {
					failed = h2.Compare(h1) != 0 && conversionCompare(h2, h1) != 0
				} else {
					failed = h2.Compare(h1) == 0
				}
				if failed {
					//if(matches ? (h2.Compare(h1) != 0 && conversionCompare(h2, h1) != 0) : (h2.Compare(h1) == 0)) {
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
						if !h1.PrefixEqual(h2) {
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
							if !h1.PrefixEqual(h2) {
								t.addFailure(newFailure("failed: prefix match fail with "+h1.String(), h2))
							}
							h1.IsValid()
							h2.IsValid()
							if !h1.PrefixEqual(h2) {
								t.addFailure(newFailure("failed: 2 prefix match fail with "+h1.String(), h2))
							}
							h1.GetAddress()
							h2.GetAddress()
							if !h1.PrefixEqual(h2) {
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
			if pass && len(addr.String()) > 0 && addr.GetAddress() != nil && !(addr.GetAddress().IsIPv6() && addr.GetAddress().ToIPv6().HasZone()) && !addr.IsPrefixed() { //only for valid addresses
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
		b := addr.Bytes()
		b2 := addr.GetLower().Bytes()
		if !bytes.Equal(b, b2) {
			t.addFailure(newIPAddrFailure("bytes on addr "+addr.String(), addr.ToIP()))
			failed = true
		}
		bytesToUse := make([]byte, ipaddr.IPv6ByteCount)
		b2 = addr.GetLower().CopyNetIP(bytesToUse)
		if !bytes.Equal(b, b2) {
			t.addFailure(newIPAddrFailure("bytes on addr "+addr.String(), addr.ToIP()))
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
	b2 := addr.Bytes()
	if !bytes.Equal(inetAddress, b2) {
		t.addFailure(newIPAddrFailure("bytes on addr "+inetAddress.String(), addr))
	}
	//	//if(!Arrays.equals(b, b2)) {
	//	var b3 []byte
	//	if addr.IsIPv4() {
	//		b3 = addr.GetSection().Bytes()
	//		//inetAddress = inetAddress.To4()
	//	} else {
	//		addr, err := addr.ToIPv6().GetEmbeddedIPv4Address()
	//		if err != nil {
	//			//failed = true;
	//			t.addFailure(newIPAddrFailure("bytes on addr "+inetAddress.String(), addr.ToIP()))
	//			return false
	//		}
	//		b3 = addr.Bytes()
	//	}
	//	//byte[] b3 = addr.isIPv4() ? addr.getSection().getBytes() : addr.toIPv6().toMappedIPv4Segments().getBytes();
	//	if !bytes.Equal(inetAddress, b3) {
	//		//if(!Arrays.equals(b, b3)) {
	//		failed = true
	//		t.addFailure(newIPAddrFailure("bytes on addr "+inetAddress.String(), addr))
	//	}
	//} else {
	//	t.addFailure(newIPAddrFailure("bytes on addr "+inetAddress.String(), addr))
	//}

	bytesToUse := make([]byte, ipaddr.IPv6ByteCount)
	b4 := addr.CopyBytes(bytesToUse)
	if !bytes.Equal(inetAddress, b4) {
		t.addFailure(newIPAddrFailure("bytes on addr "+inetAddress.String(), addr))
	}

	bytesToUse = make([]byte, ipaddr.IPv6ByteCount)
	b4 = addr.CopyNetIP(bytesToUse)
	if !bytes.Equal(inetAddress, b4) {
		t.addFailure(newIPAddrFailure("bytes on addr "+inetAddress.String(), addr))
	}
	//	//if(!Arrays.equals(b, b2)) {
	//	bytesToUse = make([]byte, ipaddr.IPv6ByteCount)
	//	b6 := addr.CopyIP(bytesToUse)
	//	if !bytes.Equal(inetAddress, b6) {
	//		//if(!Arrays.equals(b, b3)) {
	//		failed = true
	//		t.addFailure(newIPAddrFailure("bytes on addr "+inetAddress.String(), addr))
	//	} else {
	//		var b5 []byte
	//		bytesToUse = make([]byte, ipaddr.IPv6ByteCount)
	//		if addr.IsIPv4() {
	//			b5 = addr.GetSection().CopyBytes(bytesToUse)
	//			//inetAddress = inetAddress.To4()
	//		} else {
	//			addr, err := addr.ToIPv6().GetEmbeddedIPv4Address()
	//			if err != nil {
	//				//failed = true;
	//				t.addFailure(newIPAddrFailure("bytes on addr "+inetAddress.String(), addr.ToIP()))
	//				return false
	//			}
	//			b5 = addr.CopyBytes(bytesToUse)
	//		}
	//		//byte[] b3 = addr.isIPv4() ? addr.getSection().getBytes() : addr.toIPv6().toMappedIPv4Segments().getBytes();
	//		if !bytes.Equal(inetAddress, b5) {
	//			//if(!Arrays.equals(b, b3)) {
	//			failed = true
	//			t.addFailure(newIPAddrFailure("bytes on addr "+inetAddress.String(), addr))
	//		}
	//	}
	//} else {
	//	t.addFailure(newIPAddrFailure("bytes on addr "+inetAddress.String(), addr))
	//}

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
	b2 := w3.GetAddress().Bytes()
	if !bytes.Equal(inetAddress, b2) {
		//if(!Arrays.equals(b, b2)) {
		t.addFailure(newFailure("bytes on addr "+inetAddress.String(), w3))
	} else {
		b3 := w2.GetAddress().Bytes()
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
	first := w.Equal(w2)
	v, err := w.ToAddress()
	v2, err2 := w2.ToAddress()
	if err != nil || err2 != nil {
		t.addFailure(newFailure("testCIDRSubnets addresses "+w.String()+", "+w2.String()+": "+err.Error()+", "+err2.Error(), w2))
	}
	second := v.Equal(v2)
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
	sampleIpv6 := t.createAddress("1234:abcd:cdef:5678:9abc:def0:1234:5678").GetAddress().ToIPv6()
	sampleIpv4 := t.createAddress("123.156.178.201").GetAddress().ToIPv4()

	ipv6Network := ipaddr.IPv6Network
	//IPv6AddressNetwork ipv6Network = ADDRESS_OPTIONS.getIPv6Parameters().getNetwork();
	ipv6SampleNetMask := sampleIpv6.GetNetworkMask()
	ipv6SampleHostMask := sampleIpv6.GetHostMask()
	onesNetworkMask := ipv6Network.GetNetworkMask(ipaddr.IPv6BitCount)
	onesHostMask := ipv6Network.GetHostMask(0)
	if !ipv6SampleNetMask.Equal(onesNetworkMask) {
		t.addFailure(newIPAddrFailure("mask mismatch between address "+ipv6SampleNetMask.String()+" and network "+onesNetworkMask.String(), sampleIpv6.ToIP()))
	}
	if !ipv6SampleHostMask.Equal(onesHostMask) {
		t.addFailure(newIPAddrFailure("mask mismatch between address "+ipv6SampleHostMask.String()+" and network "+onesHostMask.String(), sampleIpv6.ToIP()))
	}

	//IPv4AddressNetwork ipv4Network = ADDRESS_OPTIONS.getIPv4Parameters().getNetwork();
	ipv4Network := ipaddr.IPv4Network
	ipv4SampleNetMask := sampleIpv4.GetNetworkMask()
	ipv4SampleHostMask := sampleIpv4.GetHostMask()
	onesNetworkMaskv4 := ipv4Network.GetNetworkMask(ipaddr.IPv4BitCount)
	onesHostMaskv4 := ipv4Network.GetHostMask(0)
	if !ipv4SampleNetMask.Equal(onesNetworkMaskv4) {
		t.addFailure(newIPAddrFailure("mask mismatch between address "+ipv4SampleNetMask.String()+" and network "+onesNetworkMaskv4.String(), sampleIpv4.ToIP()))
	}
	if !ipv4SampleHostMask.Equal(onesHostMaskv4) {
		t.addFailure(newIPAddrFailure("mask mismatch between address "+ipv4SampleHostMask.String()+" and network "+onesHostMaskv4.String(), sampleIpv4.ToIP()))
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
				if !ipv6NetworkMask2.Equal(ipv6NetworkMask) {
					t.addFailure(newIPAddrFailure("mask mismatch between address "+ipv6NetworkMask2.String()+" and network "+ipv6NetworkMask.String(), samplePrefixedIpv6.ToIP()))
				}
				if !ipv6HostMask2.Equal(ipv6HostMask) {
					t.addFailure(newIPAddrFailure("mask mismatch between address "+ipv6HostMask2.String()+" and network "+ipv6HostMask.String(), samplePrefixedIpv6.ToIP()))
				}
				if i <= ipaddr.IPv4BitCount {
					ipv4HostMask := ipv4Network.GetHostMask(bits)
					if t.checkMask(ipv4HostMask, bits, false, false) {
						ipv4NetworkMask := ipv4Network.GetPrefixedNetworkMask(bits)
						t.checkMask(ipv4NetworkMask, bits, true, false)

						samplePrefixedIpv4 := sampleIpv4.SetPrefixLen(bits)
						ipv4NetworkMask2 := samplePrefixedIpv4.GetNetworkMask()
						ipv4HostMask2 := samplePrefixedIpv4.GetHostMask()
						if !ipv4NetworkMask2.Equal(ipv4NetworkMask) {
							t.addFailure(newIPAddrFailure("mask mismatch between address "+ipv4NetworkMask2.String()+" and network "+ipv4NetworkMask.String(), samplePrefixedIpv4.ToIP()))
						}
						if !ipv4HostMask2.Equal(ipv4HostMask) {
							t.addFailure(newIPAddrFailure("mask mismatch between address "+ipv4HostMask2.String()+" and network "+ipv4HostMask.String(), samplePrefixedIpv4.ToIP()))
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
	//if prefixBits == 80 {
	//	fmt.Println("huh? getting block pref len for " + address.String())
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
	if maskPrefix.Len() != min(prefixBits, address.GetBitCount()) || other {
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
		t.addFailure(newIPAddrFailure("leading bits failure, bit counts are leading: "+bitCountToString(leadingBits)+" trailing: "+bitCountToString(trailingBits), address))
		return false
	}
	if leadingBits+trailingBits != address.GetBitCount() {
		t.addFailure(newIPAddrFailure("bit counts are leading: "+bitCountToString(leadingBits)+" trailing: "+bitCountToString(trailingBits), address))
		return false
	}
	if network {
		//try {
		originalPrefixStr := "/" + bitCountToString(prefixBits)
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
			addressWithNoPrefix, err = address.Mask(address.GetNetwork().GetNetworkMask(address.GetPrefixLen().Len()))
			if err != nil {
				t.addFailure(newIPAddrFailure("failed mask "+err.Error(), address))
			}
		} //else {
		//	panic("whatever")
		//}

		ipForNormalizeMask := addressWithNoPrefix.String()
		maskStrx2 := t.normalizeMask(originalPrefixStr, ipForNormalizeMask) + prefixExtra
		maskStrx3 := t.normalizeMask(bitCountToString(prefixBits), ipForNormalizeMask) + prefixExtra
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
		bytes := address.Bytes()
		var another *ipaddr.IPAddress
		// if address.IsIPv4() {
		//ipaddr.IPv4Network.
		if network {
			another = ipaddr.NewIPAddressFromPrefixedNetIP(bytes, cacheTestBits(prefixBits))
		} else {
			another = ipaddr.NewIPAddressFromNetIP(bytes)
			if another.IsIPv4() && prefixBits > ipaddr.IPv4BitCount {
				// ::ffff:ffff:ffff is interpreted as IPv4-mapped and gives the IPv4 address 255.255.255.255, so we flip it back to IPv6
				another = ipaddr.DefaultAddressConverter{}.ToIPv6(another).ToIP()
			}
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
				prefixBitsMismatch = addrPrefixBits == nil || (prefixBits != addrPrefixBits.Len())
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
			prefix, perr := ipaddr.ValidatePrefixLenStr(maskString, version)
			if perr != nil {
				t.addFailure(newFailure("prefix string incorrect: "+perr.Error(), addressString))
				return ""
			}
			maskAddress := addressString.GetAddress().GetNetwork().GetNetworkMask(prefix.Len())
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
	needsConversion := !w.GetIPVersion().Equal(w2.GetIPVersion())
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
	//boolean false = prefixConfiguration.allPrefixedAddressesAreSubnets();
	//if(false) {
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
			prefEquals := wstr.PrefixEqual(w2str)

			wstr.IsValid()
			w2str.IsValid()
			prefEquals2 := wstr.PrefixEqual(w2str)

			w = wstr.GetAddress()
			w2 = w2str.GetAddress()
			origEquals := w.PrefixEqual(w2)
			prefEquals3 := wstr.PrefixEqual(w2str)
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
					w.PrefixEqual(w2)
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

func isSameAllAround(supplied, internal *ipaddr.IPAddress) bool {
	return supplied.Equal(internal) &&
		internal.Equal(supplied) &&
		internal.GetNetworkPrefixLen().Equal(supplied.GetNetworkPrefixLen()) &&
		internal.GetMinPrefixLenForBlock() == supplied.GetMinPrefixLenForBlock() &&
		internal.GetPrefixLenForSingleBlock().Equal(supplied.GetPrefixLenForSingleBlock()) &&
		internal.GetCount().Cmp(supplied.GetCount()) == 0
}

func (t ipAddressTester) testNetmasks(prefix ipaddr.BitCount, ipv4NetworkAddress, ipv4NetworkAddressNoPrefix, ipv4HostAddress, ipv6NetworkAddress, ipv6NetworkAddressNoPrefix, ipv6HostAddress string) {
	ipv6Addr := t.createAddress(ipv6NetworkAddress)
	ipv4Addr := t.createAddress(ipv4NetworkAddress)
	if prefix <= ipaddr.IPv6BitCount {
		w2NoPrefix := t.createAddress(ipv6NetworkAddressNoPrefix)
		//try {
		_, err := ipaddr.ValidatePrefixLenStr(strconv.Itoa(int(prefix)), ipaddr.IPv6)
		if err != nil {
			t.addFailure(newFailure("failed prefix "+strconv.Itoa(int(prefix))+": "+err.Error(), w2NoPrefix))
		}
		ipv6AddrValue := ipv6Addr.GetAddress()
		ipv6network := ipv6AddrValue.GetNetwork()
		//if(ipv6network.getPrefixConfiguration().zeroHostsAreSubnets()) {
		//	IPAddress networkAddress = ipv6network.GetNetworkAddress(prefix);
		//	//IPAddress networkAddress = ipv6network.getNetworkMask(prefix).toPrefixBlock();
		//	if(!isSameAllAround(networkAddress, ipv6AddrValue)) {
		//		addFailure(new Failure("network address mismatch " + networkAddress, ipv6AddrValue));
		//	}
		ipv6AddrValue = ipv6AddrValue.GetLower()
		//}
		addr6 := ipv6network.GetPrefixedNetworkMask(prefix)
		addr6NoPrefix := ipv6network.GetNetworkMask(prefix)
		w2ValueNoPrefix := w2NoPrefix.GetAddress()
		//boolean one;
		if (!isSameAllAround(ipv6AddrValue, addr6)) || !isSameAllAround(w2ValueNoPrefix, addr6NoPrefix) {
			//one = !isSameAllAround(ipv6AddrValue, addr6);//min prefix is 0 vs 128
			//isSameAllAround(w2ValueNoPrefix, addr6NoPrefix);
			if !isSameAllAround(ipv6AddrValue, addr6) {
				t.addFailure(newIPAddrFailure("failed "+addr6.String(), ipv6AddrValue))
			} else {
				t.addFailure(newIPAddrFailure("failed "+addr6NoPrefix.String(), w2ValueNoPrefix))
			}
		} else {
			addrHost6 := ipv6network.GetHostMask(prefix)
			ipv6HostAddrString := t.createAddress(ipv6HostAddress)
			//try {
			ipv6HostAddrValue := ipv6HostAddrString.GetAddress()
			if !isSameAllAround(ipv6HostAddrValue, addrHost6) {
				t.addFailure(newFailure("failed "+addrHost6.String(), ipv6HostAddrString))
			} else if prefix <= ipaddr.IPv4BitCount {
				wNoPrefix := t.createAddress(ipv4NetworkAddressNoPrefix)
				//try {
				//prefix, err := ipaddr.ValidatePrefixLenStr(strconv.Itoa(int(prefix)), ipaddr.IPv6);
				//if err != nil {
				//	t.addFailure(newFailure("failed prefix "+strconv.Itoa(int(prefix)) + ": " + err.Error(), w2NoPrefix))
				//}
				_, err = ipaddr.ValidatePrefixLenStr(strconv.Itoa(int(prefix)), ipaddr.IPv4)
				if err != nil {
					t.addFailure(newFailure("failed prefix "+strconv.Itoa(int(prefix))+": "+err.Error(), wNoPrefix))
				}
				wValue := ipv4Addr.GetAddress()
				ipv4network := wValue.GetNetwork()
				//if(ipv4network.getPrefixConfiguration().zeroHostsAreSubnets()) {
				//	IPAddress networkAddress = ipv4network.getNetworkAddress(prefix);
				//	//IPAddress networkAddress = ipv6network.getNetworkMask(prefix).toPrefixBlock();
				//	if(!isSameAllAround(networkAddress, wValue)) {
				//		addFailure(new Failure("network address mismatch " + networkAddress, wValue));
				//	}
				wValue = wValue.GetLower()
				//}
				addr4 := ipv4network.GetPrefixedNetworkMask(prefix)
				addr4NoPrefix := ipv4network.GetNetworkMask(prefix)
				wValueNoPrefix := wNoPrefix.GetAddress()
				if (!isSameAllAround(wValue, addr4)) || !isSameAllAround(wValueNoPrefix, addr4NoPrefix) {
					//isSameAllAround(wValue, addr4);
					//isSameAllAround(wValueNoPrefix, addr4NoPrefix);
					if !isSameAllAround(wValue, addr4) {
						t.addFailure(newIPAddrFailure("failed "+addr4.String(), wValue))
					} else {
						t.addFailure(newIPAddrFailure("failed "+addr4NoPrefix.String(), wValueNoPrefix))
					}
				} else {
					addr4 := ipv4network.GetHostMask(prefix)
					ipv4Addr = t.createAddress(ipv4HostAddress)
					//try {
					wValue = ipv4Addr.GetAddress()
					if !isSameAllAround(wValue, addr4) {
						t.addFailure(newFailure("failed "+addr4.String(), ipv4Addr))
					}
					//} catch(AddressStringException e) {
					//	addFailure(new Failure("failed " + addr4, ipv4Addr));
					//}
				}
				//} catch(AddressStringException | IncompatibleAddressException e) {
				//	addFailure(new Failure("failed prefix val", ipv4Addr));
				//}
			} else { //prefix > IPv4Address.BIT_COUNT
				//try {
				_, err := ipv4Addr.ToAddress()
				if err == nil {
					t.addFailure(newFailure("did not succeed with extra-large prefix", ipv4Addr))
				}

				//} catch(AddressStringException e) {}
			}
			//} catch(AddressStringException e) {
			//	addFailure(new Failure("failed " + addrHost6, ipv6HostAddrString));
			//}
		}
		//} catch(AddressStringException | IncompatibleAddressException e) {
		//	addFailure(new Failure("failed prefix val", ipv6Addr));
		//}
	} else {
		//try {
		_, err := ipv6Addr.ToAddress()
		if err == nil {
			t.addFailure(newFailure("succeeded with invalid prefix in "+ipv6Addr.String()+": "+err.Error(), ipv4Addr))
		}
		//addFailure(new Failure("succeeded with invalid prefix", ipv6Addr));
		//} catch(AddressStringException e) {
		_, err = ipv4Addr.ToAddress()
		if err == nil {
			//t.addFailure(newFailure("succeeded with invalid prefix in "+ipv4Addr.String()+": "+err.Error(), ipv4Addr))
			t.addFailure(newFailure("succeeded with invalid prefix in "+ipv4Addr.String(), ipv4Addr))
		}
		//try {
		//	ipv4Addr.toAddress();
		//	addFailure(new Failure("succeeded with invalid prefix", ipv4Addr));
		//} catch(AddressStringException e4) {}
		//}
	}
	t.incrementTestCount()
}

func (t ipAddressTester) checkAddrNotMask(address *ipaddr.IPAddress, network bool) bool {
	maskPrefix := address.GetBlockMaskPrefixLen(network)
	otherMaskPrefix := address.GetBlockMaskPrefixLen(!network)
	if maskPrefix != nil {
		t.addFailure(newIPAddrFailure("failed not mask "+maskPrefix.String(), address))
		return false
	}
	if otherMaskPrefix != nil {
		t.addFailure(newIPAddrFailure("failed not mask "+otherMaskPrefix.String(), address))
		return false
	}
	t.incrementTestCount()
	return true
}

func (t ipAddressTester) checkNotMask(addr string) {
	addressStr := t.createAddress(addr)
	address := addressStr.GetAddress()
	val := (address.Bytes()[0] & 1) == 0
	if t.checkAddrNotMask(address, val) {
		t.checkAddrNotMask(address, !val)
	}
}

func (t ipAddressTester) testSplit(address string, bits ipaddr.BitCount, network, networkNoRange, networkWithPrefix string, networkStringCount int, host string, hostStringCount int) {
	//try {
	w := t.createAddress(address)
	v := w.GetAddress()
	section := v.GetNetworkSectionLen(bits)
	section = section.WithoutPrefixLen()
	sectionStr := section.ToNormalizedString()
	//printStrings(section);
	if sectionStr != network {
		t.addFailure(newFailure("failed got "+sectionStr+" expected "+network, w))
	} else {
		sectionWithPrefix := v.GetNetworkSectionLen(bits)
		sectionStrWithPrefix := sectionWithPrefix.ToNormalizedString()
		if sectionStrWithPrefix != (networkWithPrefix) {
			t.addFailure(newFailure("failed got "+sectionStrWithPrefix+" expected "+networkWithPrefix, w))
		} else {
			s := section.GetLower()
			//fmt.Printf("%v %v\n", s, section)
			sectionStrNoRange := s.ToNormalizedString()
			if sectionStrNoRange != networkNoRange || s.GetCount().Int64() != 1 {
				t.addFailure(newFailure("failed got "+sectionStrNoRange+" expected "+networkNoRange, w))
			} else {
				// TODO LATER string collections
				//IPAddressPartStringCollection coll = sectionWithPrefix.toStandardStringCollection();
				//String standards[] = coll.toStrings();
				//if(standards.length != networkStringCount) {
				//	addFailure(new Failure("failed " + section + " expected count " + networkStringCount + " was " + standards.length, w));
				//} else {
				section = v.GetHostSectionLen(bits)
				section = section.WithoutPrefixLen()
				//printStrings(section);
				sectionStr = section.ToNormalizedString()
				if sectionStr != (host) {
					t.addFailure(newFailure("failed "+sectionStr+" expected "+host, w))
				} //else { TODO LATER string collections
				//	String standardStrs[] = section.toStandardStringCollection().toStrings();
				//	if(standardStrs.length != hostStringCount) {
				//		addFailure(new Failure("failed " + section + " expected count " + hostStringCount + " was " + standardStrs.length, w));
				//		//standardStrs = section.toStandardStringCollection().toStrings();
				//	}
				//}
				//}
			}
		}
	}
	//} catch(RuntimeException e) {
	//	addFailure(new Failure("unexpected throw: " + e));
	//}
	t.incrementTestCount()
}

func (t ipAddressTester) testURL(url string) {
	w := t.createAddress(url)
	//try {
	_, err := w.ToAddress()
	if err == nil {
		t.addFailure(newFailure("failed: "+"URL "+url, w))
	}
	addr := w.GetAddress()
	if addr != nil {
		t.addFailure(newFailure("failed: "+"URL "+url, w))
	}
	w2 := t.createAddress(url)
	addr = w2.GetAddress()
	if addr != nil {
		t.addFailure(newFailure("failed: "+"URL "+url, w2))
	}
	_, err = w2.ToAddress()
	if err == nil {
		t.addFailure(newFailure("failed: "+"URL "+url, w2))
	}
	//} catch(AddressStringException e) {
	//pass
	//e.getMessage();
	//}
}

// gets host address, then creates a second ip addr to match the original and gets host address that way
// then checks that they match
func (t ipAddressTester) testReverseHostAddress(str string) {
	addrStr := t.createAddress(str)
	addr := addrStr.GetAddress()
	hostAddr := addrStr.GetHostAddress()
	var hostAddr2 *ipaddr.IPAddress
	if addr.IsIPv6() {
		newAddr, err := ipaddr.NewIPv6Address(addr.ToIPv6().GetSection())
		if err != nil {
			t.addFailure(newIPAddrFailure("error creating address from "+addr.String()+": "+err.Error(), addr))
		}
		newAddrString := newAddr.ToAddressString()
		hostAddr2 = newAddrString.GetHostAddress()
	} else {
		newAddr, err := ipaddr.NewIPv4Address(addr.ToIPv4().GetSection())
		if err != nil {
			t.addFailure(newIPAddrFailure("error creating address from "+addr.String()+": "+err.Error(), addr))
		}
		newAddrString := newAddr.ToAddressString()
		hostAddr2 = newAddrString.GetHostAddress()
	}
	if !hostAddr.Equal(hostAddr2) {
		t.addFailure(newIPAddrFailure("expected "+hostAddr.String()+" got "+hostAddr2.String(), addr))
	}
	t.incrementTestCount()
}

func (t ipAddressTester) testFromBytes(bytes []byte, expected string) {
	addr := t.createAddressFromIP(bytes)
	addr2 := t.createAddress(expected)
	result := addr.Equal(addr2.GetAddress())
	if !result {
		t.addFailure(newIPAddrFailure("created was "+addr.String()+" expected was "+addr2.String(), addr))
	} else {
		if addr.IsIPv4() {
			val := uint32(0)
			for i := 0; i < len(bytes); i++ {
				val <<= 8
				val |= uint32(bytes[i])
			}
			addr := t.createIPv4Address(val)
			result = addr.Equal(addr2.GetAddress())
			if !result {
				t.addFailure(newIPAddrFailure("created was "+addr.String()+" expected was "+addr2.String(), addr.ToIP()))
			}
		} else {
			var highVal, lowVal uint64
			i := 0
			for ; i < 8; i++ {
				highVal <<= 8
				highVal |= uint64(bytes[i])
			}
			for ; i < 16; i++ {
				lowVal <<= 8
				lowVal |= uint64(bytes[i])
			}
			addr := t.createIPv6Address(highVal, lowVal)
			result = addr.Equal(addr2.GetAddress())
			if !result {
				t.addFailure(newIPAddrFailure("created was "+addr.String()+" expected was "+addr2.String(), addr.ToIP()))
			}
		}
	}
	t.incrementTestCount()
}

func (t ipAddressTester) testResolved(original, expected string) {
	origAddress := t.createAddress(original)
	resolvedAddress := origAddress.GetAddress()
	if resolvedAddress == nil {
		resolvedAddress = t.createHost(original).GetAddress()
	}
	expectedAddress := t.createAddress(expected)
	var result bool
	if resolvedAddress == nil {
		result = expected == ""
	} else {
		result = resolvedAddress.Equal(expectedAddress.GetAddress())
	}
	if !result {
		t.addFailure(newFailure("resolved was "+resolvedAddress.String()+" original was "+original, origAddress))
	}
	t.incrementTestCount()
}

func (t ipAddressTester) testNormalized(original, expected string) {
	t.testNormalizedMC(original, expected, false, true)
}

func (t ipAddressTester) testMask(original, mask, expected string) {
	w := t.createAddress(original)
	orig := w.GetAddress()
	maskString := t.createAddress(mask)
	maskAddr := maskString.GetAddress()
	masked, err := orig.Mask(maskAddr)
	if err != nil {
		t.addFailure(newIPAddrFailure("testMask errored with mask "+maskAddr.String()+" error: "+err.Error(), orig))
	}
	expectedStr := t.createAddress(expected)
	expectedAddr := expectedStr.GetAddress()
	if !masked.Equal(expectedAddr) {
		t.addFailure(newFailure("mask was "+mask+" and masked was "+masked.String(), w))
	}
	t.incrementTestCount()
}

func (t ipAddressTester) testNormalizedMC(original, expected string, keepMixed, compress bool) {
	w := t.createAddress(original)
	//String normalized;
	if w.IsIPv6() {
		val := w.GetAddress().ToIPv6()
		var paramsBuilder = new(ipaddr.IPv6StringOptionsBuilder)
		if compress {
			compressOpts := new(ipaddr.CompressOptionsBuilder).SetCompressSingle(true).SetRangeSelection(ipaddr.ZerosOrHost).ToOptions()
			paramsBuilder = paramsBuilder.SetCompressOptions(compressOpts)
		}
		fromString := val.ToAddressString()
		if fromString != nil && fromString.IsMixedIPv6() {
			paramsBuilder.SetMixed(true)
		}
		params := paramsBuilder.ToOptions()
		normalized, err := val.ToCustomString(params)
		if err != nil {
			t.addFailure(newIPAddrFailure("ToCustomString errored with error: "+err.Error(), val.ToIP()))
		}
		if normalized != expected {
			t.addFailure(newFailure("normalization 1 was "+normalized+" expected was "+expected, w))
		}
	} else if w.IsIPv4() {
		val := w.GetAddress().ToIPv4()
		normalized := val.ToNormalizedString()
		if normalized != expected {
			t.addFailure(newFailure("normalization 2 was "+normalized, w))
		}
	} else {
		t.addFailure(newFailure("normalization failed on "+original, w))
	}
	t.incrementTestCount()
}

func (t ipAddressTester) testCompressed(original, expected string) {
	w := t.createAddress(original)
	var normalized string
	//if(w.isIPAddress()) {
	val := w.GetAddress()
	if val != nil {
		normalized = val.ToCompressedString()
	} else {
		//} else {
		normalized = w.String()
	}
	//}
	if normalized != expected {
		t.addFailure(newFailure("canonical was "+normalized, w))
	}
	t.incrementTestCount()
}

func (t ipAddressTester) testCanonical(original, expected string) {
	w := t.createAddress(original)
	addr := w.GetAddress()
	normalized := addr.ToCanonicalString()
	if normalized != expected {
		t.addFailure(newFailure("canonical was "+normalized, w))
	}
	t.incrementTestCount()
}

func (t ipAddressTester) testMixed(original, expected string) {
	t.testMixedNoComp(original, expected, expected)
}

func (t ipAddressTester) testMixedNoComp(original, expected, expectedNoCompression string) {
	w := t.createAddress(original)
	val := w.GetAddress().ToIPv6()
	normalized, err := val.ToMixedString()
	if err != nil {
		t.addFailure(newIPAddrFailure("testMixedNoComp errored with error: "+err.Error(), val.ToIP()))
	}
	if normalized != expected {
		t.addFailure(newFailure("mixed was "+normalized+" expected was "+expected, w))
	} else {
		compressOpts := new(ipaddr.CompressOptionsBuilder).SetCompressSingle(true).SetRangeSelection(ipaddr.ZerosOrHost).SetMixedOptions(ipaddr.NoMixedCompression).ToOptions()
		//CompressOptions opts = new CompressOptions(true, CompressOptions.CompressionChoiceOptions.ZerosOrHost, CompressOptions.MixedCompressionOptions.NO);
		normalized, err := val.ToCustomString(new(ipaddr.IPv6StringOptionsBuilder).SetMixed(true).SetCompressOptions(compressOpts).ToOptions())
		if err != nil {
			t.addFailure(newIPAddrFailure("ToCustomString errored with error: "+err.Error(), val.ToIP()))
		}
		//normalized = val.ToNormalizedString(new(ipaddr.IPv6StringOptionsBuilder).SetMixed(true).SetCompressOptions(compressOpts).ToOptions())
		if normalized != expectedNoCompression {
			t.addFailure(newFailure("mixed was "+normalized+" expected was "+expectedNoCompression, w))
		}
	}
	t.incrementTestCount()
}

func (t ipAddressTester) testRadices(original, expected string, radix int) {
	w := t.createAddress(original)
	val := w.GetAddress()
	options := new(ipaddr.IPv4StringOptionsBuilder).SetRadix(radix).ToOptions()
	normalized := val.ToCustomString(options)
	if normalized != expected {
		t.addFailure(newFailure("string was "+normalized+" expected was "+expected, w))
	}
	t.incrementTestCount()
}

func (t ipAddressTester) testInsertAndAppend(front, back string, expectedPref []ipaddr.BitCount) {
	is := make([]ipaddr.PrefixLen, len(expectedPref))
	for i := 0; i < len(expectedPref); i++ {
		is[i] = cacheTestBits(expectedPref[i])
	}
	t.testInsertAndAppendPrefs(front, back, is)
}

func (t ipAddressTester) testInsertAndAppendPrefs(front, back string, expectedPref []ipaddr.PrefixLen) {
	f := t.createAddress(front).GetAddress()
	b := t.createAddress(back).GetAddress()
	sep := byte(ipaddr.IPv4SegmentSeparator)
	if f.IsIPv6() {
		sep = ipaddr.IPv6SegmentSeparator
	}
	t.testAppendAndInsert(f.ToAddressBase(), b.ToAddressBase(), f.GetSegmentStrings(), b.GetSegmentStrings(), sep, expectedPref, false)
}

func (t ipAddressTester) testReplace(front, back string) {
	f := t.createAddress(front).GetAddress()
	b := t.createAddress(back).GetAddress()
	sep := byte(ipaddr.IPv4SegmentSeparator)
	if f.IsIPv6() {
		sep = ipaddr.IPv6SegmentSeparator
	}
	t.testBase.testReplace(f.ToAddressBase(), b.ToAddressBase(), f.GetSegmentStrings(), b.GetSegmentStrings(), sep, false)
}

func (t ipAddressTester) testInvalidIpv4Values() {
	//try {
	bytes := []byte{1, 0, 0, 0, 0}
	bytes[0] = 1
	addr, err := ipaddr.NewIPv4AddressFromBytes(bytes)
	if err == nil {
		t.addFailure(newIPAddrFailure("failed expected error for "+addr.String(), addr.ToIP()))
	}
	//} catch(AddressValueException e) {}
	//try {
	addr, err = ipaddr.NewIPv4AddressFromBytes([]byte{0, 0, 0, 0, 0})
	if err != nil {
		t.addFailure(newIPAddrFailure("failed unexpected error for "+addr.String()+" error: "+err.Error(), addr.ToIP()))
	}
	//} catch(AddressValueException e) {
	//	addFailure(new Failure("unexpected exception " + e));
	//}
	//try {
	//new IPv4Address(new byte[4]);
	addr, err = ipaddr.NewIPv4AddressFromBytes([]byte{0, 0, 0, 0})
	if err != nil {
		t.addFailure(newIPAddrFailure("failed unexpected error for "+addr.String()+" error: "+err.Error(), addr.ToIP()))
	}
	//} catch(AddressValueException e) {
	//	addFailure(new Failure("unexpected exception " + e));
	//}
	//try {
	//new IPv4Address(new byte[3]);
	addr, err = ipaddr.NewIPv4AddressFromBytes([]byte{0, 0, 0})
	if err != nil {
		t.addFailure(newIPAddrFailure("failed unexpected error for "+addr.String()+" error: "+err.Error(), addr.ToIP()))
	}
	//} catch(AddressValueException e) {
	//	addFailure(new Failure("unexpected exception " + e));
	//}
	//try {
	addr, err = ipaddr.NewIPv4AddressFromBytes([]byte{0, 0})
	if err != nil {
		t.addFailure(newIPAddrFailure("failed unexpected error for "+addr.String()+" error: "+err.Error(), addr.ToIP()))
	}
	//new IPv4Address(new byte[2]);
	//} catch(AddressValueException e) {
	//	addFailure(new Failure("unexpected exception " + e));
	//}
	//try {
	addr = ipaddr.NewIPv4AddressFromVals(func(segmentIndex int) ipaddr.IPv4SegInt {
		var val = 256 // will be truncated to 0
		return ipaddr.IPv4SegInt(val)
	})
	if !addr.IsZero() {
		t.addFailure(newIPAddrFailure("failed expected exception for "+addr.String(), addr.ToIP()))
	}
	//} catch(AddressValueException e) {}
	//try {
	addr = ipaddr.NewIPv4AddressFromVals(func(segmentIndex int) ipaddr.IPv4SegInt {
		var val = -1 // will be truncated to 0
		return ipaddr.IPv4SegInt(val)
	})
	if !addr.IsMax() {
		t.addFailure(newIPAddrFailure("failed expected exception for "+addr.String(), addr.ToIP()))
	}
	//} catch(AddressValueException e) {}
	//try {
	addr = ipaddr.NewIPv4AddressFromVals(func(segmentIndex int) ipaddr.IPv4SegInt {
		var val = 255 // will be truncated to 0
		return ipaddr.IPv4SegInt(val)
	})
	if !addr.IsMax() {
		t.addFailure(newIPAddrFailure("failed expected exception for "+addr.String(), addr.ToIP()))
	}
	//new IPv4Address(new SegmentValueProvider() {
	//	@Override
	//	public int getValue(int segmentIndex) {
	//		return 255;
	//	}
	//});
	//} catch(AddressValueException e) {
	//	addFailure(new Failure("unexpected exception " + e));
	//}
}

func (t ipAddressTester) testIPv4Values(segs []int, decimal string) {
	vals := make([]byte, len(segs))
	strb := strings.Builder{}
	//longval := 0;
	intval := uint32(0)
	bigInt := new(big.Int)
	//BigInteger bigInteger = BigInteger.ZERO;
	bitsPerSegment := ipaddr.IPv4BitsPerSegment
	for i := 0; i < len(segs); i++ {
		seg := segs[i]
		if strb.Len() > 0 {
			strb.WriteByte('.')
		}
		strb.WriteString(strconv.Itoa(seg))
		vals[i] = byte(seg)
		//longval = (longval << bitsPerSegment) | seg;
		intval = (intval << uint(bitsPerSegment)) | uint32(seg)
		bigInt = bigInt.Lsh(bigInt, uint(bitsPerSegment)).Or(bigInt, new(big.Int).SetInt64(int64(seg)))
	}
	//try {
	strbStr := strb.String()
	ipaddressStr := t.createAddress(strbStr)
	addr := [7]*ipaddr.IPv4Address{}
	//IPv4Address addr[] = new IPv4Address[7];
	//int i = 0;
	addr[0] = t.createAddressFromIP(vals).ToIPv4()
	addr[1] = ipaddressStr.GetAddress().ToIPv4()
	addr[2] = t.createIPv4Address(intval)
	ips := net.ParseIP(strbStr)
	ips2 := net.IPv4(vals[0], vals[1], vals[2], vals[3])
	//InetAddress inetAddress1 = InetAddress.getByName(strbStr);
	//InetAddress inetAddress2 = InetAddress.getByAddress(vals);
	ip, err := ipaddr.NewIPv4AddressFromBytes(ips)
	if err != nil {
		t.addFailure(newIPAddrFailure("failed unexpected error for "+strbStr+" error: "+err.Error(), ip.ToIP()))
	}
	ip2, err := ipaddr.NewIPv4AddressFromBytes(ips2)
	if err != nil {
		t.addFailure(newIPAddrFailure("failed unexpected error for "+strbStr+" error: "+err.Error(), ip2.ToIP()))
	}
	addr[3] = ip
	addr[4] = ip2
	addr[5] = ipaddr.NewIPv4AddressFromUint32(intval)
	addr[6] = ipaddr.NewIPv4AddressFromUint32(uint32(bigInt.Uint64()))
	for j := 0; j < len(addr); j++ {
		for k := j; k < len(addr); k++ {
			if !addr[k].Equal(addr[j]) || !addr[j].Equal(addr[k]) {
				t.addFailure(newFailure("failed equals: "+addr[k].String()+" and "+addr[j].String(), ipaddressStr))
			}
		}
	}
	if decimal != "" {
		for i := 0; i < len(addr); i++ {
			if decimal != addr[i].GetValue().String() {
				t.addFailure(newFailure("failed equals: "+addr[i].GetValue().String()+" and "+decimal, ipaddressStr))
			}
			if decimal != strconv.FormatUint(uint64(addr[i].Uint32Value()), 10) {
				t.addFailure(newFailure("failed equals: "+strconv.FormatUint(uint64(addr[i].Uint32Value()), 10)+" and "+decimal, ipaddressStr))
			}
		}
	}
	//} catch(UnknownHostException e) {
	//	addFailure(new Failure("failed unexpected: " + e));
	//}
}

func (t ipAddressTester) testIPv6Values(segs []int, decimal string) {
	vals := make([]byte, len(segs)*int(ipaddr.IPv6BytesPerSegment))
	strb := strings.Builder{}
	bigInt := new(big.Int)
	bitsPerSegment := ipaddr.IPv6BitsPerSegment
	for i := 0; i < len(segs); i++ {
		seg := segs[i]
		if strb.Len() > 0 {
			strb.WriteByte(':')
		}
		strb.WriteString(strconv.FormatUint(uint64(seg), 16))
		vals[i<<1] = byte(seg >> 8)
		vals[(i<<1)+1] = byte(seg)
		bigInt = bigInt.Lsh(bigInt, uint(bitsPerSegment)).Or(bigInt, new(big.Int).SetInt64(int64(seg)))
		//bigInteger = bigInteger.shiftLeft(bitsPerSegment).add(BigInteger.valueOf(seg));
	}
	//try {
	strbStr := strb.String()
	ipaddressStr := t.createAddress(strbStr)
	addr := [5]*ipaddr.IPv6Address{}
	//IPv6Address addr[] = new IPv6Address[5];
	//int i = 0;
	addr[0] = t.createAddressFromIP(vals).ToIPv6()
	addr[1] = ipaddressStr.GetAddress().ToIPv6()
	ips := net.ParseIP(strbStr)
	ips2 := net.IP{vals[0], vals[1], vals[2], vals[3], vals[4], vals[5], vals[6], vals[7], vals[8], vals[9], vals[10], vals[11], vals[12], vals[13], vals[14], vals[15]}
	//InetAddress inetAddress1 = InetAddress.getByName(strb.toString());
	//InetAddress inetAddress2 = InetAddress.getByAddress(vals);
	ip, err := ipaddr.NewIPv6AddressFromBytes(ips)
	if err != nil {
		t.addFailure(newIPAddrFailure("failed unexpected error for "+strbStr+" error: "+err.Error(), ip.ToIP()))
	}
	ip2, err := ipaddr.NewIPv6AddressFromBytes(ips2)
	if err != nil {
		t.addFailure(newIPAddrFailure("failed unexpected error for "+strbStr+" error: "+err.Error(), ip2.ToIP()))
	}
	addr[2] = ip
	addr[3] = ip2
	//addr[2] = new IPv6Address((Inet6Address) inetAddress1);
	//addr[3] = new IPv6Address((Inet6Address) inetAddress2);
	ip3, err := ipaddr.NewIPv6AddressFromInt(bigInt)
	if err != nil {
		t.addFailure(newIPAddrFailure("failed unexpected error for "+strbStr+" error: "+err.Error(), ip2.ToIP()))
	}
	addr[4] = ip3
	/*
		addr[0] = t.createAddressFromIP(vals).ToIPv4();
					addr[1] = ipaddressStr.GetAddress().ToIPv4();
					addr[2] = t.createIPv4Address(intval);
					ips := net.ParseIP(strbStr)
					ips2 := net.IPv4(vals[0],vals[1],vals[2],vals[3])
			ip, err := ipaddr.NewIPv4AddressFromBytes(ips);
			if err != nil {
				t.addFailure(newIPAddrFailure("failed unexpected error for "+strbStr + " error: " + err.Error(), ip.ToIP()));
			}
			ip2, err := ipaddr.NewIPv4AddressFromBytes(ips2);
			if err != nil {
				t.addFailure(newIPAddrFailure("failed unexpected error for "+strbStr + " error: " + err.Error(), ip2.ToIP()));
			}
			addr[3] = ip;
					addr[4] = ip2;
					addr[5] = ipaddr.NewIPv4AddressFromUint32(intval);
					addr[6] = ipaddr.NewIPv4AddressFromUint32(uint32(bigInt.Uint64()));
	*/
	for j := 0; j < len(addr); j++ {
		for k := j; k < len(addr); k++ {
			if !addr[k].Equal(addr[j]) || !addr[j].Equal(addr[k]) {
				// 0 and 3 not matching ::1:2:3:4 and 1:2:3:4:5:6:7:8
				t.addFailure(newFailure("failed equals: "+addr[k].String()+" and "+addr[j].String(), ipaddressStr))
			}
		}
	}
	if decimal != "" {
		for i := 0; i < len(addr); i++ {
			if decimal != addr[i].GetValue().String() {
				t.addFailure(newFailure("failed equals: "+addr[i].GetValue().String()+" and "+decimal, ipaddressStr))
			}
			//if decimal != strconv.FormatUint(uint64(addr[i].Uint32Value()), 10)  {
			//	t.addFailure(newFailure("failed equals: " + strconv.FormatUint(uint64(addr[i].Uint32Value()), 10) + " and " + decimal,ipaddressStr));
			//}
		}
	}
	//if(decimal != null) {
	//	for(i = 0; i < addr.length; i++) {
	//		if(!decimal.equals(addr[i].getValue().toString())) {
	//			addFailure(new Failure("failed equals: " + addr[i].getValue() + " and " + decimal));
	//		}
	//	}
	//}
	//} catch(AddressValueException e) {
	//	addFailure(new Failure("failed unexpected: " + e));
	//} catch(UnknownHostException e) {
	//	addFailure(new Failure("failed unexpected: " + e));
	//}

}

func (t ipAddressTester) testInvalidIpv6Values() {
	bytes := []byte{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	bytes[0] = 1
	addr, err := ipaddr.NewIPv6AddressFromBytes(bytes)
	if err == nil {
		t.addFailure(newIPAddrFailure("failed expected error for "+addr.String(), addr.ToIP()))
	}
	addr, err = ipaddr.NewIPv6AddressFromBytes([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	if err != nil {
		t.addFailure(newIPAddrFailure("failed unexpected error for "+addr.String()+" error: "+err.Error(), addr.ToIP()))
	}
	addr, err = ipaddr.NewIPv6AddressFromBytes([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	if err != nil {
		t.addFailure(newIPAddrFailure("failed unexpected error for "+addr.String()+" error: "+err.Error(), addr.ToIP()))
	}
	addr, err = ipaddr.NewIPv6AddressFromBytes([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	if err != nil {
		t.addFailure(newIPAddrFailure("failed unexpected error for "+addr.String()+" error: "+err.Error(), addr.ToIP()))
	}
	addr, err = ipaddr.NewIPv6AddressFromBytes([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	if err != nil {
		t.addFailure(newIPAddrFailure("failed unexpected error for "+addr.String()+" error: "+err.Error(), addr.ToIP()))
	}
	addr = ipaddr.NewIPv6AddressFromVals(func(segmentIndex int) ipaddr.IPv6SegInt {
		var val = 0x10000 // will be truncated to 0
		return ipaddr.IPv6SegInt(val)
	})
	if !addr.IsZero() {
		t.addFailure(newIPAddrFailure("failed expected exception for "+addr.String(), addr.ToIP()))
	}
	addr = ipaddr.NewIPv6AddressFromVals(func(segmentIndex int) ipaddr.IPv6SegInt {
		var val = -1 // will be truncated to 0
		return ipaddr.IPv6SegInt(val)
	})
	if !addr.IsMax() {
		t.addFailure(newIPAddrFailure("failed expected exception for "+addr.String(), addr.ToIP()))
	}
	addr = ipaddr.NewIPv6AddressFromVals(func(segmentIndex int) ipaddr.IPv6SegInt {
		var val = 0xffff // will be truncated to 0
		return ipaddr.IPv6SegInt(val)
	})
	if !addr.IsMax() {
		t.addFailure(newIPAddrFailure("failed expected exception for "+addr.String(), addr.ToIP()))
	}

	//try {
	//	byte bytes[] = new byte[17];
	//	bytes[0] = 1;
	//	IPv6Address addr = new IPv6Address(bytes);
	//	addFailure(new Failure("failed expected exception for " + addr, addr));
	//} catch(AddressValueException e) {}
	//try {
	//	new IPv6Address(new byte[17]);
	//} catch(AddressValueException e) {
	//	addFailure(new Failure("unexpected exception " + e));
	//}
	//try {
	//	new IPv6Address(new byte[16]);
	//} catch(AddressValueException e) {
	//	addFailure(new Failure("unexpected exception " + e));
	//}try {
	//	new IPv6Address(new byte[15]);
	//} catch(AddressValueException e) {
	//	addFailure(new Failure("unexpected exception " + e));
	//}
	//try {
	//	new IPv6Address(new byte[14]);
	//} catch(AddressValueException e) {
	//	addFailure(new Failure("unexpected exception " + e));
	//}
	addr, err = ipaddr.NewIPv6AddressFromInt(new(big.Int).SetInt64(-1))
	if err == nil {
		t.addFailure(newIPAddrFailure("failed, expected error for -1", addr.ToIP()))
	}
	addr, err = ipaddr.NewIPv6AddressFromInt(new(big.Int))
	if err != nil || !addr.IsZero() {
		t.addFailure(newIPAddrFailure("failed, unexpected error for "+new(big.Int).String(), addr.ToIP()))
	}
	addr, err = ipaddr.NewIPv6AddressFromInt(one28())
	if err != nil || !addr.IsMax() {
		t.addFailure(newIPAddrFailure("failed, unexpected error for "+one28().String(), addr.ToIP()))
	}
	addr, err = ipaddr.NewIPv6AddressFromInt(new(big.Int).Add(one28(), bigOneConst()))
	if err == nil {
		t.addFailure(newIPAddrFailure("failed, expected error for "+new(big.Int).Add(one28(), bigOneConst()).String(), addr.ToIP()))
	}
	addr, err = ipaddr.NewIPv6AddressFromInt(new(big.Int).SetUint64(0xffffffff))
	if err != nil {
		t.addFailure(newIPAddrFailure("failed, unexpected error for "+new(big.Int).SetUint64(0xffffffff).String(), addr.ToIP()))
	}
	addr, err = ipaddr.NewIPv6AddressFromInt(new(big.Int).SetUint64(0x1ffffffff))
	if err != nil {
		t.addFailure(newIPAddrFailure("failed, unexpected error for "+new(big.Int).SetUint64(0x1ffffffff).String(), addr.ToIP()))
	}
	//try {
	//	new IPv6Address(BigInteger.valueOf(-1));//-1 becomes [ff] which is sign extended to 16 bytes like [ff][ff]...[ff]
	//} catch(AddressValueException e) {
	//	addFailure(new Failure("unexpected exception " + e));
	//}
	//BigInteger thirtyTwo = BigInteger.valueOf(0xffffffffL);
	//BigInteger one28 = thirtyTwo.shiftLeft(96).or(thirtyTwo.shiftLeft(64).or(thirtyTwo.shiftLeft(32).or(thirtyTwo)));
	//try {
	//	new IPv6Address(one28);
	//} catch(AddressValueException e) {
	//	addFailure(new Failure("unexpected exception " + e));
	//}
	//try {
	//	IPv6Address addr = new IPv6Address(one28.add(BigInteger.ONE));
	//	addFailure(new Failure("failed expected exception for " + addr, addr));
	//} catch(AddressValueException e) {}
	//try {
	//	new IPv6Address(BigInteger.valueOf(0xffffffffL));//must make it a long so it is not negative
	//} catch(AddressValueException e) {
	//	addFailure(new Failure("failed unexpected: " + e));
	//}
	//try {
	//	IPv6Address addr = new IPv6Address(new SegmentValueProvider() {
	//		@Override
	//		public int getValue(int segmentIndex) {
	//			return 0x10000;
	//		}
	//	});
	//	addFailure(new Failure("failed expected exception for " + addr, addr));
	//} catch(AddressValueException e) {}
	//try {
	//	IPv6Address addr = new IPv6Address(new SegmentValueProvider() {
	//		@Override
	//		public int getValue(int segmentIndex) {
	//			return -1;
	//		}
	//	});
	//	addFailure(new Failure("failed expected exception for " + addr, addr));
	//} catch(AddressValueException e) {}
	//try {
	//	new IPv6Address(new SegmentValueProvider() {
	//		@Override
	//		public int getValue(int segmentIndex) {
	//			return 0xffff;
	//		}
	//	});
	//} catch(AddressValueException e) {
	//	addFailure(new Failure("unexpected exception " + e));
	//	e.printStackTrace();
	//}
}

func (t ipAddressTester) testSub(one, two string, resultStrings []string) {
	string := t.createAddress(one)
	sub := t.createAddress(two)
	addr := string.GetAddress()
	subAddr := sub.GetAddress()
	//try {
	res := addr.Subtract(subAddr)
	if len(resultStrings) == 0 {
		if len(res) != 0 {
			t.addFailure(newIPAddrFailure("non-null subtraction with "+addr.String(), subAddr))
		}
	} else {
		if len(resultStrings) != len(res) {
			t.addFailure(newIPAddrFailure(fmt.Sprintf("length mismatch %v with %v", res, resultStrings), subAddr))
		} else {
			results := make([]*ipaddr.IPAddress, len(resultStrings))
			for i := 0; i < len(resultStrings); i++ {
				results[i] = t.createAddress(resultStrings[i]).GetAddress()
			}
			for _, r := range res {
				found := false
				for _, result := range results {
					if r.Equal(result) && r.GetNetworkPrefixLen().Equal(result.GetNetworkPrefixLen()) {
						found = true
						break
					}
				}
				if !found {
					t.addFailure(newIPAddrFailure(fmt.Sprintf("mismatch with %v", resultStrings), r))
				}
			}
		}
	}
	//} catch(IncompatibleAddressException e) {
	//	addFailure(new Failure("threw " + e + " when subtracting " + subAddr, addr));
	//}
	t.incrementTestCount()
}

func (t ipAddressTester) testIntersect(one, two, resultString string) {
	t.testIntersectLowest(one, two, resultString, false)
}

func (t ipAddressTester) testIntersectLowest(one, two, resultString string, lowest bool) {
	str := t.createAddress(one)
	string2 := t.createAddress(two)
	addr := str.GetAddress()
	addr2 := string2.GetAddress()
	r := addr.Intersect(addr2)
	if resultString == "" {
		if r != nil {
			t.addFailure(newIPAddrFailure("non-null intersection with "+addr.String(), addr2))
		}
	} else {
		result := t.createAddress(resultString).GetAddress()
		if lowest {
			result = result.GetLower()
		}
		if !r.Equal(result) || !r.GetNetworkPrefixLen().Equal(result.GetNetworkPrefixLen()) {
			t.addFailure(newIPAddrFailure("mismatch with "+result.String(), r))
		}
	}
	t.incrementTestCount()
}

func (t ipAddressTester) testToPrefixBlock(addrString, subnetString string) {
	str := t.createAddress(addrString)
	string2 := t.createAddress(subnetString)
	addr := str.GetAddress()
	subnet := string2.GetAddress()
	prefixBlock := addr.ToPrefixBlock()
	if !subnet.Equal(prefixBlock) {
		t.addFailure(newIPAddrFailure("prefix block mismatch "+subnet.String()+" with block "+prefixBlock.String(), addr))
	} else if !subnet.GetNetworkPrefixLen().Equal(prefixBlock.GetNetworkPrefixLen()) {
		t.addFailure(newIPAddrFailure("prefix block length mismatch "+subnet.GetNetworkPrefixLen().String()+" and "+prefixBlock.GetNetworkPrefixLen().String(), addr))
	}
	t.incrementTestCount()
}

func (t ipAddressTester) testZeroHost(addrString, zeroHostString string) {
	str := t.createAddress(addrString)
	string2 := t.createAddress(zeroHostString)
	addr := str.GetAddress()
	specialHost := string2.GetAddress()
	transformedHost, err := addr.ToZeroHost()
	if err != nil {
		t.addFailure(newIPAddrFailure("unexpected error max host: "+err.Error(), addr))
	}

	hostSection := transformedHost.GetHostSection()
	if hostSection.GetSegmentCount() > 0 && !hostSection.IsZero() {
		t.addFailure(newIPAddrFailure("non-zero host "+hostSection.String(), addr))
	}

	if !transformedHost.GetNetworkPrefixLen().Equal(specialHost.GetNetworkPrefixLen()) {
		t.addFailure(newIPAddrFailure("prefix length mismatch "+transformedHost.GetNetworkPrefixLen().String()+" and "+specialHost.GetNetworkPrefixLen().String(), addr))
	}

	//for i := 0; i < addr.GetSegmentCount(); i++ {
	//	seg := addr.GetSegment(i)
	//	for j := 0; j < 2; j++ {
	//TODO LATER consider re-adding toZeroHost on segments, and then if you do, put back the old tests here using it
	//IPAddressSegment newSeg = seg.toZeroHost();
	//if(seg.isPrefixed()) {
	//	Integer segPrefix = seg.getSegmentPrefixLength();
	//	boolean allPrefsSubnets = seg.getNetwork().getPrefixConfiguration().allPrefixedAddressesAreSubnets();
	//	if(allPrefsSubnets) {
	//		if(newSeg.isPrefixed()) {
	//			addFailure(new Failure("prefix length unexpected " + newSeg.getSegmentPrefixLength(), seg));
	//		}
	//	} else {
	//		if(!newSeg.isPrefixed() || !segPrefix.equals(newSeg.getSegmentPrefixLength())) {
	//			addFailure(new Failure("prefix length mismatch " + segPrefix + " and " + newSeg.getSegmentPrefixLength(), seg));
	//		}
	//		IPAddressSegment expected = seg.toNetworkSegment(segPrefix).getLower();
	//		if(!newSeg.getLower().equals(expected)) {
	//			newSeg = seg.toZeroHost();
	//			addFailure(new Failure("new seg mismatch " + newSeg + " expected: " + expected, newSeg));
	//		}
	//		expected = seg.toNetworkSegment(segPrefix).getUpper().toZeroHost();
	//		if(!newSeg.getUpper().equals(expected)) {
	//			newSeg = seg.toZeroHost();
	//			addFailure(new Failure("new seg mismatch " + newSeg + " expected: " + expected, newSeg));
	//		}
	//	}
	//} else if(newSeg.isPrefixed() || !newSeg.isZero()) {
	//	addFailure(new Failure("new seg not zero " + newSeg, newSeg));
	//}
	//seg = newSeg
	//	}
	//}
	t.incrementTestCount()
}

func (t ipAddressTester) testZeroNetwork(addrString, zeroNetworkString string) {
	str := t.createAddress(addrString)
	string2 := t.createAddress(zeroNetworkString)
	addr := str.GetAddress()
	zeroNetwork := string2.GetAddress()
	transformedNetwork := addr.ToZeroNetwork()
	if !zeroNetwork.Equal(transformedNetwork) {
		//if(!prefixConfiguration.zeroHostsAreSubnets() && !zeroNetwork.equals(transformedNetwork)) {
		t.addFailure(newIPAddrFailure("mismatch "+zeroNetwork.String()+" with network "+transformedNetwork.String(), addr))
	}
	//if(!prefixConfiguration.allPrefixedAddressesAreSubnets()) {
	networkSection := transformedNetwork.GetNetworkSection()
	if networkSection.GetSegmentCount() > 0 && !networkSection.IsZero() {
		t.addFailure(newIPAddrFailure("non-zero network "+networkSection.String(), addr))
	}
	//}
	if !transformedNetwork.GetNetworkPrefixLen().Equal(zeroNetwork.GetNetworkPrefixLen()) {
		t.addFailure(newIPAddrFailure("network prefix length mismatch "+transformedNetwork.GetNetworkPrefixLen().String()+" and "+zeroNetwork.GetNetworkPrefixLen().String(), addr))
	}
	t.incrementTestCount()
}

func (t ipAddressTester) testMaxHost(addrString, maxHostString string) {
	str := t.createAddress(addrString)
	string2 := t.createAddress(maxHostString)
	addr := str.GetAddress()
	specialHost := string2.GetAddress()
	transformedHost, err := addr.ToMaxHost()
	if err != nil {
		t.addFailure(newIPAddrFailure("unexpected error max host: "+err.Error(), addr))
	}
	if !specialHost.Equal(transformedHost) {
		t.addFailure(newIPAddrFailure("mismatch "+specialHost.String()+" with host "+transformedHost.String(), addr))
	} else if !transformedHost.GetNetworkPrefixLen().Equal(specialHost.GetNetworkPrefixLen()) {
		t.addFailure(newIPAddrFailure("prefix length mismatch "+transformedHost.GetNetworkPrefixLen().String()+" and "+specialHost.GetNetworkPrefixLen().String(), addr))
	}
	t.incrementTestCount()
}

func (t ipAddressTester) testSplitBytes(addressStr string) {
	addr := t.createAddress(addressStr).GetAddress()
	t.testSplitBytesAddr(addr)
}

func (t ipAddressTester) testSplitBytesAddr(addr *ipaddr.IPAddress) {
	bytes := addr.Bytes()
	addresses := reconstitute(addr.GetIPVersion(), bytes, addr.GetBytesPerSegment())
	if addr.IsMultiple() {
		for _, addrNext := range addresses {
			if !addr.GetLower().Equal(addrNext) {
				t.addFailure(newIPAddrFailure("lower reconstitute failure: "+addrNext.String(), addr))
			}
		}
		bytes = addr.UpperBytes()
		addresses = reconstitute(addr.GetIPVersion(), bytes, addr.GetBytesPerSegment())
		for _, addrNext := range addresses {
			if !addr.GetUpper().Equal(addrNext) {
				t.addFailure(newIPAddrFailure("upper reconstitute failure: "+addrNext.String(), addr))
			}
		}
	} else {
		for _, addrNext := range addresses {
			if !addr.Equal(addrNext) {
				t.addFailure(newIPAddrFailure("reconstitute failure: "+addrNext.String(), addr))
			}
		}
	}
}

func (t ipAddressTester) testByteExtension(addrString string, byteRepresentations [][]byte) {
	addrStr := t.createAddress(addrString)
	addr := addrStr.GetAddress()
	//ArrayList<IPAddress> all = new ArrayList<IPAddress>();
	var all []*ipaddr.IPAddress
	if addr.IsIPv4() {
		for _, byteRepresentation := range byteRepresentations {
			ipv4Addr, err := ipaddr.NewIPv4AddressFromBytes(byteRepresentation)
			if err != nil {
				t.addFailure(newFailure("unexpected error: "+err.Error(), addrStr))
			}
			all = append(all, ipv4Addr.ToIP())

			//byte bytes[] = new byte[48];
			//Arrays.fill(bytes, (byte) 5); // this just throws some garbage in those bytes
			//System.arraycopy(byteRepresentation, 0, bytes, 5, byteRepresentation.length);
			//ipv4Addr = new IPv4Address(bytes, 5, 5 + byteRepresentation.length);

			//bytes := make([]byte, 32);
			//ipv4Addr, err = ipaddr.NewIPv4AddressFromBytes(bytes);
			//if err != nil {
			//	t.addFailure(newIPAddrFailure("failed unexpected error for "+addrString+" error: "+err.Error(), ipv4Addr.ToIP()))
			//}
			//all = append(all, ipv4Addr.ToIP())
		}
		all = append(all, addr)
		var lastBytes []byte
		//byte lastBytes[] = null;
		for i := 0; i < len(all); i++ {
			byts := all[i].Bytes()
			//byte bytes[] = all.get(i).getBytes();
			if lastBytes == nil {
				lastBytes = byts
				if len(byts) != ipaddr.IPv4ByteCount {
					t.addFailure(newFailure("bytes length "+strconv.Itoa(len(byts)), addrStr))
				}
				ipv4Addr, err := ipaddr.NewIPv4AddressFromBytes(byts)
				if err != nil {
					t.addFailure(newFailure("unexpected error: "+err.Error(), addrStr))
				}
				all = append(all, ipv4Addr.ToIP())
				ipv4Addr = ipaddr.NewIPv4AddressFromUint32(uint32(new(big.Int).SetBytes(byts).Uint64()))
				all = append(all, ipv4Addr.ToIP())
			} else if !bytes.Equal(lastBytes, byts) {
				t.addFailure(newFailure(fmt.Sprintf("generated addr bytes mismatch %v and %v", byts, lastBytes), addrStr))
			}
		}
	} else {
		for _, byteRepresentation := range byteRepresentations {
			ipv6Addr, err := ipaddr.NewIPv6AddressFromBytes(byteRepresentation)
			if err != nil {
				t.addFailure(newFailure("unexpected error: "+err.Error(), addrStr))
			}
			all = append(all, ipv6Addr.ToIP())

			//byte bytes[] = new byte[48];
			//Arrays.fill(bytes, (byte) 5);
			//System.arraycopy(byteRepresentation, 0, bytes, 5, byteRepresentation.length);
			//ipv6Addr = new IPv6Address(bytes, 5, 5 + byteRepresentation.length);
			//all.add(ipv6Addr);
		}

		all = append(all, addr)
		var lastBytes []byte
		//byte lastBytes[] = null;
		for i := 0; i < len(all); i++ {
			byts := all[i].Bytes()
			//byte bytes[] = all.get(i).getBytes();
			if lastBytes == nil {
				lastBytes = byts
				if len(byts) != ipaddr.IPv6ByteCount {
					t.addFailure(newFailure("bytes length "+strconv.Itoa(len(byts)), addrStr))
				}
				ipv6Addr, err := ipaddr.NewIPv6AddressFromBytes(byts)
				if err != nil {
					t.addFailure(newFailure("unexpected error: "+err.Error(), addrStr))
				}
				all = append(all, ipv6Addr.ToIP())

				b := new(big.Int).SetBytes(byts)
				//BigInteger b = new BigInteger(bytes);
				//ipv6Addr = new IPv6Address(b);
				all = append(all, ipv6Addr.ToIP())
				bs := b.Bytes()
				ipv6Addr, err = ipaddr.NewIPv6AddressFromBytes(bs)
				if err != nil {
					t.addFailure(newFailure("unexpected error: "+err.Error(), addrStr))
				}
				all = append(all, ipv6Addr.ToIP())

				//ipv4Addr = ipaddr.NewIPv4AddressFromUint32(uint32(new(big.Int).SetBytes(byts).Uint64()));
				//all = append(all, ipv4Addr.ToIP())
			} else if !bytes.Equal(lastBytes, byts) {
				t.addFailure(newFailure(fmt.Sprintf("generated addr bytes mismatch %v and %v", byts, lastBytes), addrStr))
			}
		}
	}
	var allBytes [][]byte
	for _, addr := range all {
		allBytes = append(allBytes, addr.Bytes())
	}
	for _, addr := range all {
		for _, addr2 := range all {
			if !addr.Equal(addr2) {
				t.addFailure(newFailure("addr mismatch "+addr.String()+" and "+addr2.String(), addrStr))
			}
		}
	}
	for _, b := range allBytes {
		for _, b2 := range allBytes {
			if !bytes.Equal(b, b2) {
				t.addFailure(newFailure(fmt.Sprintf("addr mismatch %v and %v", b, b2), addrStr))
			}
		}
	}
	t.incrementTestCount()
}

func reconstitute(version ipaddr.IPVersion, bytes []byte, segmentByteSize int) []*ipaddr.IPAddress {
	//IPAddressCreator<?, ?, ?, S, ?> creator = (IPAddressCreator<?, ?, ?, S, ?>) originalAddress.getNetwork().getAddressCreator();
	var addresses []*ipaddr.IPAddress
	//ArrayList<IPAddress> addresses = new ArrayList<IPAddress>();
	sets := createSets(bytes, segmentByteSize)
	creator := ipaddr.IPAddressCreator{version}
	for _, set := range sets {
		//for(byte set[][] : sets) {
		//ArrayList<S> segments = new ArrayList<S>();
		//ArrayList<S> segments2 = new ArrayList<S>();
		var segments, segments2 []*ipaddr.IPAddressSegment

		for i, ind := 0, 0; i < len(set); i++ {
			setBytes := set[i]
			segs := creator.NewIPSectionFromBytes(setBytes).GetSegments()
			segs2 := creator.NewIPSectionFromBytes(bytes[ind : ind+len(setBytes)]).GetSegments()

			if i%2 == 1 {
				segs, segs2 = segs2, segs
			}
			ind += len(setBytes)
			segments = append(segments, segs...)
			segments2 = append(segments2, segs2...)
			//segments.addAll(Arrays.asList(segs));
			//segments2.addAll(Arrays.asList(seg2));
		}
		addr1, _ := ipaddr.NewIPAddressFromSegments(segments)
		addr2, _ := ipaddr.NewIPAddressFromSegments(segments2)
		addresses = append(addresses, addr1)
		addresses = append(addresses, addr2)
		//S segs[] = creator.createSegmentArray(segments.size());
		//IPAddress addr1 = creator.createAddress(segments.toArray(segs));
		//IPAddress addr2 = creator.createAddress(segments2.toArray(segs));
		//addresses.add(addr1);
		//addresses.add(addr2);
	}
	return addresses
}

func createSets(bytes []byte, segmentByteSize int) [][][]byte {
	//break into two, and three
	segmentLength := len(bytes) / segmentByteSize
	sets := [][][]byte{
		{
			make([]byte, (segmentLength/2)*segmentByteSize), make([]byte, (segmentLength-segmentLength/2)*segmentByteSize),
		},
		{
			make([]byte, (segmentLength/3)*segmentByteSize), make([]byte, (segmentLength/3)*segmentByteSize), make([]byte, (segmentLength-2*(segmentLength/3))*segmentByteSize),
		},
	}
	for _, set := range sets {
		for i, ind := 0, 0; i < len(set); i++ {
			part := set[i]
			copy(part, bytes[ind:])
			//System.arraycopy(bytes, ind, part, 0, part.length);
			ind += len(part)
		}
	}
	return sets
}

func (t ipAddressTester) testIsPrefixBlock(
	orig string,
	isPrefixBlock,
	isSinglePrefixBlock bool) {
	original := t.createAddress(orig).GetAddress()
	if isPrefixBlock != original.IsPrefixBlock() {
		t.addFailure(newIPAddrFailure("is prefix block: "+strconv.FormatBool(original.IsPrefixBlock())+" expected: "+strconv.FormatBool(isPrefixBlock), original))
	} else if isSinglePrefixBlock != original.IsSinglePrefixBlock() {
		t.addFailure(newIPAddrFailure("is single prefix block: "+strconv.FormatBool(original.IsSinglePrefixBlock())+" expected: "+strconv.FormatBool(isSinglePrefixBlock), original))
	}
	t.incrementTestCount()
}

func (t ipAddressTester) testPrefixBlocks(
	orig string,
	prefix ipaddr.BitCount,
	containsPrefixBlock,
	containsSinglePrefixBlock bool) {
	original := t.createAddress(orig).GetAddress()
	if containsPrefixBlock != original.ContainsPrefixBlock(prefix) {
		t.addFailure(newIPAddrFailure("contains prefix block: "+strconv.FormatBool(original.ContainsPrefixBlock(prefix))+" expected: "+strconv.FormatBool(containsPrefixBlock), original))
	} else if containsSinglePrefixBlock != original.ContainsSinglePrefixBlock(prefix) {
		t.addFailure(newIPAddrFailure("contains single prefix block: "+strconv.FormatBool(original.ContainsSinglePrefixBlock(prefix))+" expected: "+strconv.FormatBool(containsPrefixBlock), original))
	}
	t.incrementTestCount()
}

func (t ipAddressTester) testIncrement(originalStr string, increment int64, resultStr string) {
	var addr *ipaddr.IPAddress
	if resultStr != "" {
		addr = t.createAddress(resultStr).GetAddress()
	}
	t.testBase.testIncrement(t.createAddress(originalStr).GetAddress().ToAddressBase(), increment, addr.ToAddressBase())
}

func (t ipAddressTester) testLeadingZeroAddr(addrStr string, hasLeadingZeros bool) {
	//try {
	str := t.createAddress(addrStr)
	_, err := str.ToAddress()
	if err != nil {
		t.addFailure(newFailure("unexpected error "+err.Error(), str))
	}
	//try {
	params := new(addrformat.IPAddressStringParametersBuilder).
		GetIPv4AddressParametersBuilder().AllowLeadingZeros(false).GetParentBuilder().
		GetIPv6AddressParametersBuilder().AllowLeadingZeros(false).GetParentBuilder().ToParams()
	str = ipaddr.NewIPAddressStringParams(addrStr, params)
	_, err = str.ToAddress()
	if err == nil {
		if hasLeadingZeros {
			t.addFailure(newFailure("leading zeros allowed when forbidden", str))
		}
	} else {
		if !hasLeadingZeros {
			t.addFailure(newFailure("leading zeros not there", str))
		}
	}

	t.incrementTestCount()
}

func (t ipAddressTester) testInetAtonLeadingZeroAddr(addrStr string, hasLeadingZeros, hasInetAtonLeadingZeros, isInetAtonOctal bool) {
	//try {
	str := t.createInetAtonAddress(addrStr)
	addr, err := str.ToAddress()
	if err != nil {
		t.addFailure(newFailure("unexpected error "+err.Error(), str))
	}
	value := addr.GetValue()

	params := new(addrformat.IPAddressStringParametersBuilder).
		GetIPv4AddressParametersBuilder().AllowLeadingZeros(false).GetParentBuilder().ToParams()
	str = ipaddr.NewIPAddressStringParams(addrStr, params)
	_, err = str.ToAddress()
	if err == nil {
		if hasLeadingZeros {
			t.addFailure(newFailure("leading zeros allowed when forbidden", str))
		}
	} else {
		if !hasLeadingZeros {
			t.addFailure(newFailure("leading zeros not there", str))
		}
	}

	params = new(addrformat.IPAddressStringParametersBuilder).Set(params).GetIPv4AddressParametersBuilder().AllowLeadingZeros(true).Allow_inet_aton(true).Allow_inet_aton_leading_zeros(false).GetParentBuilder().ToParams()
	str = ipaddr.NewIPAddressStringParams(addrStr, params)
	_, err = str.ToAddress()
	if err == nil {
		if hasInetAtonLeadingZeros {
			t.addFailure(newFailure("leading zeros allowed when forbidden", str))
		}
	} else {
		if !hasInetAtonLeadingZeros {
			t.addFailure(newFailure("leading zeros not there", str))
		}
	}

	params = new(addrformat.IPAddressStringParametersBuilder).Set(params).Allow_inet_aton(false).ToParams()
	str = ipaddr.NewIPAddressStringParams(addrStr, params)
	_, err = str.ToAddress()
	if isInetAtonOctal {
		//try {
		addr, err = str.ToAddress()
		if err != nil {
			t.addFailure(newFailure("inet aton octal should be decimal, unexpected error: "+err.Error(), str))
		}
		value2 := addr.GetValue()
		octalDiffers := false
		for i := 0; i < addr.GetSegmentCount(); i++ {
			octalDiffers = octalDiffers || addr.GetSegment(i).GetSegmentValue() >= 7
		}
		valsEqual := value.Cmp(value2) == 0
		if !octalDiffers {
			valsEqual = !valsEqual
		}
		if valsEqual {
			t.addFailure(newFailure("inet aton octal should be unequal", str))
		}
		//} catch(AddressStringException e) {
		//	addFailure(new Failure("inet aton octal should be decimal", str));
		//}
	} else if hasLeadingZeros { // if not octal but has leading zeros, then must be hex
		_, err = str.ToAddress()
		if err == nil {
			t.addFailure(newFailure("inet aton hex should be forbidden", str))
		}
	} else { // neither octal nor hex
		//try {
		addr, err = str.ToAddress()
		if err != nil {
			t.addFailure(newFailure("inet aton should have no effect, unexpected error: "+err.Error(), str))
		}
		value2 := addr.GetValue()
		if value.Cmp(value2) != 0 {
			t.addFailure(newFailure("should be same value", str))
		}
		//} catch(AddressStringException e) {
		//	addFailure(new Failure("inet aton should have no effect", string));
		//}
	}
	//} catch(AddressStringException e) {
	//	addFailure(new Failure(e.toString()));
	//} catch(IncompatibleAddressException e) {
	//	addFailure(new Failure(e.toString()));
	//} catch(RuntimeException e) {
	//	addFailure(new Failure(e.toString()));
	//}
	t.incrementTestCount()
}

func (t ipAddressTester) testRangeExtend(lower1, higher1, lower2, higher2, resultLower, resultHigher string) {
	t.testRangeExtendImpl(lower1, higher1, lower2, higher2, resultLower, resultHigher)
	t.testRangeExtendImpl(lower2, higher2, lower1, higher1, resultHigher, resultLower)
}

func (t ipAddressTester) testRangeExtendImpl(lower1, higher1, lower2, higher2, resultLower, resultHigher string) {
	var addr, addr2 *ipaddr.IPAddress
	var range1, range2, result2 *ipaddr.IPAddressSeqRange

	addr = t.createAddress(lower1).GetAddress()
	if higher1 == "" {
		range1 = addr.ToSequentialRange()
	} else {
		addr2 = t.createAddress(higher1).GetAddress()
		range1 = addr.SpanWithRange(addr2)
	}

	addr = t.createAddress(lower2).GetAddress()
	if higher2 == "" {
		result2 = range1.Extend(addr.ToSequentialRange())
		range2 = addr.ToSequentialRange()
	} else {
		addr2 = t.createAddress(higher2).GetAddress()
		range2 = addr.SpanWithRange(addr2)
	}

	result := range1.Extend(range2)
	if result2 != nil {
		if !result.Equal(result2) {
			t.addFailure(newIPAddrFailure("mismatch result "+result.String()+"' with '"+result2.String()+"'", addr))
		}
	}
	if resultLower == "" {
		if result != nil {
			t.addFailure(newIPAddrFailure("mismatch result "+result.String()+" expected null extending '"+range1.String()+"' with '"+range2.String()+"'", addr))
		}
	} else {
		addr = t.createAddress(resultLower).GetAddress()
		addr2 = t.createAddress(resultHigher).GetAddress()
		expectedResult := addr.SpanWithRange(addr2)
		if !result.Equal(expectedResult) {
			t.addFailure(newIPAddrFailure("mismatch result '"+result.String()+"' expected '"+expectedResult.String()+"' extending '"+range1.String()+"' with '"+range2.String()+"'", addr))
		}
	}
	t.incrementTestCount()
}

func (t ipAddressTester) testRangeJoin(lower1, higher1, lower2, higher2, resultLower, resultHigher string) {
	t.testRangeJoinImpl(lower1, higher1, lower2, higher2, resultLower, resultHigher)
	t.testRangeJoinImpl(lower2, higher2, lower1, higher1, resultHigher, resultLower)
}

func (t ipAddressTester) testRangeJoinImpl(lower1, higher1, lower2, higher2, resultLower, resultHigher string) {
	addr := t.createAddress(lower1).GetAddress()
	addr2 := t.createAddress(higher1).GetAddress()
	range1 := addr.SpanWithRange(addr2)

	addr = t.createAddress(lower2).GetAddress()
	addr2 = t.createAddress(higher2).GetAddress()
	range2 := addr.SpanWithRange(addr2)

	result := range1.JoinTo(range2)
	if resultLower == "" {
		if result != nil {
			t.addFailure(newIPAddrFailure(fmt.Sprintf("mismatch result %v expected null joining '"+addr.String()+"' with '"+addr2.String()+"'", result), addr))
		}
	} else {
		addr = t.createAddress(resultLower).GetAddress()
		addr2 = t.createAddress(resultHigher).GetAddress()
		expectedResult := addr.SpanWithRange(addr2)
		if !result.Equal(expectedResult) {
			t.addFailure(newIPAddrFailure(fmt.Sprintf("mismatch result %v expected '"+expectedResult.String()+"' joining '"+addr.String()+"' with '"+addr2.String()+"'", result), addr))
		}

	}
	t.incrementTestCount()
}

func (t ipAddressTester) testRangeIntersect(lower1, higher1, lower2, higher2, resultLower, resultHigher string) {
	t.testRangeIntersectImpl(lower1, higher1, lower2, higher2, resultLower, resultHigher)
	t.testRangeIntersectImpl(lower2, higher2, lower1, higher1, resultHigher, resultLower)
}

func (t ipAddressTester) testRangeIntersectImpl(lower1, higher1, lower2, higher2, resultLower, resultHigher string) {
	addr := t.createAddress(lower1).GetAddress()
	addr2 := t.createAddress(higher1).GetAddress()
	range1 := addr.SpanWithRange(addr2)

	addr = t.createAddress(lower2).GetAddress()
	addr2 = t.createAddress(higher2).GetAddress()
	range2 := addr.SpanWithRange(addr2)

	result := range1.Intersect(range2)
	if resultLower == "" {
		if result != nil {
			t.addFailure(newIPAddrFailure("mismatch result "+result.String()+" expected null intersecting '"+addr.String()+"' with '"+addr2.String()+"'", addr))
		}
	} else {
		addr := t.createAddress(resultLower).GetAddress()
		addr2 := t.createAddress(resultHigher).GetAddress()
		expectedResult := addr.SpanWithRange(addr2)
		if !result.Equal(expectedResult) {
			t.addFailure(newIPAddrFailure("mismatch result '"+result.String()+"' expected '"+expectedResult.String()+"' intersecting '"+addr.String()+"' with '"+addr2.String()+"'", addr))
		}
	}
	t.incrementTestCount()
}

func (t ipAddressTester) testRangeSubtract(lower1, higher1, lower2, higher2 string, resultPairs ...string) {
	addr := t.createAddress(lower1).GetAddress()
	addr2 := t.createAddress(higher1).GetAddress()
	range1 := addr.SpanWithRange(addr2)

	addr = t.createAddress(lower2).GetAddress()
	addr2 = t.createAddress(higher2).GetAddress()
	range2 := addr.SpanWithRange(addr2)

	result := range1.Subtract(range2)
	if len(resultPairs) == 0 {
		if len(result) != 0 {
			t.addFailure(newIPAddrFailure(fmt.Sprintf("mismatch result %v expected zero length result subtracting '"+addr2.String()+"' from '"+addr.String()+"'", result), addr))
		}
	} else { //resultPairs.length >= 2
		addr = t.createAddress(resultPairs[0]).GetAddress()
		addr2 = t.createAddress(resultPairs[1]).GetAddress()
		expectedResult := addr.SpanWithRange(addr2)
		if len(result) == 0 || !result[0].Equal(expectedResult) {
			t.addFailure(newIPAddrFailure(fmt.Sprintf("mismatch result %v expected '"+expectedResult.String()+"' subtracting '"+addr2.String()+"' from '"+addr.String()+"'", result), addr))
		} else if len(resultPairs) == 4 {
			addr = t.createAddress(resultPairs[2]).GetAddress()
			addr2 = t.createAddress(resultPairs[3]).GetAddress()
			expectedResult = addr.SpanWithRange(addr2)
			if len(result) == 1 || !result[1].Equal(expectedResult) {
				t.addFailure(newIPAddrFailure(fmt.Sprintf("mismatch result %v expected '"+expectedResult.String()+"' subtracting '"+addr2.String()+"' from '"+addr.String()+"'", result), addr))
			}
		} else if len(result) > 1 {
			t.addFailure(newIPAddrFailure(fmt.Sprintf("mismatch result %v expected %v ranges subtracting '"+addr2.String()+"' from '"+addr.String()+"'", result, len(resultPairs)/2), addr))
		}
	}
	t.incrementTestCount()
}

// divs is an array with the series of values or range of values in the grouping
// divs must be an []interface{} with each element a *big.Int/int/uint/uint64 or an array of two *big.Int/int/uint/uint64
// Alternatively, instead of supplying Object[1] you can supply the first and only element instead
func (t ipAddressTester) testAddressStringRangeP(address string, isIncompatibleAddress, isMaskedIncompatibleAddress bool, lowerAddress, upperAddress string, divs interface{}, prefixLength ipaddr.PrefixLen, isSequential *bool) {
	addrStr := t.createAddress(address)
	//TODO LATER this code and the calling tests are all ready to go once I support toDivisionGrouping,
	//just a little more Java to go translation in here is needed, but not much.  I left some of the Java types to help with clarity.

	//IPAddressDivisionSeries s, err := addrStr.ToDivisionGrouping();
	//if err != nil {
	//			if !isMaskedIncompatibleAddress {
	//				t.addFailure(newFailure("address " + addrStr.String() + " produced error " + e.Error() + " when getting grouping ", addrStr));
	//			}
	//} else if(isMaskedIncompatibleAddress) {
	//	t.addFailure(newFailure("masked incompatible address " + addrStr.String() + " did not produce error when getting grouping " + s.String(), addrStr));
	//}
	if !isMaskedIncompatibleAddress {
		var divisions []interface{}
		if bidivs, ok := divs.([2]*big.Int); ok {
			divisions = []interface{}{bidivs}
		} else if bidiv, ok := divs.(*big.Int); ok {
			divisions = []interface{}{bidiv}
		} else if intdivs, ok := divs.([2]int); ok {
			divisions = []interface{}{intdivs}
		} else if intdiv, ok := divs.(int); ok {
			divisions = []interface{}{intdiv}
		} else if uintdivs, ok := divs.([2]uint); ok {
			divisions = []interface{}{uintdivs}
		} else if uintdiv, ok := divs.(uint); ok {
			divisions = []interface{}{uintdiv}
		} else if uint64divs, ok := divs.([2]uint64); ok {
			divisions = []interface{}{uint64divs}
		} else if uint64div, ok := divs.(uint64); ok {
			divisions = []interface{}{uint64div}
		} else {
			divisions = divs.([]interface{})
		}
		//if s.getDivisionCount() != len(divisions) {
		//	t.addFailure(newFailure("grouping " + s.String() + " for " + addrStr.String() + " does not have expected length " + strconv.Itoa(len(divisions)), addrStr));
		//}
		var totalBits ipaddr.BitCount
		for i := 0; i < len(divisions); i++ {
			//IPAddressGenericDivision d = s.GetDivision(i);
			//int divBits = d.getBitCount();
			//totalBits += divBits;
			//BigInteger val := d.GetValue();
			//BigInteger upperVal := d.GetUpperValue();
			expectedDivision := divisions[i]
			var expectedUpper, expectedLower *big.Int
			if expected, ok := expectedDivision.(int); ok {
				expectedUpper = new(big.Int).SetInt64(int64(expected))
				expectedLower = expectedUpper
			} else if expected, ok := expectedDivision.([]int); ok {
				expectedUpper = new(big.Int).SetUint64(uint64(expected[0]))
				expectedLower = new(big.Int).SetUint64(uint64(expected[1]))
			} else if expected, ok := expectedDivision.(uint); ok {
				expectedUpper = new(big.Int).SetUint64(uint64(expected))
				expectedLower = expectedUpper
			} else if expected, ok := expectedDivision.([]uint); ok {
				expectedUpper = new(big.Int).SetUint64(uint64(expected[0]))
				expectedLower = new(big.Int).SetUint64(uint64(expected[1]))
			} else if expected, ok := expectedDivision.(uint64); ok {
				expectedUpper = new(big.Int).SetUint64(expected)
				expectedLower = expectedUpper
			} else if expected, ok := expectedDivision.([]uint64); ok {
				expectedUpper = new(big.Int).SetUint64(expected[0])
				expectedLower = new(big.Int).SetUint64(expected[1])
			} else if expected, ok := expectedDivision.([]*big.Int); ok {
				expectedLower = expected[0]
				expectedUpper = expected[1]
			} else if expected, ok := expectedDivision.(*big.Int); ok {
				expectedUpper = expectedLower
				expectedLower = expected
			}
			//if val.Cmp(expectedLower) != 0 {
			//	t.addFailure(newFailure("division val " + val.String() + " for " + addrStr.String() + " is not expected val " + expectedLower.String(), addrStr));
			//} else if(upperVal.Cmp(expectedUpper) != 0) {
			//	t.addFailure(newFailure("upper division val " + upperVal.String() + " for " + addrStr.String() + " is not expected val " + expectedUpper.String(), addrStr));
			//}
		}
		var expectedBitCount ipaddr.BitCount
		if addrStr.IsIPv4() {
			expectedBitCount = ipaddr.IPv4BitCount
		} else {
			expectedBitCount = ipaddr.IPv6BitCount
		}
		if totalBits != expectedBitCount {
			//t.addFailure(newFailure("bit count " + totalBits.String() + " for " + addrStr.String() + " is not expected " + expectedBitCount.String(), addrStr));
		}
		//if !s.GetPrefixLen().Equal(prefixLength) {
		//	t.addFailure(newFailure("prefix length " + s.GetPrefixLen().String() + " for " + s.String() + " is not expected " + prefixLength.String(), addrStr));
		//}
	}
	rangeString := t.createAddress(address)
	// go directly to getting the range which should never throw IncompatibleAddressException even for incompatible addresses
	range1 := rangeString.GetSequentialRange()
	low := t.createAddress(lowerAddress).GetAddress().GetLower() // getLower() needed for auto subnets
	up := t.createAddress(upperAddress).GetAddress().GetUpper()  // getUpper() needed for auto subnets
	if !range1.GetLower().Equal(low) {
		t.addFailure(newSeqRangeFailure("range lower "+range1.GetLower().String()+" does not match expected "+low.String(), range1))
	}
	if !range1.GetUpper().Equal(up) {
		t.addFailure(newSeqRangeFailure("range upper "+range1.GetUpper().String()+" does not match expected "+up.String(), range1))
	}
	addrStr = t.createAddress(address)
	// now we should throw IncompatibleAddressException if address is incompatible
	addr, err := addrStr.ToAddress()
	if err != nil {
		if !isIncompatibleAddress {
			t.addFailure(newFailure("address "+addrStr.String()+" identified as an incompatible address", addrStr))
		}
		addrRange, err := addrStr.ToSequentialRange()
		if err != nil {
			t.addFailure(newFailure("unexpected error getting range from "+addrStr.String(), addrStr))
		}
		if !range1.Equal(addrRange) || !addrRange.Equal(range1) {
			t.addFailure(newFailure("address range from "+addrStr.String()+" ("+addrRange.GetLower().String()+","+addrRange.GetUpper().String()+")"+
				" does not match range from address string "+rangeString.String()+" ("+range1.GetLower().String()+","+range1.GetUpper().String()+")", addrStr))
		}
	} else {
		if isIncompatibleAddress {
			t.addFailure(newFailure("address "+addrStr.String()+" not identified as an incompatible address, instead it is "+addr.String(), addrStr))
		}
		if isSequential != nil {
			if *isSequential != addr.IsSequential() {
				t.addFailure(newIPAddrFailure("sequential mismatch, unexpectedly: "+addr.String(), addr))
			}
		}
		addrRange := addr.ToSequentialRange()
		if !range1.Equal(addrRange) || !addrRange.Equal(range1) {
			t.addFailure(newIPAddrFailure("address range from "+addr.String()+" ("+addrRange.GetLower().String()+","+addrRange.GetUpper().String()+")"+
				" does not match range from address string "+rangeString.String()+" ("+range1.GetLower().String()+","+range1.GetUpper().String()+")", addr))
		}
		// now get the range from rangeString after you get the address, which should get it a different way, from the address
		after := rangeString.GetAddress()
		lowerFromSeqRange := after.GetLower()
		upperFromSeqRange := after.GetUpper()
		lowerFromAddr := addr.GetLower()
		upperFromAddr := addr.GetUpper()
		if !lowerFromSeqRange.Equal(lowerFromAddr) || !lowerFromSeqRange.GetNetworkPrefixLen().Equal(lowerFromAddr.GetNetworkPrefixLen()) {
			t.addFailure(newIPAddrFailure("lower from range "+lowerFromSeqRange.String()+" does not match lower from address "+lowerFromAddr.String(), lowerFromSeqRange))
		}
		if !upperFromSeqRange.Equal(upperFromAddr) || !upperFromSeqRange.GetNetworkPrefixLen().Equal(upperFromAddr.GetNetworkPrefixLen()) {
			t.addFailure(newIPAddrFailure("upper from range "+upperFromSeqRange.String()+" does not match upper from address "+upperFromAddr.String(), upperFromSeqRange))
		}
		// now get the range from a string after you get the address first, which should get it a different way, from the address
		oneMore := t.createAddress(address)
		oneMore.GetAddress()
		rangeAfterAddr := oneMore.GetSequentialRange()
		if !range1.Equal(rangeAfterAddr) || !rangeAfterAddr.Equal(range1) {
			t.addFailure(newIPAddrFailure("address range from "+rangeString.String()+" after address ("+rangeAfterAddr.GetLower().String()+","+rangeAfterAddr.GetUpper().String()+")"+
				" does not match range from address string "+rangeString.String()+" before address ("+range1.GetLower().String()+","+range1.GetUpper().String()+")", addr))
		}
		if !addrRange.Equal(rangeAfterAddr) || !rangeAfterAddr.Equal(addrRange) {
			t.addFailure(newIPAddrFailure("address range from "+rangeString.String()+" after address ("+rangeAfterAddr.GetLower().String()+","+rangeAfterAddr.GetUpper().String()+")"+
				" does not match range from address string "+addr.String()+" ("+addrRange.GetLower().String()+","+addrRange.GetUpper().String()+")", addr))
		}

	}

	//seqStr := t.createAddress(address)
	//if isSequential != nil {
	//if *isSequential != seqStr.IsSequential() {
	//	t.addFailure(newFailure("sequential mismatch, unexpectedly: "+seqStr.String(), seqStr))
	//}
	//if !isMaskedIncompatibleAddress && isSequential != seqStr.ToDivisionGrouping().IsSequential() {
	//	t.addFailure(newFailure("sequential grouping mismatch, unexpectedly, " + seqStr.String() + " and " + seqStr.ToDivisionGrouping().String()  , seqStr));
	//}
	//}
	t.incrementTestCount()
}

func (t ipAddressTester) testMaskedIncompatibleAddress(address, lower, upper string) {
	t.testAddressStringRangeP(address, true, true, lower, upper, nil, nil, nil)
}

func (t ipAddressTester) testIncompatibleAddress2(address, lower, upper string, divisions interface{}) {
	t.testIncompatibleAddress(address, lower, upper, divisions, nil)
}

func (t ipAddressTester) testIncompatibleAddress(address, lower, upper string, divisions interface{}, prefixLength ipaddr.PrefixLen) {
	t.testAddressStringRangeP(address, true, false, lower, upper, divisions, prefixLength, nil)
}

func (t ipAddressTester) testIncompatibleAddress1(address, lower, upper string, divisions interface{}, prefixLength ipaddr.PrefixLen, isSequential bool) {
	t.testAddressStringRangeP(address, true, false, lower, upper, divisions, prefixLength, &isSequential)
}

func (t ipAddressTester) testSubnetStringRange2(address, lower, upper string, divisions interface{}) {
	t.testSubnetStringRange(address, lower, upper, divisions, nil)
}

func (t ipAddressTester) testSubnetStringRange(address, lower, upper string, divisions interface{}, prefixLength ipaddr.PrefixLen) {
	t.testAddressStringRangeP(address, false, false, lower, upper, divisions, prefixLength, nil)
}

func (t ipAddressTester) testSubnetStringRange1(address, lower, upper string, divisions interface{}, prefixLength ipaddr.PrefixLen, isSequential bool) {
	t.testAddressStringRangeP(address, false, false, lower, upper, divisions, prefixLength, &isSequential)
}

func (t ipAddressTester) testAddressStringRange1(address string, divisions interface{}) {
	t.testAddressStringRangeP(address, false, false, address, address, divisions, nil, &trueVal)
}

func (t ipAddressTester) testAddressStringRange(address string, divisions interface{}, prefixLength ipaddr.PrefixLen) {
	t.testAddressStringRangeP(address, false, false, address, address, divisions, prefixLength, &trueVal)
}

var trueVal = true

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
				return h1.GetAddress().Equal(conv.ToIPv4(h2.GetAddress()))
			}
		}
	} else if h1.IsIPv6() {
		if !h2.IsIPv6() {
			if h2.GetAddress() != nil && conv.IsIPv6Convertible(h2.GetAddress()) {
				return h1.GetAddress().Equal(conv.ToIPv6(h2.GetAddress()))
			}
		}
	}
	return false
}

func conversionCompare(h1, h2 *ipaddr.IPAddressString) int {
	if h1.IsIPv4() {
		if !h2.IsIPv4() {
			if h2.GetAddress() != nil && conv.IsIPv4Convertible(h2.GetAddress()) {
				return h1.GetAddress().Compare(conv.ToIPv4(h2.GetAddress()))
			}
		}
		return -1
	} else if h1.IsIPv6() {
		if !h2.IsIPv6() {
			if h2.GetAddress() != nil && conv.IsIPv6Convertible(h2.GetAddress()) {
				return h1.GetAddress().Compare(conv.ToIPv6(h2.GetAddress()))
			}
		}
	}
	return 1
}

func makePrefixSubnet(directAddress *ipaddr.IPAddress) *ipaddr.IPAddress {
	segs := directAddress.GetSegments()
	pref := directAddress.GetPrefixLen()
	prefSeg := int(pref.Len() / directAddress.GetBitsPerSegment())
	if prefSeg < len(segs) {
		creator := ipaddr.IPAddressCreator{directAddress.GetIPVersion()}
		if directAddress.GetPrefixCount().Cmp(bigOneConst()) == 0 {
			origSeg := segs[prefSeg]
			mask := origSeg.GetSegmentNetworkMask(pref.Len() % directAddress.GetBitsPerSegment())

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
			//directAddress = creator.NewIPAddressFromPrefixedIP(bytes, pref)
			directAddress = ipaddr.NewIPAddressFromPrefixedNetIP(bytes, pref)
		} else {
			//we could have used SegmentValueProvider in both blocks, but mixing it up to test everything
			origSeg := segs[prefSeg]
			mask := origSeg.GetSegmentNetworkMask(pref.Len() % directAddress.GetBitsPerSegment())
			//maxValue := directAddress.GetMaxSegmentValue()
			directAddress = creator.NewIPAddressFromPrefixedVals(
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
