package test

import "github.com/seancfoley/ipaddress/ipaddress-go/ipaddr"

type ipAddressAllTester struct {
	ipAddressRangeTester
}

func (t ipAddressAllTester) testStrings() {
	t.testMatches(true, "aaaabbbbccccddddeeeeffffaaaabbbb", "aaaa:bbbb:cccc:dddd:eeee:ffff:aaaa:bbbb")
	t.testMatches(true, "aaaabbbbcccccdddffffffffffffffff-aaaabbbbccccdddd0000000000000000", "aaaa:bbbb:cccc:cddd-dddd:*:*:*:*")
	// failed: matching aaaabbbbccccdddd0000000000000000-aaaabbbbcccccdddffffffffffffffff with aaaa:bbbb:cc
	t.testMatches(true, "aaaabbbbccccdddd0000000000000000-aaaabbbbcccccdddffffffffffffffff", "aaaa:bbbb:cccc:cddd-dddd:*:*:*:*")

	// TODO base85
	//t.testMatches(true, "4)+k&C#VzJ4br>0wv%Yp", "1080::8:800:200c:417a")
	//t.testMatches(true, "=r54lj&NUUO~Hi%c2ym0", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")
	//t.testMatches(true, "=r54lj&NUUO~Hi%c2yl0"+ipaddr.AlternativeRangeSeparatorStr+"=r54lj&NUUO~Hi%c2ym0", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffaa-ffff")

	t.ipAddressRangeTester.testStrings()
}

func (t ipAddressAllTester) run() {
	t.testStrings()

	// TODO base85
	//testMatches(true, "ef86:1dc3:deba:d48:612d:f19c:de7d:e89c", "********************") // base 85
	//testMatches(true, "--------------------", "f677:73f6:11b4:5073:4a06:76c2:ceae:1474")

	t.testMatches(true, "-", "*.*")
	t.testMatches(true, "-", "*.*.*.*")

	t.testMatches(true, "-0000000000000000efabffffffffffff", "00000000000000000000000000000000-0000000000000000efabffffffffffff")
	t.testMatches(true, "00000000000000000000000000000000-", "00000000000000000000000000000000-ffffffffffffffffffffffffffffffff")
	t.testMatches(true, "abfe0000000000000000000000000000-", "abfe0000000000000000000000000000-ffffffffffffffffffffffffffffffff")

	t.testMatches(true, "-0x0000000000000000efabffffffffffff", "00000000000000000000000000000000-0000000000000000efabffffffffffff")
	t.testMatches(true, "-0X0000000000000000efabffffffffffff", "00000000000000000000000000000000-0000000000000000efabffffffffffff")
	t.testMatches(true, "0x00000000000000000000000000000000-", "00000000000000000000000000000000-ffffffffffffffffffffffffffffffff")
	t.testMatches(true, "0xabcd0000000000000000000000000000-", "abcd0000000000000000000000000000-ffffffffffffffffffffffffffffffff")

	// these are the same addresses as the above tests in hex, but here in base 85
	// TODO base85
	//testMatches(true, ipaddr.AlternativeRangeSeparatorStr+"0000000000=l?k|EPzi+", "00000000000000000000"+ipaddr.AlternativeRangeSeparatorStr+"0000000000=l?k|EPzi+")
	//testMatches(true, "00000000000000000000"+ipaddr.AlternativeRangeSeparatorStr, "00000000000000000000"+ipaddr.AlternativeRangeSeparatorStr+"=r54lj&NUUO~Hi%c2ym0")
	//testMatches(true, "oBky9Vh_d)e!eUd#8280"+ipaddr.AlternativeRangeSeparatorStr, "oBky9Vh_d)e!eUd#8280"+ipaddr.AlternativeRangeSeparatorStr+"=r54lj&NUUO~Hi%c2ym0")

	t.testMatches(true, "*.*.*.*", "-4294967295")   // ok on all tests
	t.testMatches(true, "*.*.*.*", "-0xffffffff")   // ok on all tests
	t.testMatches(true, "*.*.*.*", "-037777777777") // ok on all tests

	t.testMatches(true, "*.*.*.*", "0-")
	t.testMatches(true, "*.*.*.*", "-")

	t.testMatches(true, "0.-", "0.*.*.*")
	t.testMatches(true, "0.-", "0.*")
	t.testMatches(true, "0.0.-", "0.0.*.*")
	t.testMatches(true, "0.0.-", "0.0.*")
	t.testMatches(true, "0.-.0", "0.*.0.0") //ok
	t.testMatches(true, "-.0.-", "*.0.*.*") // more than one inferred range
	t.testMatches(true, "-.0.-", "*.0.*")
	t.testMatches(true, "1-.0.256-", "1-255.0.256-65535")    // 1-.0.256- becomes 1-255.0.*.255 // more than one inferred range
	t.testMatches(true, "0.1-.256-", "0.1-255.256-65535")    // more than one inferred range
	t.testMatches(true, "1-.65536-", "1-255.65536-16777215") // test more than one inferred range

	t.testMatches(true, "0b1.0b01.0b101.0b11111111", "1.1.5.255")
	t.testMatches(true, "0b1.0b01.0b101.0b11111111/16", "1.1.5.255/16")
	t.testMatches(true, "0b1.1.0b101.0b11111111/16", "1.1.5.255/16")

	t.ipv6test(true, "0x00010002000300040000000000000000-0x0001000200030004ffffffffffffffff")
	t.ipv6test(true, "0x0001000200030004ffffffffffffffff-0x00010002000300040000000000000000")
	t.ipv6test(true, "0x00010002000300040000000000000000")

	t.ipv6test(true, "00010002000300040000000000000000-0001000200030004ffffffffffffffff")
	t.ipv6test(true, "0001000200030004ffffffffffffffff-00010002000300040000000000000000")
	t.ipv6test(true, "00010002000300040000000000000000")

	//TODO base 85
	//t.ipv6test(true, "00|M>t|ttwH6V6EEzblZ"+ipaddr.AlternativeRangeSeparatorStr+"00|M>t|ttwH6V6EEzkrZ")
	//t.ipv6test(true, "00|M>t|ttwH6V6EEzkrZ"+ipaddr.AlternativeRangeSeparatorStr+"00|M>t|ttwH6V6EEzblZ")
	t.ipv6test(false, "00|M>t|ttwH6V6EEzkr"+ipaddr.AlternativeRangeSeparatorStr+"00|M>t|ttwH6V6EEzblZ")
	t.ipv6test(false, "00|M>t|ttwH6V6EEzkrZ"+ipaddr.AlternativeRangeSeparatorStr+"0|M>t|ttwH6V6EEzblZ")
	t.ipv6test(false, "00|M>t|ttwH6V6EEzkrZx"+ipaddr.AlternativeRangeSeparatorStr+"00|M>t|ttwH6V6EEzblZ")
	t.ipv6test(false, "00|M>t|ttwH6V6EEzkrZ"+ipaddr.AlternativeRangeSeparatorStr+"x00|M>t|ttwH6V6EEzblZ")

	t.ipv6test(true, "00000000000000000000000000000000-0001ffffffffffffffffffffffffffff")

	//t.ipv6test(true, "=q{+M|w0(OeO5^F85=Cb")
	t.ipv6test(false, "=q{+M|w0.OeO5^F85=Cb") // .
	t.ipv6test(false, "=q{+:|w0(OeO5^F85=Cb") // :
	t.ipv6test(false, "=q{+M|w0(OeO5^F85=C/") // / in middle
	t.ipv6test(false, "=q{+M|w0(OeO5^F85=/b") // / in middle
	//t.ipv6test(true, "=q{+M|w0(OeO5^F85=Cb/127")                                           // ok
	//t.ipv6test(true, "=q{+-|w0(OeO5^-85=Cb")                                               // two '-'
	//t.ipv6test(true, "=q{+M|w0(OeO5^F85=Cb"+ipaddr.AlternativeRangeSeparatorStr+"eth0") // ok
	t.ipv6test(false, "=q{+M|w0(OeO5^F85=C"+ipaddr.AlternativeRangeSeparatorStr+"eth0") // too soon

	t.testAllContains("*", "1:2:3:4:1:2:3:4", true)
	t.testAllContains("*", "1.2.3.4.5", false)
	t.testAllContains("*", "1.2.3.4", true)
	t.testAllContains("*/64", "1.2.3.4", false)
	t.testAllContains("*.*", "1::", false)
	t.testAllContains("*:*", "1::", true)
	t.testAllContains("*:*", "1.2.3.4", false)
	t.testAllContains("*.*", "1.2.3.4", true)
	t.testAllContains("*/64", "::", true)

	t.testNormalized("aaaabbbbcccccddd0000000000000000-aaaabbbbccccddddffffffffffffffff", "aaaa:bbbb:cccc:cddd-dddd:*:*:*:*")
	t.testCanonical("aaaabbbbcccccddd0000000000000000-aaaabbbbccccddddffffffffffffffff", "aaaa:bbbb:cccc:cddd-dddd:*:*:*:*")

	t.ipAddressRangeTester.run()
}

func (t ipAddressAllTester) testAllContains(cidr1, cidr2 string, result bool) {
	wstr := t.createAddress(cidr1)
	w2str := t.createAddress(cidr2)

	t.testStringContains(result, false, wstr, w2str)

	t.incrementTestCount()
}
