package test

import (
	"github.com/seancfoley/ipaddress/ipaddress-go/ipaddr"
	"math/big"
)

type ipAddressAllTester struct {
	ipAddressRangeTester
}

func (t ipAddressAllTester) testStrings() {
	t.testMatches(true, "aaaabbbbccccddddeeeeffffaaaabbbb", "aaaa:bbbb:cccc:dddd:eeee:ffff:aaaa:bbbb")
	t.testMatches(true, "aaaabbbbcccccdddffffffffffffffff-aaaabbbbccccdddd0000000000000000", "aaaa:bbbb:cccc:cddd-dddd:*:*:*:*")
	t.testMatches(true, "aaaabbbbccccdddd0000000000000000-aaaabbbbcccccdddffffffffffffffff", "aaaa:bbbb:cccc:cddd-dddd:*:*:*:*")

	p0 := cacheTestBits(0)
	p1 := cacheTestBits(1)
	p15 := cacheTestBits(15)
	p16 := cacheTestBits(16)
	p32 := cacheTestBits(32)
	p64 := cacheTestBits(64)
	p89 := cacheTestBits(89)
	p126 := cacheTestBits(126)
	p128 := cacheTestBits(128)

	t.testSubnetStringRange2("*.0-65535", "0.0.0.0", "255.0.255.255", []interface{}{[]uint{0, 255}, []uint{0, 65535}}) // only valid with inet_aton allowed, and inet_aton takes precedence over wildcard
	t.testSubnetStringRange2("00000000000000000000000000000000-00000000000000000000007fffffffff", "::", "::7f:ffff:ffff",
		[]interface{}{[]*big.Int{bigZeroConst(), setBigString("00000000000000000000007fffffffff", 16)}})
	t.testSubnetStringRange2("00000000000000000000000000000000-00000000007fffffffffffffffffffff", "::", "::7f:ffff:ffff:ffff:ffff:ffff",
		[]interface{}{[]*big.Int{bigZeroConst(), setBigString("00000000007fffffffffffffffffffff", 16)}})
	t.testSubnetStringRange2("00000000000000000000000000000000-7fffffffffffffffffffffffffffffff", "::", "7fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
		[]interface{}{[]*big.Int{bigZeroConst(), setBigString("7fffffffffffffffffffffffffffffff", 16)}})
	t.testSubnetStringRange2("00000000000000000000000000000000-ffffffffffffffffffffffffffffffff", "::", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
		[]interface{}{[]*big.Int{bigZeroConst(), setBigString("ffffffffffffffffffffffffffffffff", 16)}})
	t.testSubnetStringRange2("0000000000000000000000000000abcd-0000000000000000000000000000bbcd", "::abcd", "::bbcd",
		[]interface{}{[]uint{0xabcd, 0xbbcd}})

	t.testMaskedIncompatibleAddress("*/f0ff::", "::", "f0ff::")
	t.testMaskedIncompatibleAddress("*/129.0.0.0", "0.0.0.0", "129.0.0.0")

	t.testMaskedIncompatibleAddress("*:*/f0ff::", "::", "f0ff::")
	t.testMaskedIncompatibleAddress("*.*/129.0.0.0", "0.0.0.0", "129.0.0.0")

	t.testIncompatibleAddress2("*.257-65535", "0.0.1.1", "255.0.255.255", []interface{}{[]uint{0, 255}, []uint{257, 65535}})                                                                                                                                                                                      //[0-255, 257-65535]
	t.testIncompatibleAddress2("1-1000", "1", "1000", []interface{}{[]uint{1, 1000}})                                                                                                                                                                                                                             //[1-1000]
	t.testIncompatibleAddress2("50000-60000", "50000", "60000", []interface{}{[]uint{50000, 60000}})                                                                                                                                                                                                              //[50000-60000]
	t.testIncompatibleAddress2("*.11-16000111", "0.11", "255.16000111", []interface{}{[]uint{0, 255}, []uint{11, 16000111}})                                                                                                                                                                                      //[0-255, 11-16000111]
	t.testIncompatibleAddress2("0-255.11-16000111", "0.11", "255.16000111", []interface{}{[]uint{0, 255}, []uint{11, 16000111}})                                                                                                                                                                                  //[0-255, 11-16000111] // inet_aton
	t.testIncompatibleAddress2("0-254.10101-16000111", "0.10101", "254.16000111", []interface{}{[]uint{0, 254}, []uint{10101, 16000111}})                                                                                                                                                                         // [0-254, 10101-16000111] // inet_aton
	t.testIncompatibleAddress2("1.10101-16000111", "1.10101", "1.16000111", []interface{}{1, []uint{10101, 16000111}})                                                                                                                                                                                            //[1, 10101-16000111] // inet_aton
	t.testIncompatibleAddress2("3-1.10101-16000111", "1.10101", "3.16000111", []interface{}{[]uint{1, 3}, []uint{10101, 16000111}})                                                                                                                                                                               //[1-3, 10101-16000111] // inet_aton
	t.testIncompatibleAddress2("00000000000000000000000000000000-abcdefabcdefabcdefabcdefabcdefab", "::", "abcd:efab:cdef:abcd:efab:cdef:abcd:efab", []*big.Int{bigZeroConst(), setBigString("abcdefabcdefabcdefabcdefabcdefab", 16)})                                                                            //[0-abcdefabcdefabcdefabcdefabcdefab]
	t.testIncompatibleAddress2("abcdefabcdefabcdefabcdefabcdefab-ffffffffffffffffffffffffffffffff", "abcd:efab:cdef:abcd:efab:cdef:abcd:efab", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", []*big.Int{setBigString("abcdefabcdefabcdefabcdefabcdefab", 16), setBigString("ffffffffffffffffffffffffffffffff", 16)}) //[abcdefabcdefabcdefabcdefabcdefab-ffffffffffffffffffffffffffffffff]
	t.testIncompatibleAddress2("abcdefabcdefabcdefabcdefabcdefab-bbcdefabcdefabcdefabcdefabcdefab", "abcd:efab:cdef:abcd:efab:cdef:abcd:efab", "bbcd:efab:cdef:abcd:efab:cdef:abcd:efab", []*big.Int{setBigString("abcdefabcdefabcdefabcdefabcdefab", 16), setBigString("bbcdefabcdefabcdefabcdefabcdefab", 16)}) //[abcdefabcdefabcdefabcdefabcdefab-bbcdefabcdefabcdefabcdefabcdefab]
	t.testIncompatibleAddress2("-abcdefabcdefabcdefabcdefabcdefab", "::", "abcd:efab:cdef:abcd:efab:cdef:abcd:efab", []*big.Int{bigZeroConst(), setBigString("abcdefabcdefabcdefabcdefabcdefab", 16)})                                                                                                            //[0-abcdefabcdefabcdefabcdefabcdefab]
	t.testIncompatibleAddress2("abcdefabcdefabcdefabcdefabcdefab-", "abcd:efab:cdef:abcd:efab:cdef:abcd:efab", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", []*big.Int{setBigString("abcdefabcdefabcdefabcdefabcdefab", 16), setBigString("ffffffffffffffffffffffffffffffff", 16)})                                 //[abcdefabcdefabcdefabcdefabcdefab-ffffffffffffffffffffffffffffffff]

	t.testIncompatibleAddress2("a:bb:c:dd:e:f:1.1-65535", "a:bb:c:dd:e:f:1.1", "a:bb:c:dd:e:f:1.65535", []interface{}{0xa, 0xbb, 0xc, 0xdd, 0xe, 0xf, 1, []uint{1, 0xffff}}) // mixed with inet_aton, mixed is incompatible address //[a, bb, c, dd, e, f, 1, 1-ffff]

	// with prefix lengths

	// inet_aton *.0.*.*/15
	t.testSubnetStringRange("*.0-65535/15", "0.0.0.0", "255.1.255.255", []interface{}{[]uint{0, 255}, []uint{0, 131071}}, p15) // only valid with inet_aton allowed, and inet_aton takes precedence over wildcard

	t.testSubnetStringRange("00000000000000000000000000000000-00000000000000000000007fffffffff/89", "::", "::7f:ffff:ffff",
		[]interface{}{[]*big.Int{bigZeroConst(), setBigString("00000000000000000000007fffffffff", 16)}}, p89)
	t.testSubnetStringRange("00000000000000000000000000000000-00000000007fffffffffffffffffffff/89", "::", "::7f:ffff:ffff:ffff:ffff:ffff",
		[]interface{}{[]*big.Int{bigZeroConst(), setBigString("00000000007fffffffffffffffffffff", 16)}}, p89)

	t.testSubnetStringRange("00000000000000000000000000000000-7fffffffffffffffffffffffffffffff/0", "::", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
		[]interface{}{[]*big.Int{bigZeroConst(), setBigString("ffffffffffffffffffffffffffffffff", 16)}}, p0)

	t.testSubnetStringRange("00000000000000000000000000000000-7fffffffffffffffffffffffffffffff/1", "::", "7fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
		[]interface{}{[]*big.Int{bigZeroConst(), setBigString("7fffffffffffffffffffffffffffffff", 16)}}, p1)

	t.testSubnetStringRange("0000000000000000000000000000abcd-0000000000000000000000000000bbcd/126", "::abcd", "::bbcd",
		[]interface{}{[]uint{0xabcd, 0xbbcd}}, p126)

	t.testSubnetStringRange("00000000000000000000000000000000/89", "::", "::7f:ffff:ffff",
		[]interface{}{[]*big.Int{bigZeroConst(), setBigString("00000000000000000000007fffffffff", 16)}}, p89)

	t.testIncompatibleAddress("*.11-16000111/32", "0.11", "255.16000111", []interface{}{[]uint{0, 255}, []uint{11, 16000111}}, p32) //[0-255, 11-16000111]

	t.testIncompatibleAddress("*.257-65535/16", "0.0.1.1", "255.0.255.255", []interface{}{[]uint{0, 255}, []uint{257, 65535}}, p16)                                                                                                                                                                                      //[0-255, 257-65535]
	t.testIncompatibleAddress("1-1000/16", "1", "1000", []interface{}{[]uint{1, 1000}}, p16)                                                                                                                                                                                                                             //[1-1000]
	t.testIncompatibleAddress("50000-60000/16", "50000", "60000", []interface{}{[]uint{50000, 60000}}, p16)                                                                                                                                                                                                              //[50000-60000]
	t.testIncompatibleAddress("3-1.10101-16000111/16", "1.10101", "3.16000111", []interface{}{[]uint{1, 3}, []uint{10101, 16000111}}, p16)                                                                                                                                                                               //[1-3, 10101-16000111] // inet_aton
	t.testIncompatibleAddress("00000000000000000000000000000000-abcdefabcdefabcdefabcdefabcdefab/64", "::", "abcd:efab:cdef:abcd:efab:cdef:abcd:efab", []*big.Int{bigZeroConst(), setBigString("abcdefabcdefabcdefabcdefabcdefab", 16)}, p64)                                                                            //[0-abcdefabcdefabcdefabcdefabcdefab]
	t.testIncompatibleAddress("abcdefabcdefabcdefabcdefabcdefab-ffffffffffffffffffffffffffffffff/64", "abcd:efab:cdef:abcd:efab:cdef:abcd:efab", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", []*big.Int{setBigString("abcdefabcdefabcdefabcdefabcdefab", 16), setBigString("ffffffffffffffffffffffffffffffff", 16)}, p64) //[abcdefabcdefabcdefabcdefabcdefab-ffffffffffffffffffffffffffffffff]
	t.testIncompatibleAddress("abcdefabcdefabcdefabcdefabcdefab-bbcdefabcdefabcdefabcdefabcdefab/64", "abcd:efab:cdef:abcd:efab:cdef:abcd:efab", "bbcd:efab:cdef:abcd:efab:cdef:abcd:efab", []*big.Int{setBigString("abcdefabcdefabcdefabcdefabcdefab", 16), setBigString("bbcdefabcdefabcdefabcdefabcdefab", 16)}, p64) //[abcdefabcdefabcdefabcdefabcdefab-bbcdefabcdefabcdefabcdefabcdefab]
	t.testIncompatibleAddress("-abcdefabcdefabcdefabcdefabcdefab/64", "::", "abcd:efab:cdef:abcd:efab:cdef:abcd:efab", []*big.Int{bigZeroConst(), setBigString("abcdefabcdefabcdefabcdefabcdefab", 16)}, p64)                                                                                                            //[0-abcdefabcdefabcdefabcdefabcdefab]
	t.testIncompatibleAddress("abcdefabcdefabcdefabcdefabcdefab-/64", "abcd:efab:cdef:abcd:efab:cdef:abcd:efab", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", []*big.Int{setBigString("abcdefabcdefabcdefabcdefabcdefab", 16), setBigString("ffffffffffffffffffffffffffffffff", 16)}, p64)                                 //[abcdefabcdefabcdefabcdefabcdefab-ffffffffffffffffffffffffffffffff]

	t.testIncompatibleAddress2("a:bb:c:dd:e:f:1.1-65535", "a:bb:c:dd:e:f:1.1", "a:bb:c:dd:e:f:1.65535", []interface{}{0xa, 0xbb, 0xc, 0xdd, 0xe, 0xf, 1, []uint{1, 0xffff}}) // mixed with inet_aton, mixed is incompatible address //[a, bb, c, dd, e, f, 1, 1-ffff]

	t.testMaskedIncompatibleAddress("1234567890abcdef1234567890abcdef-2234567890abcdef1234567890abcdef/ffff:0:ffff:0:ffff:0:ffff:0",
		"1234::", "2234:0:ffff:0:ffff:0:ffff:0")

	t.testSubnetStringRange1("1234567890abcdef1234567890abcdef-2234567890abcdef1234567890abcdef/::ffff:ffff:FFFF:ffff:FFFF",
		"00000000000000000000000000000000", "000000000000ffffffffffffffffffff",
		[]interface{}{[]*big.Int{bigZeroConst(), setBigString("000000000000ffffffffffffffffffff", 16)}},
		nil, true,
	)
	t.testIncompatibleAddress1("1234567890abcdef1234567890abcdef-2234567890abcdef1234567890abcdef/ffff:ffff:ffff:ffff:ffff:FFFF:ffff:FFFF",
		"1234567890abcdef1234567890abcdef", "2234567890abcdef1234567890abcdef",
		[]interface{}{[]*big.Int{setBigString("1234567890abcdef1234567890abcdef", 16), setBigString("2234567890abcdef1234567890abcdef", 16)}},
		p128, true,
	)
	t.testSubnetStringRange1("1234567890abcdef1234567890abcdef-2234567890abcdef1234567890abcdef/fff:ffff:ffff:ffff:ffff:FFFF:ffff:FFFF",
		"00000000000000000000000000000000", "0fffffffffffffffffffffffffffffff",
		[]interface{}{[]*big.Int{bigZeroConst(), setBigString("0fffffffffffffffffffffffffffffff", 16)}},
		nil, true,
	)
	t.testMaskedIncompatibleAddress("1234567890abcdef1234567890abcdef-2234567890abcdef1234567890abcded/fff:ffff:ffff:ffff:ffff:FFFF:ffff:FFFF",
		"00000000000000000000000000000000", "0fffffffffffffffffffffffffffffff",
	)
	t.testSubnetStringRange1("1234567890abcdef1234567890abcdef-2234567890abcdef2234567890abcdef/::ffff:ffff:FFFF:ffff:FFFF",
		"00000000000000000000000000000000", "000000000000ffffffffffffffffffff",
		[]interface{}{[]*big.Int{bigZeroConst(), setBigString("000000000000ffffffffffffffffffff", 16)}},
		nil, true)
	t.testSubnetStringRange1("1234567890abcdef1234567890abcdef-2234567890abcdef2234567890abcdef/::FFFF:ffff:FFFF",
		"00000000000000000000000000000000", "00000000000000000000ffffffffffff",
		[]interface{}{[]*big.Int{bigZeroConst(), setBigString("00000000000000000000ffffffffffff", 16)}},
		nil, true)
	t.testMaskedIncompatibleAddress("1234567890abcdef1234567890abcdef-2234567890abcdef2234567890abcdef/::FFFF:ffff:0000",
		"00000000000000000000000000000000", "00000000000000000000ffffffff0000")

	t.testIncompatibleAddress1("1234567890abcdef1234567890abcdef-2234567890abcdef1234567890abcdef/ffff:FFFF:ffff:FFFF::",
		"1234567890abcdef1234567890abcdef", "2234567890abcdef1234567890abcdef",
		[]interface{}{[]*big.Int{setBigString("1234567890abcdef1234567890abcdef", 16), setBigString("2234567890abcdef1234567890abcdef", 16)}},
		p64, true)

	// TODO LATER base85
	//t.testMatches(true, "4)+k&C#VzJ4br>0wv%Yp", "1080::8:800:200c:417a")
	//t.testMatches(true, "=r54lj&NUUO~Hi%c2ym0", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")
	//t.testMatches(true, "=r54lj&NUUO~Hi%c2yl0"+ipaddr.AlternativeRangeSeparatorStr+"=r54lj&NUUO~Hi%c2ym0", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffaa-ffff")

	t.ipAddressRangeTester.testStrings()
}

func (t ipAddressAllTester) run() {
	t.testStrings()

	// TODO LATER base85
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
	// TODO LATER base85
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

	//TODO LATER base 85
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
