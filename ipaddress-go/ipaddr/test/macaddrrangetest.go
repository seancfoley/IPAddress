package test

import (
	"github.com/seancfoley/ipaddress/ipaddress-go/ipaddr"
	"math"
	"strconv"
)

type macAddressRangeTester struct {
	macAddressTester
}

func (t macAddressRangeTester) run() {

	t.mactest(true, "*-abcdef|fffffe")        // throws IncompatibleAddressException
	t.mactest(true, "0|ffffff-abcdef|fffffe") // throws IncompatibleAddressException
	t.mactest(true, "*-ab0000|ffffff")
	t.mactest(true, "0|ffffff-ab0000|ffffff")

	t.mactest(false, "*|1")
	t.mactest(false, "1|*")
	t.mactest(true, "*-1")
	t.mactest(true, "1-*")
	t.mactest(true, "*-*")
	t.mactest(true, "*:1")
	t.mactest(true, "1:*")
	t.mactest(true, "*:*")
	t.mactest(false, "1:1")
	t.mactest(false, "1-1")
	t.mactest(true, "0xaabbccddeeee-0xaabbccddeeff")
	t.mactest(true, "0xaabbccddeeee-aabbccddeeff")
	t.mactest(true, "aabbccddeeee-0xaabbccddeeff")
	t.mactest(true, "aabbccddeeee-aabbccddeeff")

	t.mactest(t.allowsRange(), "aa-|1-*-d-ee-f")
	t.mactest(t.allowsRange(), "|1-aa-cc-*-ee-f")
	t.mactest(t.allowsRange(), "aa-1|-cc-d-*-f")
	t.mactest(t.allowsRange(), "1|-aa-cc-d-*")
	t.mactest(t.allowsRange(), "aa-0|1-cc-*")
	t.mactest(t.allowsRange(), "aa-1|ff-*")
	t.mactest(t.allowsRange(), "*-1|ff-*")

	t.mactest(true, "aa0000|abffff-ddeeff")
	t.mactest(true, "aa0000|abffff-*")
	t.mactest(false, "aabbcc|ddeeff-ddeefff")
	t.mactest(false, "aabbcc|aabbcd-ddeefffff")
	t.mactest(true, "aabbcc|aabbcd-ddeeffffff")
	t.mactest(false, "aabbcc|aabbcd-ddeefffffff")
	t.mactest(true, "aabbcc|aabbcd-*")
	t.mactest(false, "aabbcc|aabbcd-ddeefffffff")

	t.mactest(true, "ddeeff-aa0000|afffff")
	t.mactest(true, "*-aa0000|afffff")
	t.mactest(false, "ddeefff-aabbcc|ddeeff")
	t.mactest(true, "ddeeff-aabbffffcc|aabbffffdd")
	t.mactest(false, "ddeeff-aabbffffccc|aabbffffddd")
	t.mactest(false, "ddeeff-aabbffffc|aabbffffd")
	t.mactest(false, "ddeefffffff-aabbcc|aabbcd")

	t.mactest(true, "000000000000-abcdefabcdef")
	t.mactest(true, "000000000000-ffffffffffff")
	t.mactest(true, "abcdefabcdef-ffffffffffff")
	t.mactest(true, "000000000000-abcdefabcdef")
	t.mactest(true, "000000000000-ffffffffffff")
	t.mactest(true, "abcdefabcdefabcd-ffffffffffffffff")

	t.mactest(true, "000000000000-")
	t.mactest(true, "-000000000010")
	t.mactest(true, "-abcdefabcdefabcd")
	t.mactest(true, "abcdefabcdefabcd-")

	// length mismatch
	t.mactest(false, "0000000000001-abcdefabcdef")
	t.mactest(false, "000000000000-fffffffffffff")
	t.mactest(false, "abcdefabcdeff-ffffffffffff")
	t.mactest(false, "000000000000-abcdefabcdeff")
	t.mactest(false, "0000000000-ffffffffffff")
	t.mactest(false, "abcdefabcdef-ffffffff")

	t.mactest(false, "00000000000-")
	t.mactest(false, "-00000000001")
	t.mactest(false, "-abcdefabcdefabcde")
	t.mactest(false, "abcdefabcdefabcde-")
	t.mactest(false, "000000000000-abcdefabcdefabcd")
	t.mactest(false, "0000000000000000-ffffffffffff")
	t.mactest(false, "efabcdefabcd-ffffffffffffffff")
	t.mactest(false, "0000000000000000-abcdefabcdef")
	t.mactest(false, "0000000000000000-ffffffffffff")
	t.mactest(false, "abcdefabcdefabc-fffffffffffffff")

	t.mactest(true, "11:11:11:ff:_:0")
	t.mactest(true, "_:11:11:11:1:1")
	t.mactest(true, "1:2:3:4:_:6:7:8")
	t.mactest(true, "1:2:_:4:5:6:8:7")
	t.mactest(true, "1:3:4:5:6:_")
	t.mactest(true, "1:2:3:_:5:6:8:7")
	t.mactest(true, "_:2:3:5:ff:8")
	t.mactest(true, "1:11:11:11:1:_")
	t.mactest(true, "_:2:3:4:5:6:7:7")
	t.mactest(true, "_:2:3:4:5:6")
	t.mactest(true, "1:5:2:3:4:_")

	t.mactest(true, "11:11:11:ff:__:0")
	t.mactest(true, "__:11:11:11:1:1")
	t.mactest(true, "1:2:3:4:__:6:7:8")
	t.mactest(true, "1:2:__:4:5:6:7:8")
	t.mactest(true, "1:2:3:4:5:__")
	t.mactest(true, "1:2:3:__:5:8")
	t.mactest(true, "__:2:3:4:5:8")
	t.mactest(true, "1:2:3:4:5:__")
	t.mactest(true, "__:2:3:4:5:6:7:8")
	t.mactest(true, "__:2:3:4:5:6")
	t.mactest(true, "1:2:3:3:4:__")

	t.mactest(false, "11:11:11:ff:___:0")
	t.mactest(false, "___:11:11:11:1:1")
	t.mactest(false, "1:2:3:4:___:6:7:8")
	t.mactest(false, "1:2:___:4:5:6:7:8")
	t.mactest(false, "1:2:3:4:5:___")
	t.mactest(false, "1:2:3:___:5:8")
	t.mactest(false, "___:2:3:4:5:8")
	t.mactest(false, "1:2:3:4:5:___")
	t.mactest(false, "___:2:3:4:5:6:7:8")
	t.mactest(false, "___:2:3:4:5:6")
	t.mactest(false, "1:2:3:4:5:___")

	t.mactest(false, "11:11:11:ff:_2_:0")
	t.mactest(false, "_2_:11:11:11:1:1")
	t.mactest(false, "1:2:3:4:_2_:6:7:8")
	t.mactest(false, "1:2:_2_:4:5:6:7:8")
	t.mactest(false, "1:2:3:4:5:_2_")
	t.mactest(false, "1:2:3:_2_:5:8")
	t.mactest(false, "_2_:2:3:4:5:8")
	t.mactest(false, "1:2:3:4:5:_2_")
	t.mactest(false, "_2_:2:3:4:5:6:7")
	t.mactest(false, "_2_:2:3:4:5:6")

	t.mactest(false, "11:11:11:ff:_2:0")
	t.mactest(false, "_2:11:11:11:1:1")
	t.mactest(false, "1:2:3:4:_2:6:7:8")
	t.mactest(false, "1:2:_2:4:5:6:7:8")
	t.mactest(false, "1:2:3:4:5:_2")
	t.mactest(false, "1:2:3:_2:5:8")
	t.mactest(false, "_2:2:3:4:5:8")
	t.mactest(false, "1:2:3:4:5:_2")
	t.mactest(false, "_2:2:3:4:5:6:7:8")
	t.mactest(false, "_2:2:3:4:5:6")

	t.mactest(true, "11:11:11:ff:2_:0")
	t.mactest(true, "2_:11:11:11:1:1")
	t.mactest(true, "1:2:3:4:2_:6:7:8")
	t.mactest(true, "1:2:2_:4:5:6:7:8")
	t.mactest(true, "1:2:3:4:5:2_")
	t.mactest(true, "1:2:3:2_:5:8")
	t.mactest(true, "2_:2:3:4:5:8")
	t.mactest(true, "1:2:3:4:5:2_")
	t.mactest(true, "2_:2:3:4:5:6:7:8")
	t.mactest(true, "2_:2:3:4:5:6")

	t.testEquivalentPrefix("*:*", 0)
	t.testEquivalentPrefix("*:*:*:*:*:*", 0)
	t.testEquivalentPrefix("*:*:*:*:*:*:*:*", 0)
	t.testEquivalentPrefix("80-ff:*", 1)
	t.testEquivalentPrefix("0-7f:*", 1)
	t.testEquivalentPrefix("1:2:*", 16)
	t.testEquivalentPrefix("1:2:*:*:*:*", 16)
	t.testEquivalentMinPrefix("1:2:*:0:*:*", nil, 32)
	t.testEquivalentMinPrefix("1:2:*:0:0:0", nil, 48)

	t.testEquivalentPrefix("1:2:80-ff:*", 17)
	t.testEquivalentPrefix("1:2:00-7f:*", 17)
	t.testEquivalentPrefix("1:2:c0-ff:*", 18)
	t.testEquivalentPrefix("1:2:00-3f:*", 18)
	t.testEquivalentPrefix("1:2:80-bf:*", 18)
	t.testEquivalentPrefix("1:2:40-7f:*", 18)
	t.testEquivalentPrefix("1:2:fc-ff:*", 22)
	t.testEquivalentPrefix("1:2:fc-ff:0-ff:*", 22)
	t.testEquivalentMinPrefix("1:2:fd-ff:0-ff:*", nil, 24)
	t.testEquivalentMinPrefix("1:2:fc-ff:0-fe:*", nil, 32)
	t.testEquivalentMinPrefix("1:2:fb-ff:0-fe:*", nil, 32)
	t.testEquivalentMinPrefix("1:2:fb-ff:0-ff:*", nil, 24)

	t.testReverse("1:2:*:4:5:6", false, false)
	t.testReverse("1:1:1-ff:2:3:3", false, false)
	t.testReverse("1:1:0-fe:1-fe:*:1", false, false)
	t.testReverse("ff:80:*:ff:01:ff", false, false)
	t.testReverse("ff:80:fe:7f:01:ff", true, false)
	t.testReverse("ff:80:*:*:01:ff", true, false)
	t.testReverse("ff:81:ff:*:1-fe:ff", false, true)
	t.testReverse("ff:81:c3:42:24:0-fe", false, true)
	t.testReverse("ff:1:ff:ff:*:*", false, false)

	t.testIncrement("ff:ff:ff:ff:ff:1-2:2-3:ff", 0, "ff:ff:ff:ff:ff:1:2:ff")
	t.testIncrement("ff:ff:ff:ff:ff:1-2:2-3:ff", 2, "ff:ff:ff:ff:ff:2:2:ff")
	t.testIncrement("ff:ff:ff:ff:ff:1-2:2-3:ff", 3, "ff:ff:ff:ff:ff:2:3:ff")
	t.testIncrement("ff:ff:ff:ff:ff:1-2:2-3:ff", 4, "ff:ff:ff:ff:ff:2:4:0")
	t.testIncrement("ff:ff:ff:ff:ff:fe-ff:fe-ff:ff", 4, "")

	t.testIncrement("ff:ff:ff:1-2:2-3:ff", 0, "ff:ff:ff:1:2:ff")
	t.testIncrement("ff:ff:ff:1-2:2-3:ff", 2, "ff:ff:ff:2:2:ff")
	t.testIncrement("ff:ff:ff:1-2:2-3:ff", 3, "ff:ff:ff:2:3:ff")
	t.testIncrement("ff:ff:ff:1-2:2-3:ff", 4, "ff:ff:ff:2:4:0")
	t.testIncrement("ff:ff:ff:fe-ff:fe-ff:ff", 4, "")

	t.testIncrement("ff:ff:ff:ff:ff:1-2:2-3:ff", -0x102fb, "ff:ff:ff:ff:ff:0:0:4")
	t.testIncrement("ff:ff:ff:ff:ff:1-2:2-3:ff", -0x102fc, "ff:ff:ff:ff:ff:0:0:3")
	t.testIncrement("ff:ff:ff:ff:ff:1-2:2-3:ff", -0x102ff, "ff:ff:ff:ff:ff:0:0:0")
	t.testIncrement("ff:ff:ff:ff:ff:1-2:2-3:ff", -0x10300, "ff:ff:ff:ff:fe:ff:ff:ff")
	t.testIncrement("0:0:0:0:0:1-2:2-3:ff", -0x10300, "")

	t.testIncrement("ff:ff:ff:1-2:2-3:ff", -0x102fb, "ff:ff:ff:0:0:4")
	t.testIncrement("ff:ff:ff:1-2:2-3:ff", -0x102fc, "ff:ff:ff:0:0:3")
	t.testIncrement("ff:ff:ff:1-2:2-3:ff", -0x102ff, "ff:ff:ff:0:0:0")
	t.testIncrement("ff:ff:ff:1-2:2-3:ff", -0x10300, "ff:ff:fe:ff:ff:ff")
	t.testIncrement("0:0:0:1-2:2-3:ff", -0x10300, "")

	t.testIncrement("ff:3-4:ff:ff:ff:1-2:2-3:0", 6, "ff:4:ff:ff:ff:2:2:0")
	t.testIncrement("ff:3-4:ff:ff:ff:1-2:2-3:0", 8, "ff:4:ff:ff:ff:2:3:1")

	t.testIncrement("3-4:ff:ff:1-2:2-3:0", 6, "4:ff:ff:2:2:0")
	t.testIncrement("3-4:ff:ff:1-2:2-3:0", 8, "4:ff:ff:2:3:1")

	t.testPrefix("25:51:27:*:*:*", p24, p24)
	t.testPrefix("25:50-51:27:*:*:*", p24, nil)
	t.testPrefix("25:51:27:12:82:55", nil, p48)
	t.testPrefix("*:*:*:*:*:*", p0, p0)
	t.testPrefix("*:*:*:*:*:*:*:*", p0, p0)
	t.testPrefix("*:*:*:*:*:*:0-fe:*", p56, nil)
	t.testPrefix("*:*:*:*:*:*:0-ff:*", p0, p0)
	t.testPrefix("*:*:*:*:*:*:0-7f:*", p49, nil)
	t.testPrefix("*:*:*:*:*:*:80-ff:*", p49, nil)
	t.testPrefix("*.*.*.*", p0, p0)
	t.testPrefix("3.*.*.*", p16, p16)
	t.testPrefix("3.*.*.1-3", nil, nil)
	t.testPrefix("3.0-7fff.*.*", p17, p17)
	t.testPrefix("3.8000-ffff.*.*", p17, p17)

	t.testPrefixes("25:51:27:*:*:*",
		16, -5,
		"25:51:27:00:*:*",
		"25:51:0:*:*:*",
		"25:51:20:*:*:*",
		"25:51:0:*:*:*",
		"25:51:0:*:*:*")

	t.testPrefixes("*:*:*:*:*:*:0-fe:*",
		15, 2,
		"*:*:*:*:*:*:0-fe:0",
		"*:*:*:*:*:*:0:*",
		"*:*:*:*:*:*:0-fe:0-3f",
		"*:00-fe:00:00:00:00:00:*",
		"*:00-fe:00:00:00:00:00:*")

	t.testPrefixes("*:*:*:*:*:*:*:*",
		15, 2,
		"0:*:*:*:*:*:*:*",
		"*:*:*:*:*:*:*:*",
		"0-3f:*:*:*:*:*:*:*",
		"0:0-1:*:*:*:*:*:*",
		"*:*:*:*:*:*:*:*")

	t.testPrefixes("1:*:*:*:*:*",
		15, 2,
		"1:0:*:*:*:*",
		"0:*:*:*:*:*",
		"1:0-3f:*:*:*:*",
		"1:0-1:*:*:*:*",
		"1:*:*:*:*:*")

	t.testPrefixes("3.8000-ffff.*.*",
		15, 2,
		"3.8000-80ff.*.*",
		"00:03:00-7f:*:*:*:*:*",
		"3.8000-9fff.*.*",
		"00:02:00-7f:*:*:*:*:*",
		"00:02:00-7f:*:*:*:*:*")

	t.testPrefixes("3.8000-ffff.*.*",
		31, 2,
		"3.8000-80ff.*.*",
		"00:03:00-7f:*:*:*:*:*",
		"3.8000-9fff.*.*",
		"3.8000-8001.*.*",
		"3.8000-ffff.*.*")

	t.testStrings()

	t.testMACCount("11:22:33:44:55:ff", 1)
	t.testMACCount("11:22:*:0-2:55:ff", 3*0x100)
	t.testMACCount("11:22:2:0-2:55:*", 3*0x100)
	t.testMACCount("11:2-4:1:0-2:55:ff", 9)
	t.testMACCount("112-114.1.0-2.55ff", 9)
	t.testMACCount("*.1.0-2.55ff", 3*0x10000)
	t.testMACCount("1-2.1-2.1-2.2-3", 16)
	t.testMACCount("1-2.1.*.2-3", 4*0x10000)
	t.testMACCount("11:*:*:0-2:55:ff", 3*0x100*0x100)

	t.testMACPrefixCount("11:22:*:0-2:55:ff", 3*0x100)
	t.testMACPrefixCount("11:22:*:0-2:55:*", 3*0x100)
	t.testMACPrefixCount("11:22:1:2:55:*", 1)

	t.testToOUIPrefixed("25:51:27:*:*:*")
	t.testToOUIPrefixed("*:*:*:*:*:*")
	t.testToOUIPrefixed("*:*:*:25:51:27")
	t.testToOUIPrefixed("ff:ee:25:51:27:*:*:*")
	t.testToOUIPrefixed("*:*:*:*:*:*:*:*")
	t.testToOUIPrefixed("*:*:*:25:51:27:ff:ee")
	t.testToOUIPrefixed("123.456.789.abc")
	t.testToOUIPrefixed("123.456.789.*")

	t.testOUIPrefixed("ff:7f:fe:2:7f:fe", "ff:7f:fe:*", 24)
	t.testOUIPrefixed("ff:7f:fe:2:7f:*", "ff:7f:fe:*", 24)
	t.testOUIPrefixed("ff:7f:fe:*", "ff:7f:fe:*", 24)
	t.testOUIPrefixed("ff:*", "ff:*", 8)
	t.testOUIPrefixed("ff:7f:fe:2:7f:fe:7f:fe", "ff:7f:fe:*:*:*:*:*", 24)
	t.testOUIPrefixed("ff:7f:0-f:*", "ff:7f:0-f:*", 20)

	t.testRadices("11:10:*:1-7f:f3:2", "10001:10000:*:1-1111111:11110011:10", 2)
	t.testRadices("0:1:0:1:0-1:1:0:1", "0:1:0:1:0-1:1:0:1", 2)

	t.testRadices("f3-ff:7f:fe:*:7_:fe", "f3-ff:7f:fe:*:70-7f:fe", 16)
	t.testRadices("*:1:0:1:0-1:1:0:1", "*:1:0:1:0-1:1:0:1", 16)

	t.testRadices("ff:7f:*:2:7_:fe", "255:127:*:2:112-127:254", 10)
	t.testRadices("*:1:0:1:0-1:1:0:1", "*:1:0:1:0-1:1:0:1", 10)

	t.testRadices("ff:*:fe:2:7d-7f:fe", "513:*:512:2:236-241:512", 7)
	t.testRadices("1:0:0-1:0:1:*", "1:0:0-1:0:1:*", 7)

	t.testRadices("ff:70-7f:fe:2:*:fe", "377:160-177:376:2:*:376", 8)
	t.testRadices("1:0:0-1:0:1:*", "1:0:0-1:0:1:*", 8)

	t.testRadices("ff:7f:fa-fe:2:7f:*", "120:87:11a-11e:2:87:*", 15)
	t.testRadices("1:0:0-1:0:1:*", "1:0:0-1:0:1:*", 15)

	t.testMatches(true, "aa:-1:cc:d:ee:f", "aa:0-1:cc:d:ee:f")
	t.testMatches(true, "aa:-:cc:d:ee:f", "aa:*:cc:d:ee:f")
	t.testMatches(true, "-:-:cc:d:ee:f", "*:cc:d:ee:f")
	t.testMatches(true, "aa:-dd:cc:d:ee:f", "aa:0-dd:cc:d:ee:f")
	t.testMatches(true, "aa:1-:cc:d:ee:f", "aa:1-ff:cc:d:ee:f")
	t.testMatches(true, "-1:aa:cc:d:ee:f", "0-1:aa:cc:d:ee:f")
	t.testMatches(true, "1-:aa:cc:d:ee:f", "1-ff:aa:cc:d:ee:f")
	t.testMatches(true, "aa:cc:d:ee:f:1-", "aa:cc:d:ee:f:1-ff")
	t.testMatches(true, "aa-|1-cc-d-ee-f", "aa-0|1-cc-d-ee-f")
	t.testMatches(true, "|1-aa-cc-d-ee-f", "0|1-aa-cc-d-ee-f")
	t.testMatches(true, "aa-1|-cc-d-ee-f", "aa-1|ff-cc-d-ee-f")
	t.testMatches(true, "1|-aa-cc-d-ee-f", "1|ff-aa-cc-d-ee-f")
	t.testMatches(true, "|-aa-cc-d-ee-f", "*-aa-cc-d-ee-f")
	t.testMatches(true, "|-|-cc-d-ee-f", "*-cc-d-ee-f")
	t.testMatches(true, "|-|-cc-d-ee-|", "*-*-cc-d-ee-*")
	t.testMatches(true, "|-|-cc-d-ee-2|", "*-*-cc-d-ee-2|ff")
	t.testMatches(true, "|-|-cc-d-ee-|2", "*-*-cc-d-ee-0|2")
	t.testMatches(true, "*-|-*", "*-*")
	t.testMatches(true, "*-|-|", "*-*")
	t.testMatches(true, "|-|-*", "*:*")
	t.testMatches(true, "*:*:*:*:*:*", "*:*")
	t.testMatches(true, "1:*:*:*:*:*", "1:*")
	t.testMatches(true, "*:*:*:*:*:1", "*:1")
	t.testMatches(true, "*:*:*:12:34:56", "*-123456")
	t.testMatches(true, "12:34:56:*:*:*", "123456-*")
	t.testMatches(true, "1:*:*:*:*:*", "1-*")
	t.testMatches(true, "*:*:*:*:*:1", "*-1")
	t.testMatches(true, "*-*-*", "*:*:*")
	t.testMatches(true, "*-*", "*:*:*")
	t.testMatches(true, "bbaacc0dee0f", "bb:aa:cc:d:ee:f")
	t.testMatches(true, "bbaacc0dee0faab0", "bb:aa:cc:d:ee:f:aa:b0")
	t.testMatches(false, "*-abcdef|fffffe", "0|ffffff-abcdef|fffffe") // inet.ipaddr.IncompatibleAddressException: *-abcdef|fffffe, IP Address error: range of joined segments cannot be divided into individual ranges
	t.testMatches(true, "*-ab0000|ffffff", "0|ffffff-ab0000|ffffff")
	t.testMatches(true, "*-ab|fe-aa-aa-aa-aa", "0|ff-ab|fe-aa-aa-aa-aa")

	// inferred lower and upper boundaries
	// single segment
	t.testMatches(true, "-abffffffffff", "000000000000-abffffffffff")
	t.testMatches(true, "000000000000-", "000000000000-ffffffffffff")
	t.testMatches(true, "ab0000000000-", "ab0000000000-ffffffffffff")
	t.testMatches(true, "-0xabffffffffff", "000000000000-abffffffffff")
	t.testMatches(true, "0x000000000000-", "000000000000-ffffffffffff")
	t.testMatches(true, "0xab0000000000-", "ab0000000000-ffffffffffff")

	t.testMatches(true, "-abffffffffffffff", "0000000000000000-abffffffffffffff")
	t.testMatches(true, "0000000000000000-", "0000000000000000-ffffffffffffffff")
	t.testMatches(true, "ab00000000000000-", "ab00000000000000-ffffffffffffffff")
	t.testMatches(true, "-0xabffffffffffffff", "0000000000000000-abffffffffffffff")
	t.testMatches(true, "0x0000000000000000-", "0000000000000000-ffffffffffffffff")
	t.testMatches(true, "0xab00000000000000-", "ab00000000000000-ffffffffffffffff")

	// dotted
	t.testMatches(true, "f302.3304.-06ff", "f302.3304.0-06ff")
	t.testMatches(true, "f302.-06ff.3304", "f302.0-06ff.3304")
	t.testMatches(true, "-06ff.f302.3304", "0-06ff.f302.3304")

	t.testMatches(true, "f302.3304.ffff.-06ff", "f302.3304.ffff.0-06ff")
	t.testMatches(true, "f302.3304.-06ff.ffff", "f302.3304.0-06ff.ffff")
	t.testMatches(true, "f302.-06ff.3304.ffff", "f302.0-06ff.3304.ffff")
	t.testMatches(true, "-06ff.f302.3304.ffff", "0-06ff.f302.3304.ffff")

	t.testMatches(true, "f302.3304.100-", "f302.3304.100-ffff")
	t.testMatches(true, "f302.100-.3304", "f302.100-ffff.3304")
	t.testMatches(true, "100-.f302.3304", "100-ffff.f302.3304")

	t.testMatches(true, "f302.3304.ffff.1100-", "f302.3304.ffff.1100-ffff")
	t.testMatches(true, "f302.3304.1100-.ffff", "f302.3304.1100-ffff.ffff")
	t.testMatches(true, "f302.1100-.3304.ffff", "f302.1100-ffff.3304.ffff")
	t.testMatches(true, "1100-.f302.3304.ffff", "1100-ffff.f302.3304.ffff")

	// colon
	t.testMatches(true, "aa-:bb:cc:dd:ee:ff", "aa-ff:bb:cc:dd:ee:ff")
	t.testMatches(true, "aa-:bb-:cc:dd:ee:ff", "aa-ff:bb-ff:cc:dd:ee:ff")
	t.testMatches(true, "aa-:bb:cc-:dd:ee:ff", "aa-ff:bb:cc-ff:dd:ee:ff")
	t.testMatches(true, "aa-:bb:cc:dd-:ee:ff", "aa-ff:bb:cc:dd-ff:ee:ff")
	t.testMatches(true, "aa-:bb:cc:dd:ee-:ff", "aa-ff:bb:cc:dd:ee-ff:ff")
	t.testMatches(true, "aa-:bb:cc:dd:ee:ff-", "aa-ff:bb:cc:dd:ee:ff")
	t.testMatches(true, "aa-:bb:cc:dd:ee:ee-", "aa-ff:bb:cc:dd:ee:ee-ff")
	t.testMatches(true, "aa-:bb:cc:dd:ee:ee-:aa:bb", "aa-ff:bb:cc:dd:ee:ee-ff:aa:bb")
	t.testMatches(true, "aa-:bb:cc:dd:ee:ee:aa-:bb", "aa-ff:bb:cc:dd:ee:ee:aa-ff:bb")
	t.testMatches(true, "aa-:bb:cc:dd:ee:ee:aa:bb-", "aa-ff:bb:cc:dd:ee:ee:aa:bb-ff")

	t.testMatches(true, "-ff:bb:cc:dd:ee:ff", "00-ff:bb:cc:dd:ee:ff")
	t.testMatches(true, "-ff:-bb:cc:dd:ee:ff", "00-ff:00-bb:cc:dd:ee:ff")
	t.testMatches(true, "-ff:-bb:0-cc:dd:ee:ff", "00-ff:00-bb:-cc:dd:ee:ff")
	t.testMatches(true, "ff:-bb:0-cc:dd-0:ee:ff", "ff:00-bb:-cc:-dd:ee:ff") // reverse range
	t.testMatches(true, "ff:-bb:0-cc:0-dd:ee-:ff", "ff:00-bb:-cc:-dd:ee-ff:ff")
	t.testMatches(true, "ff:-bb:0-cc:0-dd:ee-:-ff", "ff:00-bb:-cc:-dd:ee-ff:0-ff")
	t.testMatches(true, "ff:-bb:0-cc:0-dd:ee-:-ff:0-aa:bb", "ff:00-bb:-cc:-dd:ee-ff:0-ff:-aa:bb")
	t.testMatches(true, "ff:-bb:0-cc:0-dd:ee-:-ff:0-aa:bb-", "ff:bb-0:-cc:-dd:ee-ff:0-ff:-aa:bb-ff")
	// end inferred lower and upper boundaries

	t.testMatches(true, "1-02.03-4.05-06.07", "1-2.3-4.5-6.7")
	t.testMatches(true, "1-002.003-4.005-006.007", "1-2.3-4.5-6.7")
	t.testMatches(true, "1-002.003-4.0005-006.0007", "1-2.3-4.5-6.7")
	t.testMatches(true, "1100-22ff.003-4.0005-006.0007", "1100-22ff.3-4.5-6.7")
	t.testMatches(true, "1-2.0-0.00-00.00-0", "1-2.0.0.0")
	t.testMatches(true, "00-0.0-0.00-00.00-0", "0.0.0.0")
	t.testMatches(true, "0-00:0-0:00-00:00-0:0-00:00-00:00-00:00-0", "0:0:0:0:0:0:0:0")
	t.testMatches(true, "1-2:0-0:00-00:00-0:0-00:00-00:00-00:00-0", "1-2:0:0:0:0:0:0:0")

	t.testMatches(true, "11:11:11:ff:20-2f:0", "11:11:11:ff:2_:0")
	t.testMatches(true, "20-2f:11:11:11:1:1", "2_:11:11:11:1:1")
	t.testMatches(true, "1:2:3:4:20-2f:6:7:8", "1:2:3:4:2_:6:7:8")
	t.testMatches(true, "1:2:20-2f:4:5:6:7:8", "1:2:2_:4:5:6:7:8")
	t.testMatches(true, "1:2:3:4:5:20-2f", "1:2:3:4:5:2_")
	t.testMatches(true, "1:2:3:20-2f:5:8", "1:2:3:2_:5:8")
	t.testMatches(true, "20-2f:2:3:4:5:8", "2_:2:3:4:5:8")
	t.testMatches(true, "1:2:3:4:5:20-2f", "1:2:3:4:5:2_")
	t.testMatches(true, "20-2f:2:3:4:5:6:7:8", "2_:2:3:4:5:6:7:8")
	t.testMatches(true, "20-2f:2:3:4:5:6", "2_:2:3:4:5:6")
	t.testMatches(true, "11:11:11:ff:0-f:0", "11:11:11:ff:_:0")
	t.testMatches(true, "0-f:11:11:11:1:1", "_:11:11:11:1:1")
	t.testMatches(true, "1:2:3:4:0-f:6:7:8", "1:2:3:4:_:6:7:8")
	t.testMatches(true, "1:2:0-f:4:5:6:7:8", "1:2:_:4:5:6:7:8")
	t.testMatches(true, "1:2:3:4:6:0-f", "1:2:3:4:6:_")
	t.testMatches(true, "1:2:3:0-f:5:6:8:8", "1:2:3:_:5:6:8:8")
	t.testMatches(true, "0-f:2:3:5:ff:8", "_:2:3:5:ff:8")
	t.testMatches(true, "1:11:11:11:1:0-f", "1:11:11:11:1:_")
	t.testMatches(true, "0-f:2:3:4:5:6:7:8", "_:2:3:4:5:6:7:8")
	t.testMatches(true, "0-f:2:3:4:5:6", "_:2:3:4:5:6")
	t.testMatches(true, "1:5:2:3:4:0-f", "1:5:2:3:4:_")
	t.testMatches(true, "11:11:11:ff:*:0", "11:11:11:ff:__:0")
	t.testMatches(true, "*:11:11:11:1:1", "__:11:11:11:1:1")
	t.testMatches(true, "1:2:3:4:*:6:7:8", "1:2:3:4:__:6:7:8")
	t.testMatches(true, "1:2:*:4:5:6:7:8", "1:2:__:4:5:6:7:8")
	t.testMatches(true, "1:2:3:4:5:*", "1:2:3:4:5:__")
	t.testMatches(true, "1:2:3:*:5:8", "1:2:3:__:5:8")
	t.testMatches(true, "*:2:3:4:5:8", "__:2:3:4:5:8")
	t.testMatches(true, "1:2:3:4:5:*", "1:2:3:4:5:__")
	t.testMatches(true, "*:2:3:4:5:6:7:8", "__:2:3:4:5:6:7:8")
	t.testMatches(true, "*:2:3:4:5:6", "__:2:3:4:5:6")
	t.testMatches(true, "1:2:3:4:4:*", "1:2:3:4:4:__")

	t.testMatches(true, "0-ff.2.3.4", "__.2.3.4")
	t.testMatches(true, "1.2.3.0-ff", "1.2.3.__")
	t.testMatches(true, "0-f.2.3.4", "_.2.3.4")
	t.testMatches(true, "1.2.3.0-f", "1.2.3._")
	t.testMatches(true, "1.0-fff.3.4", "1.___.3.4")
	t.testMatches(true, "1.2.0-fff.0-f", "1.2.___._")
	t.testMatches(true, "1.*.3.4", "1.____.3.4")
	t.testMatches(true, "1.2.*.0-f", "1.2.____._")
	t.testMatches(true, "*.2.3.4", "____.2.3.4")
	t.testMatches(true, "1.2.3.*", "1.2.3.____")

	t.testDelimitedCount("1,2|3,4-3-4,5-6-7-8", 8)            //this will iterate through 1.3.4.6 1.3.5.6 2.3.4.6 2.3.5.6
	t.testDelimitedCount("1,2-3,6-7-8-4,5|6-6,8", 16)         //this will iterate through 1.3.4.6 1.3.5.6 2.3.4.6 2.3.5.6
	t.testDelimitedCount("1:2:3:*:4:5", 1)                    //this will iterate through 1.3.4.6 1.3.5.6 2.3.4.6 2.3.5.6
	t.testDelimitedCount("1:2,3,*:3:6:4:5,ff,7,8,99", 15)     //this will iterate through 1.3.4.6 1.3.5.6 2.3.4.6 2.3.5.6
	t.testDelimitedCount("1:0,1-2,3,5:3:6:4:5,ff,7,8,99", 30) //this will iterate through 1.3.4.6 1.3.5.6 2.3.4.6 2.3.5.6

	t.testNotContains("*.*", "1.2.3.4")
	t.testContains("*.*.*.*", "1.2.3.4", false)
	t.testContains("*.*.*", "1.2.3", false)
	t.testContains("*.*.1.aa00-ffff", "1.2.1.bbbb", false)
	t.testContains("*.*.1.aa00-ffff", "0-ffff.*.1.aa00-ffff", true)
	t.testContains("0-1ff.*.*.*", "127.2.3.4", false)
	t.testContains("0-1ff.*.*.*", "128.2.3.4", false)
	t.testNotContains("0-1ff.*", "200.2.3.4")
	t.testNotContains("0-1ff.*", "128.2.3.4")
	t.testContains("0-1ff.*", "128.2.3", false)
	t.testContains("0-ff.*.*.*", "15.2.3.4", false)
	t.testContains("0-ff.*", "15.2.3", false)
	t.testContains("9.129.*.*", "9.129.237.26", false)
	t.testContains("9.129.*", "9.129.237", false)
	t.testNotContains("9.129.*.25", "9.129.237.26")
	t.testContains("9.129.*.26", "9.129.237.26", false)
	t.testContains("9.129.*.26", "9.129.*.26", true)

	t.testContains("9.a0-ae.1.226-254", "9.ad.1.227", false)
	t.testNotContains("9.a0-ac.1.226-254", "9.ad.1.227")
	t.testNotContains("9.a0-ae.2.226-254", "9.ad.1.227")
	t.testContains("9.a0-ae.1.226-254", "9.a0-ae.1.226-254", true)

	t.testContains("8-9:a0-ae:1-3:20-26:0:1", "9:ad:1:20:0:1", false)
	t.testContains("8-9:a0-ae:1-3:20-26:0:1", "9:ad:1:23-25:0:1", false)
	t.testNotContains("8-9:a0-ae:1-3:20-26:0:1", "9:ad:1:23-27:0:1")
	t.testNotContains("8-9:a0-ae:1-3:20-26:0:1", "9:ad:1:18-25:0:1")
	t.testContains("*:*:*:*:ab:*:*:*", "*:*:*:*:ab:*:*:*", true)
	t.testContains("*:*:*:*:*:*:*:*", "*:*:*:*:*:*:*:*", true)
	t.testContains("*:*:*:*:*:*:*:*", "a:b:c:d:e:f:a:b", false)
	t.testContains("*:*:*:*:*:*", "a:b:c:d:a:b", false)
	t.testContains("80-8f:*:*:*:*:*", "8a:d:e:f:a:b", false)
	t.testContains("*:*:*:*:*:80-8f", "d:e:f:a:b:8a", false)
	t.testContains("*:*:*:*:*:*:*:*", "a:*:c:d:e:1-ff:a:b", false)
	t.testContains("8a-8d:*:*:*:*:*:*:*", "8c:b:c:d:e:f:*:b", false)
	t.testNotContains("80:0:0:0:0:0:0:0-1", "7f-8f:b:c:d:e:f:*:b")
	t.testContains("ff:0-3:*:*:*:*:*:*", "ff:0-3:c:d:e:f:a:b", false)
	t.testNotContains("ff:0-3:*:*:*:*:*:*", "ff:0-4:c:d:e:f:a:b")
	t.testContains("ff:0:*:*:*:*:*:*", "ff:0:ff:1-d:e:f:*:b", false)
	t.testContains("*:*:ff:0:*:*:*:*", "*:b:ff:0:ff:1-d:e:f", false)
	t.testNotContains("ff:0:*:*:*:*:*:*", "ff:0-1:ff:d:e:f:a:b")
	t.testContains("ff:0:0:0:0:4-ff:0:fc-ff", "ff:0:0:0:0:4-ff:0:fd-ff", false)
	t.testContains("ff:0:0:0:0:4-ff:0:fc-ff", "ff:0:0:0:0:4-ff:0:fc-ff", true)
	t.testContains("ff:0:*:0:0:4-ff:0:ff", "ff:0:*:0:0:4-ff:0:ff", true)
	t.testContains("*:*:*:*:*:*:*:*", "*:*:*:*:*:*:*:*", true)
	t.testContains("80-8f:*:*:*:*:80-8f", "83-8e:*:*:*:a-b:80-8f", false)
	t.testContains("80-8f:*:*:*:*:80-8f", "83-8e:*:*:*:a-b:80-8f", false)
	t.testNotContains("80-8f:*:*:*:*:80-8f", "7f-8e:*:*:*:a-b:80-8f")

	t.testLongShort2("ff:ff:ff:ff:ff:*:ff:1-ff", "ff:ff:ff:*:ff:1-ff", true)
	t.testLongShort2("12-cd-cc-dd-ee-ff-*", "12-cd-cc-*", true)
	t.testLongShort2("12CD.CCdd.*.a", "12CD.*.a", true)
	t.testLongShort2("*-0D0E0F0A0B", "0A0B0C-*", true)
	t.testLongShort("*-0D0E0F0A0B", "*-0A0B0C")
	t.testLongShort2("*-0D0E0F0A0B", "*-*", true)
	t.testLongShort("ee:ff:aa:*:dd:ee:ff", "ee:ff:a-b:bb:cc:dd")
	t.testLongShort2("ee:ff:aa:*:dd:ee:ff", "ee:ff:a-b:*:dd", true)
	t.testLongShort2("e:f:a:b:c:d:e:e-f", "e:*", true)

	t.testSections("00-1:21-ff:*:10")
	t.testSections("00-1:21-ff:2f:*:10")
	t.testSections("*-A7-94-07-CB-*")
	t.testSections("aa-*")
	t.testSections("aa-bb-*")
	t.testSections("aa-bb-cc-*")
	t.testSections("8-9:a0-ae:1-3:20-26:0:1")
	t.testSections("fe-ef-39-*-94-07-b|C-D0")
	t.testSections("5634-5678.*.7feb.6b40")
	t.testSections("ff:0:1:*")
	t.testSections("ff:0:1:*:*:*:*:*")

	t.testInsertAndAppend("*:*:*:*:*:*:*:*", "*:*:*:*:*:*:*:*", []ipaddr.BitCount{0, 0, 0, 0, 0, 0, 0, 0, 0})
	t.testInsertAndAppend("a:b:c:d:e:f:aa:bb", "*:*:*:*:*:*:*:*", []ipaddr.BitCount{0, 8, 16, 24, 32, 40, 48, 56, 64})
	//t.testInsertAndAppend("*:*:*:*:*:*:*:*", "1:2:3:4:5:6:7:8", []ipaddr.BitCount{0, 0, 0, 0, 0, 0, 0, 0, 0})
	t.testInsertAndAppendPrefs("*:*:*:*:*:*:*:*", "1:2:3:4:5:6:7:8", []ipaddr.PrefixLen{nil, p0, p0, p0, p0, p0, p0, p0, p0})

	t.testInsertAndAppend("a:b:c:d:*:*:*:*", "1:2:3:4:*:*:*:*", []ipaddr.BitCount{32, 32, 32, 32, 32, 32, 32, 32, 32})
	t.testInsertAndAppend("a:b:c:d:e:f:aa:bb", "1:2:3:4:*:*:*:*", []ipaddr.BitCount{32, 32, 32, 32, 32, 40, 48, 56, 64})
	t.testInsertAndAppendPrefs("a:b:c:0-1:*:*:*:*", "1:2:3:4:5:6:7:8", []ipaddr.PrefixLen{pnil, pnil, pnil, pnil, p31, p31, p31, p31, p31})
	t.testInsertAndAppendPrefs("a:b:c:d:*:*:*:*", "1:2:3:4:5:6:7:8", []ipaddr.PrefixLen{pnil, pnil, pnil, pnil, p32, p32, p32, p32, p32})
	t.testInsertAndAppendPrefs("a:b:c:d:0-7f:*:*:*", "1:2:3:4:5:6:7:8", []ipaddr.PrefixLen{pnil, pnil, pnil, pnil, pnil, p33, p33, p33, p33})

	t.testInsertAndAppend("a:b:*:*:*:*:*:*", "1:2:3:4:*:*:*:*", []ipaddr.BitCount{32, 32, 16, 16, 16, 16, 16, 16, 16})
	t.testInsertAndAppend("a:b:c:d:*:*:*:*", "1:2:*:*:*:*:*:*", []ipaddr.BitCount{16, 16, 16, 24, 32, 32, 32, 32, 32})
	//t.testInsertAndAppend("*:*:*:*:*:*:*:*", "1:2:3:4:*:*:*:*", []ipaddr.BitCount{0, 0, 0, 0, 0, 0, 0, 0, 0})
	t.testInsertAndAppendPrefs("*:*:*:*:*:*:*:*", "1:2:3:4:*:*:*:*", []ipaddr.PrefixLen{p32, p0, p0, p0, p0, p0, p0, p0, p0})
	t.testInsertAndAppendPrefs("a:b:c:d:*:*:*:*", "1:2:3:4:5:6:7:8", []ipaddr.PrefixLen{pnil, pnil, pnil, pnil, p32, p32, p32, p32, p32})
	t.testInsertAndAppendPrefs("a:b:c:d:e:f:aa:bb", "1:2:3:4:*:*:*:*", []ipaddr.PrefixLen{p32, p32, p32, p32, p32, p40, p48, p56, pnil})

	t.testReplace("*:*:*:*:*:*:*:*", "*:*:*:*:*:*:*:*")
	t.testReplace("a:b:c:d:e:f:aa:bb", "*:*:*:*:*:*:*:*")
	t.testReplace("*:*:*:*:*:*:*:*", "1:2:3:4:5:6:7:8")

	t.testReplace("a:b:c:d:*:*:*:*", "1:2:3:4:*:*:*:*")
	t.testReplace("a:b:c:d:e:f:aa:bb", "1:2:3:4:*:*:*:*")
	t.testReplace("a:b:c:0-1:*:*:*:*", "1:2:3:4:5:6:7:8")
	t.testReplace("a:b:c:d:*:*:*:*", "1:2:3:4:5:6:7:8")
	t.testReplace("a:b:c:d:0-7f:*:*:*", "1:2:3:4:5:6:7:8")

	t.testReplace("a:b:*:*:*:*:*:*", "1:2:3:4:*:*:*:*")
	t.testReplace("a:b:c:d:*:*:*:*", "1:2:*:*:*:*:*:*")
	t.testReplace("*:*:*:*:*:*:*:*", "1:2:3:4:*:*:*:*")
	t.testReplace("a:b:c:d:*:*:*:*", "1:2:3:4:5:6:7:8")
	t.testReplace("a:b:c:d:e:f:aa:bb", "1:2:3:4:*:*:*:*")

	t.testMACIPv6("aaaa:bbbb:cccc:dddd:0221:2fff:fe00-feff:6e10", "00:21:2f:*:6e:10")
	t.testMACIPv6("*:*:*:*:200-2ff:FF:FE00-FEFF:*", "0:*:0:*:*:*")
	t.testMACIPv6("*:*:*:*:200-3ff:abFF:FE01-FE03:*", "0-1:*:ab:1-3:*:*")
	t.testMACIPv6("*:*:*:*:a200-a3ff:abFF:FE01-FE03:*", "a0-a1:*:ab:1-3:*:*")
	t.testMACIPv6("*:2:*:*:a388-a399:abFF:FE01-FE03:*", "a1:88-99:ab:1-3:*:*")
	t.testMACIPv6("*:2:*:*:a388-a399:abFF:FE01-FE03:*", "a1:88-99:ab:1-3:*:*")
	t.testMACIPv6("1:0:0:0:8a0:bbff:fe00-feff:*", "0a:a0:bb:*:*:*") //[1:0:0:0:aa0:bbff:fe00-feff:*, 1:0:0:0:8a0:bbff:fe00-feff:*]
	t.testMACIPv6("1:0:0:0:200:bbff:fe00:b00-cff", "00:00:bb:00:0b-0c:*")
	t.testMACIPv6("1:0:0:0:200:bbff:fe00:b00-cff", "00:00:bb:00:0b-0c:*")
	t.testMACIPv6("1:0:0:0:c200:aaff:fec0:b00-cff", "c0:00:aa:c0:0b-0c:*")
	t.testMACIPv6("1:0:0:0:200:aaff:fe00:b00", "00:00:aa:00:0b:00")
	t.testMACIPv6("1:0:0:0:200:bbff:fe00:b00-cff", "00:00:bb:00:0b-0c:*")
	t.testMACIPv6("1:0:0:0:200:bbff:fe00-feff:*", "00:00:bb:*:*:*")

	t.testPrefixBlock("ff:*:*:*:*:*", 8)
	t.testPrefixBlock("ff:ff:*:*:*:*", 16)
	t.testPrefixBlock("ff:fe-ff:*:*:*:*", 15)
	t.testPrefixBlock("ff:fc-ff:*:*:*:*", 14)
	t.testPrefixBlock("ff:ff:80-ff:*:*:*", 17)
	t.testPrefixBlock("ff:ff:0-7f:*:*:*", 17)
	t.testPrefixBlock("ff:ff:0-3f:*:*:*", 18)
	t.testPrefixBlock("ff:0:0:ff:0:*", 40)
	t.testPrefixBlock("ff:0:0:ff:0:fe-ff", 47)

	t.testTrees()

	t.macAddressTester.run()
}

func (t macAddressRangeTester) testToOUIPrefixed(addrString string) {
	w := t.createMACAddress(addrString)
	v := w.GetAddress()
	suffixSeg := ipaddr.NewMACRangeSegment(0, 0xff)
	suffixSegs := make([]*ipaddr.MACAddressSegment, v.GetSegmentCount())
	v.CopySubSegments(0, 3, suffixSegs)
	for i := 3; i < len(suffixSegs); i++ {
		suffixSegs[i] = suffixSeg
	}
	suffix := ipaddr.NewMACSection(suffixSegs)
	//if err != nil {
	//	t.addFailure(newMACFailure(err.Error(), w))
	//}
	suffixed, err := ipaddr.NewMACAddress(suffix)
	if err != nil {
		t.addFailure(newMACFailure(err.Error(), w))
	}
	prefixed := v.ToOUIPrefixBlock()
	if !prefixed.Equal(suffixed) {
		t.addFailure(newMACFailure("failed oui prefixed "+prefixed.String()+" constructed "+suffixed.String(), w))
	}
	t.incrementTestCount()
}

func (t macAddressRangeTester) testOUIPrefixed(original, expected string, expectedPref ipaddr.BitCount) {
	w := t.createMACAddress(original)
	val := w.GetAddress()
	w2 := t.createMACAddress(expected)
	expectedAddress := w2.GetAddress()
	prefixed := val.ToOUIPrefixBlock()
	if !prefixed.Equal(expectedAddress) {
		t.addFailure(newMACFailure("oui prefixed was "+prefixed.String()+" expected was "+expected, w))
	}
	if expectedPref != prefixed.GetPrefixLen().Len() {
		t.addFailure(newMACFailure("oui prefix was "+prefixed.GetPrefixLen().String()+" expected was "+bitCountToString(expectedPref), w))
	}
	t.incrementTestCount()
}

func (t macAddressRangeTester) testEquivalentPrefix(host string, prefix ipaddr.BitCount) {
	t.testEquivalentMinPrefix(host, cacheTestBits(prefix), prefix)
}

func (t macAddressRangeTester) testEquivalentMinPrefix(host string, equivPrefix ipaddr.PrefixLen, minPrefix ipaddr.BitCount) {
	str := t.createMACAddress(host)
	h1, err := str.ToAddress()
	if err != nil {
		t.addFailure(newMACFailure(err.Error(), str))
	} else {
		equiv := h1.GetPrefixLenForSingleBlock()
		if !equivPrefix.Equal(equiv) {
			t.addFailure(newMACAddrFailure("failed: prefix expected: "+equivPrefix.String()+" prefix got: "+equiv.String(), h1))
		} else {
			minPref := h1.GetMinPrefixLenForBlock()
			if minPref != minPrefix {
				t.addFailure(newMACAddrFailure("failed: prefix expected: "+bitCountToString(minPrefix)+" prefix got: "+bitCountToString(minPref), h1))
			}
		}
	}
	t.incrementTestCount()
}

func bitCountToString(i ipaddr.BitCount) string {
	return strconv.Itoa(i)
}

func (t macAddressRangeTester) testMACCount(original string, number uint64) {
	w := t.createMACAddress(original)
	t.testMACCountRedirect(w, number)
}

func (t macAddressRangeTester) testMACCountRedirect(w *ipaddr.MACAddressString, number uint64) {
	t.testCountRedirect(w.Wrap(), number, math.MaxUint64)
}

func (t macAddressRangeTester) testMACPrefixCount(original string, number uint64) {
	w := t.createMACAddress(original)
	t.testMACPrefixCountImpl(w, number)
}

func (t macAddressRangeTester) testMACPrefixCountImpl(w *ipaddr.MACAddressString, number uint64) {
	t.testPrefixCountImpl(w.Wrap(), number)
}

func (t macAddressRangeTester) testPrefixBlock(prefixedAddressStr string, expectedPref ipaddr.BitCount) {
	//starting with prefixed address like 1:2:3:*:*:*, get lower (whcih should retain prefix except for allsubnets)
	//check if prefix block (not), then for all subnets assign prefix, then for all call toPrefixBlock, compare with original and also the prefix
	prefixedAddressString := t.createMACAddress(prefixedAddressStr)
	prefixedAddress := prefixedAddressString.GetAddress()

	//a whole bunch of address manipulations, all of which we will reverse and then convert back to the prefix block
	lower := prefixedAddress.GetLower()
	upper := prefixedAddress.GetUpper()
	removedPrefix := prefixedAddress.WithoutPrefixLen()
	adjustPrefix := prefixedAddress.AdjustPrefixLen(1)
	adjustPrefix2 := prefixedAddress.AdjustPrefixLen(-1)
	hostSeg := int((prefixedAddress.GetPrefixLen().Len() + (ipaddr.MACBitsPerSegment - 1)) / ipaddr.MACBitsPerSegment)
	replaced := prefixedAddress
	replacement := t.createMACAddress("1:1:1:1:1:1").GetAddress()
	for i := hostSeg; i < replaced.GetSegmentCount(); i++ {
		replaced = replaced.ReplaceLen(i, i+1, replacement, i)
	}
	if lower.Equal(upper) {
		t.addFailure(newSegmentSeriesFailure("lower / upper "+lower.String()+" / "+upper.String(), prefixedAddress))
	}
	if !prefixedAddress.IsPrefixBlock() {
		t.addFailure(newSegmentSeriesFailure("not prefix block", prefixedAddress))
	}
	if !adjustPrefix.IsPrefixBlock() {
		t.addFailure(newSegmentSeriesFailure("adjustPrefix is not prefix block: "+adjustPrefix.String(), prefixedAddress))
	}
	if !adjustPrefix.IsPrefixed() {
		t.addFailure(newSegmentSeriesFailure("adjustPrefix not prefixed: "+adjustPrefix.GetPrefixLen().String(), prefixedAddress))
	}
	if !adjustPrefix2.IsPrefixed() {
		t.addFailure(newSegmentSeriesFailure("adjustPrefix2 not prefixed: "+adjustPrefix2.GetPrefixLen().String(), prefixedAddress))
	}
	if removedPrefix.IsPrefixed() {
		t.addFailure(newSegmentSeriesFailure("removedPrefix prefixed: "+removedPrefix.GetPrefixLen().String(), prefixedAddress))
	}
	if !replaced.IsPrefixed() {
		t.addFailure(newSegmentSeriesFailure("replaced prefixed: "+replaced.GetPrefixLen().String(), prefixedAddress))
	}

	if hostSeg < replaced.GetSegmentCount() && replaced.IsPrefixBlock() {
		t.addFailure(newSegmentSeriesFailure("replaced is prefix block: "+replaced.String(), prefixedAddress))
	}
	if adjustPrefix2.IsPrefixBlock() {
		t.addFailure(newSegmentSeriesFailure("adjustPrefix2 is not prefix block: "+adjustPrefix2.String(), prefixedAddress))
	}
	if !lower.IsPrefixed() {
		t.addFailure(newSegmentSeriesFailure("lower not prefixed: "+lower.String(), prefixedAddress))
	}
	if lower.IsPrefixBlock() {
		t.addFailure(newSegmentSeriesFailure("lower is prefix block: "+lower.String(), prefixedAddress))
	}
	if !upper.IsPrefixed() {
		t.addFailure(newSegmentSeriesFailure("upper not prefixed: "+upper.String(), prefixedAddress))
	}
	if upper.IsPrefixBlock() {
		t.addFailure(newSegmentSeriesFailure("upper is prefix block: "+upper.String(), prefixedAddress))
	}
	prefixedBlockAgain := lower.ToPrefixBlock()
	if !prefixedBlockAgain.IsPrefixBlock() {
		t.addFailure(newSegmentSeriesFailure("reconstituted prefix block not a prefix block: "+prefixedBlockAgain.String(), prefixedAddress))
	}
	if !prefixedBlockAgain.Equal(prefixedAddress) {
		t.addFailure(newSegmentSeriesFailure("reconstituted prefix block mismatch: "+prefixedBlockAgain.String()+" original: "+prefixedAddress.String(), prefixedAddress))
	}
	if !prefixedBlockAgain.GetPrefixLen().Equal(prefixedAddress.GetPrefixLen()) {
		t.addFailure(newSegmentSeriesFailure("reconstituted prefix block prefix mismatch: "+prefixedBlockAgain.GetPrefixLen().String()+" original: "+prefixedAddress.GetPrefixLen().String(), prefixedAddress))
	}

	//now revert all our operations, convert them all back to prefix blocks, and compare
	removedPrefix = removedPrefix.SetPrefixLen(prefixedAddress.GetPrefixLen().Len())
	adjustPrefix = adjustPrefix.AdjustPrefixLen(-1)
	adjustPrefix2 = adjustPrefix2.AdjustPrefixLen(1)
	if !prefixedBlockAgain.Equal(removedPrefix.ToPrefixBlock()) || !prefixedBlockAgain.GetPrefixLen().Equal(removedPrefix.GetPrefixLen()) {
		t.addFailure(newSegmentSeriesFailure("reconstituted prefix block mismatch with other: "+prefixedBlockAgain.String()+" other: "+removedPrefix.String(), prefixedAddress))
	}
	if !prefixedBlockAgain.Equal(adjustPrefix.ToPrefixBlock()) || !prefixedBlockAgain.GetPrefixLen().Equal(adjustPrefix.GetPrefixLen()) {
		t.addFailure(newSegmentSeriesFailure("reconstituted prefix block mismatch with other: "+prefixedBlockAgain.String()+" other: "+adjustPrefix.String(), prefixedAddress))
	}
	if !prefixedBlockAgain.GetPrefixLen().Equal(adjustPrefix2.GetPrefixLen()) {
		t.addFailure(newSegmentSeriesFailure("reconstituted prefix block mismatch with other: "+prefixedBlockAgain.String()+" other: "+adjustPrefix2.String(), prefixedAddress))
	}
	if !prefixedBlockAgain.Equal(replaced.ToPrefixBlock()) || !prefixedBlockAgain.GetPrefixLen().Equal(replaced.GetPrefixLen()) {
		t.addFailure(newSegmentSeriesFailure("reconstituted prefix block mismatch with other: "+prefixedBlockAgain.String()+" other: "+replaced.String(), prefixedAddress))
	}
	if !prefixedBlockAgain.Equal(upper.ToPrefixBlock()) || !prefixedBlockAgain.GetPrefixLen().Equal(upper.GetPrefixLen()) {
		t.addFailure(newSegmentSeriesFailure("reconstituted prefix block mismatch with other: "+prefixedBlockAgain.String()+" other: "+upper.String(), prefixedAddress))
	}
	t.incrementTestCount()
}

func (t macAddressRangeTester) testStrings() {

	t.testMACStrings("a:b:c:d:*:*:*",
		"0a:0b:0c:0d:*:*:*:*",               //normalizedString, //toColonDelimitedString
		"a:b:c:d:*:*:*:*",                   //compressedString,
		"0a-0b-0c-0d-*-*-*-*",               //canonicalString, //toDashedString
		"0a0b.0c0d.*.*",                     //dottedString,
		"0a 0b 0c 0d * * * *",               //spaceDelimitedString,
		"0a0b0c0d00000000-0a0b0c0dffffffff") //singleHex

	t.testMACStrings("a:b:c:*:*:*:*",
		"0a:0b:0c:*:*:*:*:*",                //normalizedString, //toColonDelimitedString
		"a:b:c:*:*:*:*:*",                   //compressedString,
		"0a-0b-0c-*-*-*-*-*",                //canonicalString, //toDashedString
		"0a0b.0c00-0cff.*.*",                //dottedString,
		"0a 0b 0c * * * * *",                //spaceDelimitedString,
		"0a0b0c0000000000-0a0b0cffffffffff") //singleHex

	t.testMACStrings("a:b:c:d:*",
		"0a:0b:0c:0d:*:*",           //normalizedString, //toColonDelimitedString
		"a:b:c:d:*:*",               //compressedString,
		"0a-0b-0c-0d-*-*",           //canonicalString, //toDashedString
		"0a0b.0c0d.*",               //dottedString,
		"0a 0b 0c 0d * *",           //spaceDelimitedString,
		"0a0b0c0d0000-0a0b0c0dffff") //singleHex

	t.testMACStrings("a:b:c:d:1-2:*",
		"0a:0b:0c:0d:01-02:*",       //normalizedString, //toColonDelimitedString
		"a:b:c:d:1-2:*",             //compressedString,
		"0a-0b-0c-0d-01|02-*",       //canonicalString, //toDashedString
		"0a0b.0c0d.0100-02ff",       //dottedString,
		"0a 0b 0c 0d 01-02 *",       //spaceDelimitedString,
		"0a0b0c0d0100-0a0b0c0d02ff") //singleHex

	t.testMACStrings("0:0:c:d:e:f:10-1f:b",
		"00:00:0c:0d:0e:0f:10-1f:0b", //normalizedString, //toColonDelimitedString
		"0:0:c:d:e:f:10-1f:b",        //compressedString,
		"00-00-0c-0d-0e-0f-10|1f-0b", //canonicalString, //toDashedString
		"",                           //dottedString,
		"00 00 0c 0d 0e 0f 10-1f 0b", //spaceDelimitedString,
		"")                           //singleHex

	t.testMACStrings("0:0:c:d:e:f:10-1f:*",
		"00:00:0c:0d:0e:0f:10-1f:*",         //normalizedString, //toColonDelimitedString
		"0:0:c:d:e:f:10-1f:*",               //compressedString,
		"00-00-0c-0d-0e-0f-10|1f-*",         //canonicalString, //toDashedString
		"0000.0c0d.0e0f.1000-1fff",          //dottedString,
		"00 00 0c 0d 0e 0f 10-1f *",         //spaceDelimitedString,
		"00000c0d0e0f1000-00000c0d0e0f1fff") //singleHex

	t.testMACStrings("a-b:b-c:0c-0d:0d-e:e-0f:f-ff:aa-bb:bb-cc",
		"0a-0b:0b-0c:0c-0d:0d-0e:0e-0f:0f-ff:aa-bb:bb-cc", //normalizedString, //toColonDelimitedString
		"a-b:b-c:c-d:d-e:e-f:f-ff:aa-bb:bb-cc",            //compressedString,
		"0a|0b-0b|0c-0c|0d-0d|0e-0e|0f-0f|ff-aa|bb-bb|cc", //canonicalString, //toDashedString
		"", //dottedString,
		"0a-0b 0b-0c 0c-0d 0d-0e 0e-0f 0f-ff aa-bb bb-cc", //spaceDelimitedString,
		"") //singleHex

	t.testMACStrings("12-ef:*:cd:d:0:*",
		"12-ef:*:cd:0d:00:*",       //normalizedString, //toColonDelimitedString
		"12-ef:*:cd:d:0:*",         //compressedString,
		"12|ef-*-cd-0d-00-*",       //canonicalString, //toDashedString
		"1200-efff.cd0d.0000-00ff", //dottedString,
		"12-ef * cd 0d 00 *",       //spaceDelimitedString,
		"")                         //singleHex

	t.testMACStrings("ff:ff:*:*:aa-ff:0-de",
		"ff:ff:*:*:aa-ff:00-de", //normalizedString, //toColonDelimitedString
		"ff:ff:*:*:aa-ff:0-de",  //compressedString,
		"ff-ff-*-*-aa|ff-00|de", //canonicalString, //toDashedString
		"",                      //dottedString,
		"ff ff * * aa-ff 00-de", //spaceDelimitedString,
		"")                      //singleHex

	t.testMACStrings("ff:ff:aa-ff:*:*:*",
		"ff:ff:aa-ff:*:*:*",         //normalizedString, //toColonDelimitedString
		"ff:ff:aa-ff:*:*:*",         //compressedString,
		"ff-ff-aa|ff-*-*-*",         //canonicalString, //toDashedString
		"ffff.aa00-ffff.*",          //dottedString,
		"ff ff aa-ff * * *",         //spaceDelimitedString,
		"ffffaa000000-ffffffffffff") //singleHex

	t.testMACStrings("ff:f:aa-ff:*:*:*",
		"ff:0f:aa-ff:*:*:*",         //normalizedString, //toColonDelimitedString
		"ff:f:aa-ff:*:*:*",          //compressedString,
		"ff-0f-aa|ff-*-*-*",         //canonicalString, //toDashedString
		"ff0f.aa00-ffff.*",          //dottedString,
		"ff 0f aa-ff * * *",         //spaceDelimitedString,
		"ff0faa000000-ff0fffffffff") //singleHex

	t.testMACStrings("ff:ff:ee:aa-ff:*:*",
		"ff:ff:ee:aa-ff:*:*",        //normalizedString, //toColonDelimitedString
		"ff:ff:ee:aa-ff:*:*",        //compressedString,
		"ff-ff-ee-aa|ff-*-*",        //canonicalString, //toDashedString
		"ffff.eeaa-eeff.*",          //dottedString,
		"ff ff ee aa-ff * *",        //spaceDelimitedString,
		"ffffeeaa0000-ffffeeffffff") //singleHex

	t.testMACStrings("*",
		"*:*:*:*:*:*",               //normalizedString, //toColonDelimitedString
		"*:*:*:*:*:*",               //compressedString,
		"*-*-*-*-*-*",               //canonicalString, //toDashedString
		"*.*.*",                     //dottedString,
		"* * * * * *",               //spaceDelimitedString,
		"000000000000-ffffffffffff") //singleHex

	t.testMACStrings("1-3:2:33:4:55-60:6",
		"01-03:02:33:04:55-60:06",
		"1-3:2:33:4:55-60:6",
		"01|03-02-33-04-55|60-06",
		"",
		"01-03 02 33 04 55-60 06",
		"")

	t.testMACStrings("f3:2:33:4:6:55-60",
		"f3:02:33:04:06:55-60",
		"f3:2:33:4:6:55-60",
		"f3-02-33-04-06-55|60",
		"f302.3304.0655-0660",
		"f3 02 33 04 06 55-60",
		"f30233040655-f30233040660")

	t.testMACStrings("*-b00cff",
		"*:*:*:b0:0c:ff",
		"*:*:*:b0:c:ff",
		"*-*-*-b0-0c-ff",
		"",
		"* * * b0 0c ff",
		"")

	t.testMACStrings("0aa0bb-*",
		"0a:a0:bb:*:*:*",
		"a:a0:bb:*:*:*",
		"0a-a0-bb-*-*-*",
		"0aa0.bb00-bbff.*",
		"0a a0 bb * * *",
		"0aa0bb000000-0aa0bbffffff")

	t.testMACStrings("0000aa|0000bb-000b00|000cff",
		"00:00:aa-bb:00:0b-0c:*",
		"0:0:aa-bb:0:b-c:*",
		"00-00-aa|bb-00-0b|0c-*",
		"",
		"00 00 aa-bb 00 0b-0c *",
		"")

	t.testMACStrings("c000aa|c000bb-c00b00|c00cff",
		"c0:00:aa-bb:c0:0b-0c:*",
		"c0:0:aa-bb:c0:b-c:*",
		"c0-00-aa|bb-c0-0b|0c-*",
		"",
		"c0 00 aa-bb c0 0b-0c *",
		"")

	t.testMACStrings("0000aa|0000bb-000b00",
		"00:00:aa-bb:00:0b:00",
		"0:0:aa-bb:0:b:0",
		"00-00-aa|bb-00-0b-00",
		"",
		"00 00 aa-bb 00 0b 00",
		"")

	t.testMACStrings("0000bb-000b00|000cff",
		"00:00:bb:00:0b-0c:*",
		"0:0:bb:0:b-c:*",
		"00-00-bb-00-0b|0c-*",
		"0000.bb00.0b00-0cff",
		//"",
		"00 00 bb 00 0b-0c *",
		"0000bb000b00-0000bb000cff")

	t.testMACStrings("0000aa|0000bb-*",
		"00:00:aa-bb:*:*:*",
		"0:0:aa-bb:*:*:*",
		"00-00-aa|bb-*-*-*",
		"0000.aa00-bbff.*",
		"00 00 aa-bb * * *",
		"0000aa000000-0000bbffffff")

	t.testMACStrings("*-000b00|000cff",
		"*:*:*:00:0b-0c:*",
		"*:*:*:0:b-c:*",
		"*-*-*-00-0b|0c-*",
		"",
		"* * * 00 0b-0c *",
		"")
}

func (t macAddressRangeTester) testTree(start string, parents []string) {
	usePrefixBlocks := false
	for k := 0; k < 2; k++ {
		if k == 1 {
			usePrefixBlocks = true
		}
		//try {
		str := t.createMACParamsAddress(start, wildcardAndRangeMACAddressOptions)
		addr := str.GetAddress()
		//now do the same thing but use the IPAddress objects instead
		var i, j int
		var pref ipaddr.PrefixLen
		brokeEarly := false
		for {
			label := getMACLabel(addr.ToAddressString())
			expected := parents[i]
			if label != expected {
				t.addFailure(newMACFailure("failed expected: "+expected+" actual: "+label, str))
				brokeEarly = true
				break
			}
			pref = addr.GetPrefixLen()
			addr = enlargeMACSubnet(addr)
			//addr = addr.adjustPrefixBySegment(false, false)
			//if(prefixConfiguration.allPrefixedAddressesAreSubnets()) {
			//	i++;
			//}
			if usePrefixBlocks {
				addr = addr.ToPrefixBlock()
				i++
			}
			j++
			if pref != nil && pref.Len() == 0 { //when network prefix is 0, Address.toSupernet() returns the same address
				break
			}
		}
		if !brokeEarly && j != len(parents) {
			t.addFailure(newMACFailure("failed: invalid label count "+strconv.Itoa(len(parents))+" expected "+strconv.Itoa(j), str))
		}
		//} catch(RuntimeException e) {
		//	addFailure(new Failure("failed: " + e + " " + start));
		//}
		t.incrementTestCount()
	}
}

func enlargeMACSubnet(addr *ipaddr.MACAddress /*boolean nextSegment  false , int bitsPerSegment, /* boolean skipBitCountPrefix false */) *ipaddr.MACAddress {
	prefix := addr.GetPrefixLen()
	if prefix == nil {
		return addr.SetPrefixLen(addr.GetBitCount() - addr.GetBitsPerSegment())
	}
	prefLen := prefix.Len()
	if prefLen == 0 {
		return addr
	}
	adjustment := ((prefLen - 1) % addr.GetBitsPerSegment()) + 1
	addr = addr.SetPrefixLen(prefLen - adjustment)
	//addr, _ = addr.SetPrefixLenZeroed(prefLen - adjustment) xxx
	//if addr.GetLower().IsZeroHost() {
	//	addr = addr.ToPrefixBlock()
	//}
	return addr
}

func getMACLabel(addressString *ipaddr.MACAddressString) string {
	address := addressString.GetAddress()
	if address == nil {
		return addressString.String()
	}
	return address.ToNormalizedString()
}

func (t macAddressRangeTester) testTrees() {
	t.testTree("1:2:0-8f:*", []string{
		"01:02:00-8f:*:*:*",
		"01:02:*:*:*:*",
		"01:*:*:*:*:*",
		"*:*:*:*:*:*",
	})
	t.testTree("a:b:c:d:e:f", []string{
		"0a:0b:0c:0d:0e:0f",
		"0a:0b:0c:0d:0e:*",
		"0a:0b:0c:0d:*:*",
		"0a:0b:0c:*:*:*",
		"0a:0b:*:*:*:*",
		"0a:*:*:*:*:*",
		"*:*:*:*:*:*",
	})
	t.testTree("a:b:c:d:e:f:a:b", []string{
		"0a:0b:0c:0d:0e:0f:0a:0b",
		"0a:0b:0c:0d:0e:0f:0a:*",
		"0a:0b:0c:0d:0e:0f:*:*",
		"0a:0b:0c:0d:0e:*:*:*",
		"0a:0b:0c:0d:*:*:*:*",
		"0a:0b:0c:*:*:*:*:*",
		"0a:0b:*:*:*:*:*:*",
		"0a:*:*:*:*:*:*:*",
		"*:*:*:*:*:*:*:*",
	})
	t.testTree("a:b:c:d:e:f:a0-bf:*", []string{ //this one is good now
		"0a:0b:0c:0d:0e:0f:a0-bf:*",
		"0a:0b:0c:0d:0e:0f:*:*",
		"0a:0b:0c:0d:0e:*:*:*",
		"0a:0b:0c:0d:*:*:*:*",
		"0a:0b:0c:*:*:*:*:*",
		"0a:0b:*:*:*:*:*:*",
		"0a:*:*:*:*:*:*:*",
		"*:*:*:*:*:*:*:*",
	})
	t.testTree("a:b:c:d:e:f:a2-a3:*", []string{ //this one is good now
		"0a:0b:0c:0d:0e:0f:a2-a3:*",
		"0a:0b:0c:0d:0e:0f:*:*",
		"0a:0b:0c:0d:0e:*:*:*",
		"0a:0b:0c:0d:*:*:*:*",
		"0a:0b:0c:*:*:*:*:*",
		"0a:0b:*:*:*:*:*:*",
		"0a:*:*:*:*:*:*:*",
		"*:*:*:*:*:*:*:*",
	})
	t.testTree("a:b:c:d:e:f:1f-80:*", []string{
		"0a:0b:0c:0d:0e:0f:1f-80:*",
		"0a:0b:0c:0d:0e:0f:*:*",
		"0a:0b:0c:0d:0e:*:*:*",
		"0a:0b:0c:0d:*:*:*:*",
		"0a:0b:0c:*:*:*:*:*",
		"0a:0b:*:*:*:*:*:*",
		"0a:*:*:*:*:*:*:*",
		"*:*:*:*:*:*:*:*",
	})
	t.testTree("a:b:c:11-12:*", []string{
		"0a:0b:0c:11-12:*:*",
		"0a:0b:0c:*:*:*",
		"0a:0b:*:*:*:*",
		"0a:*:*:*:*:*",
		"*:*:*:*:*:*",
	})
}
