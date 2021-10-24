package test

import (
	"github.com/seancfoley/ipaddress/ipaddress-go/ipaddr"
)

type macAddressRangeTester struct {
	macAddressTester
}

func (t macAddressRangeTester) run() {
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
		if !equivPrefix.Equals(equiv) {
			t.addFailure(newMACAddrFailure("failed: prefix expected: "+equivPrefix.String()+" prefix got: "+equiv.String(), h1))
		} else {
			minPref := h1.GetMinPrefixLenForBlock()
			if minPref != minPrefix {
				t.addFailure(newMACAddrFailure("failed: prefix expected: "+minPrefix.String()+" prefix got: "+minPref.String(), h1))
			}
		}
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
