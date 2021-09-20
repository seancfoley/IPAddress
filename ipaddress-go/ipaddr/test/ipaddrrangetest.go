package test

type ipAddressRangeTester struct {
	ipAddressTester
}

func (t ipAddressRangeTester) run() {
	t.testEquivalentPrefix("*.*.*.*", 0)
	t.testEquivalentPrefix("0-127.*.*.*", 1)
	t.testEquivalentPrefix("128-255.*.*.*", 1)
	t.testEquivalentPrefix("*.*.*.*/1", 0)
	t.testEquivalentPrefix("0.*.*.*/1", 1)
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
}
