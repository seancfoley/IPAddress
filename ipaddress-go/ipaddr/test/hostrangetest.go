package test

type hostRangeTester struct {
	hostTester
}

func (t hostRangeTester) run() {
	t.testMatches(true, "1.*.*.*/255.0.0.0", "1.0.0.0/255.0.0.0")
	t.testMatches(true, "1.0.0.0/8", "1.0.0.0/255.0.0.0")

	t.testMatches(true, "1.2.3.4/255.0.0.0", "1.2.3.4")
	t.testMatches(true, "1.2.3.4/255.0.0.0", "1.2.3.4")
	t.testMatches(true, "1.2.3.4/255.0.0.0", "1.2.3.4")

	t.testMatches(true, "1.0.0.0/255.0.0.0", "1.*.*.*")
	t.testMatches(true, "1.0.0.0/255.0.0.0", "1.*.___.*")
	t.testMatches(false, "1.0.0.0/255.0.0.0", "1.0-255.*.*") //failing due to the options
	t.testMatchesParams(true, "1.0.0.0/255.0.0.0", "1.0-255.*.*", hostWildcardAndRangeOptions)

	t.testMatchesParams(true, "1-2.0-0.00-00.00-0", "1-2.0.0.0", hostWildcardAndRangeOptions)
	t.testMatchesParams(true, "1-2:0-0:00-00:00-0:0-000:0000-0000:0000-00:0000-0", "1-2:0:0:0:0:0:0:0", hostWildcardAndRangeOptions)
	t.testMatchesParams(true, "00-0.0-0.00-00.00-0", "0.0.0.0", hostWildcardAndRangeOptions)
	t.testMatchesParams(true, "0-00:0-0:00-00:00-0:0-000:0000-0000:0000-00:0000-0", "::", hostWildcardAndRangeOptions)

	t.testResolved("a::b:*:d:1.2.*%x", "a::b:*:d:1.2.*%x")
	t.testResolved("[a::b:*:d:1.2.*%x]", "a::b:*:d:1.2.*%x")
	t.testResolved("[a::*:c:d:1.*.3.4]", "a::*:c:d:1.*.3.4")
	t.testResolved("2001:0000:1234:0000:*:C1C0:ABCD:0876%x", "2001:0:1234:0:*:c1c0:abcd:876%x")
	t.testResolved("[2001:*:1234:0000:0000:C1C0:ABCD:0876%x]", "2001:*:1234::C1C0:abcd:876%x")
	t.testResolved("[2001:0000:*:0000:0000:C1C0:ABCD:0876]", "2001:0:*::C1C0:abcd:876")
	t.testResolved("2001:0000:*:0000:0000:C1C0:ABCD:0876", "2001:0:*::C1C0:abcd:876")
	t.testResolved("1.2.*.04", "1.2.*.4")
	t.testResolved_inet_aton("1.*.0-255.3", "1.*.*.3")
	t.testResolved_inet_aton("1.*.3", "1.*.0.3")
	t.testResolved("[1.2.*.4]", "1.2.*.4")

	t.testResolved("espn.*.com", "") //no wildcards for hosts, just addresses
	t.testResolved("*.instapundit.com", "")
	t.testResolved("es*n.com", "")
	t.testResolved("inst*undit.com", "")

	if t.fullTest && runDNS {
		t.testResolved("espn.com/24", "199.181.132.*")
	}

	t.testResolved("3*", "")
	t.testResolved("*", "*")
	t.testResolved("3.*", "3.*.*.*")
	t.testResolved("3:*", "3:*:*:*:*:*:*:*")
	t.testResolved("9.*.237.26", "9.*.237.26")
	t.testResolved("*.70.146.*", "*.70.146.*")

	t.hostLabelsTest("*", []string{"*"})
	t.hostLabelsTest("**", []string{"*"})

	t.hostTest(true, "1.2.3.4/1.2.3.4")
	t.hostTest(false, "1.2.3.4/*")
	t.hostTest(false, "1.*.3.4/*")
	t.hostTest(true, "1.*.3.4")
	t.hostTest(true, "1:*:3:4")

	t.hostTester.run()
}

func (t hostRangeTester) testMatches(matches bool, host1, host2 string) {
	t.testMatchesParams(matches, host1, host2, hostWildcardOptions)
}
