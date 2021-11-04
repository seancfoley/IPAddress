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

	t.hostTester.run()
}

func (t hostRangeTester) testMatches(matches bool, host1, host2 string) {
	t.testMatchesParams(matches, host1, host2, hostWildcardOptions)
}
