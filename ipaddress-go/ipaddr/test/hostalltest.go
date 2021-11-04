package test

type hostAllTester struct {
	hostRangeTester
}

func (t hostAllTester) run() {
	t.hostRangeTester.run()
}

//TODO this overrides, so do what you did with the overriding methods in address types
// At the moment it appears I do not need it
//func (t hostAllTester) testMatches(matches bool, host1, host2 string) {
//	t.testMatchesParams(matches, host1, host2, HOST_ALL_OPTIONS)
//}
