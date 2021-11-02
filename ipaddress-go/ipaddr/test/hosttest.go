package test

import "strconv"

var runDNS = false

type hostTester struct {
	testBase
}

//TODO need to start like I did with ipaddress, just go through, and while you go, populate hostrange and hostall whenever they have the same tests

func (t hostTester) run() {
	t.testSelf("1.2.3.4", false)
	t.testSelf("1::", false)
	t.testSelf("[1::]", false)
	t.testSelf("bla.com", false)
	t.testSelf("::1", true)
	t.testSelf("[::1]", true)
	t.testSelf("localhost", true)
	t.testSelf("127.0.0.1", true)

	t.testSelf("[127.0.0.1]", true)
	t.testSelf("[localhost]", false) //square brackets are for ipv6
	t.testSelf("-ab-.com", false)
}

func (t hostTester) testSelf(host string, isSelf bool) {
	w := t.createHost(host)
	if isSelf != w.IsSelf() {
		t.addFailure(newHostFailure("failed: isSelf is "+strconv.FormatBool(isSelf), w))
	}
	t.incrementTestCount()
}
