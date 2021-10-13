package test

type macAddressTester struct {
	testBase
}

func (t macAddressTester) run() {

	t.testReverse("1:2:3:4:5:6", false, false)
	t.testReverse("1:1:2:2:3:3", false, false)
	t.testReverse("1:1:1:1:1:1", false, false)
	t.testReverse("0:0:0:0:0:0", true, true)

	t.testReverse("ff:ff:ff:ff:ff:ff", true, true)
	t.testReverse("ff:ff:ff:ff:ff:ff:ff:ff", true, true)

	t.testReverse("ff:80:ff:ff:01:ff", true, false)
	t.testReverse("ff:81:ff:ff:ff:ff", false, true)
	t.testReverse("ff:81:c3:42:24:ff", false, true)
	t.testReverse("ff:1:ff:ff:ff:ff", false, false)

	t.testReverse("11:22:33:44:55:66", false, false)
	t.testReverse("11:11:22:22:33:33", false, false)
	t.testReverse("11:11:22:22:33:33:44:55", false, false)
	t.testReverse("11:11:11:11:11:11:11:11", false, false)
	t.testReverse("0:0:0:0:0:0:00:00", true, true)

	//TODO
	//t.testPrefixes("25:51:27:12:82:55",
	//	16, -5,
	//	"25:51:27:12:82:55",
	//	"25:51:27:12:82:0",
	//	"25:51:27:12:82:40",
	//	"25:51:0:0:0:0",
	//	"25:51:0:0:0:0")

}

func (t macAddressTester) testReverse(addressStr string, bitsReversedIsSame, bitsReversedPerByteIsSame bool) {
	str := t.createMACAddress(addressStr)
	//try {
	t.testBase.testReverse(str.GetAddress().ToAddress().Wrap(), bitsReversedIsSame, bitsReversedPerByteIsSame)
	//} catch(RuntimeException e) {
	//addFailure(new Failure("reversal: " + addressStr));
	//}
	t.incrementTestCount()
}

//TODO
//func (t macAddressTester) testPrefixes(original string,
//	prefix, adjustment ipaddr.BitCount,
//	next string,
//	previous,
//	adjusted,
//	prefixSet,
//	prefixApplied string) {
//	t.testBase.testPrefixes(t.createMACAddress(original).GetAddress().Wrap(),
//		prefix, adjustment,
//		t.createMACAddress(next).GetAddress().Wrap(),
//		t.createMACAddress(previous).GetAddress().Wrap(),
//		t.createMACAddress(adjusted).GetAddress().Wrap(),
//		t.createMACAddress(prefixSet).GetAddress().Wrap(),
//		t.createMACAddress(prefixApplied).GetAddress().Wrap())
//	t.incrementTestCount()
//}
