package test

import (
	"fmt"
	"github.com/seancfoley/ipaddress/ipaddress-go/ipaddr"
	"math/big"
	"time"
)

//TODO NEXT you want to reorg the test files so they are in test package and not main
// that way you can just add new files as needed
// use a cmd dir for the main package

func Test() {
	var acc testAccumulator
	var addresses addresses
	tester := ipAddressTester{testBase{testResults: &acc, testAddresses: &addresses}}
	macTester := macAddressTester{testBase{testResults: &acc, testAddresses: &addresses}}
	fmt.Println("Starting TestRunner")
	startTime := time.Now()
	tester.run()
	macTester.run()
	rangedAddresses := rangedAddresses{addresses}
	rangeTester := ipAddressRangeTester{ipAddressTester{testBase{testResults: &acc, testAddresses: &rangedAddresses}}}
	macRangeTester := macAddressRangeTester{macAddressTester{testBase{testResults: &acc, testAddresses: &rangedAddresses}}}
	rangeTester.run()
	macRangeTester.run()
	endTime := time.Now().Sub(startTime)
	fmt.Printf("TestRunner\ntest count: %d\nfail count:%d\n", acc.counter, len(acc.failures))
	if len(acc.failures) > 0 {
		fmt.Printf("%v\n", acc.failures)
	}
	fmt.Printf("Done: TestRunner\nDone in %v\n", endTime)
}

type testResults interface {

	// test failures
	addFailure(failure)

	// store test counts
	incrementTestCount()
}

type testAccumulator struct {
	counter  int64
	failures []failure
}

func (t *testAccumulator) addFailure(f failure) {
	t.failures = append(t.failures, f)
}

func (t *testAccumulator) incrementTestCount() {
	t.counter++
}

type tester interface {
	run()
}

type testBase struct {
	testResults
	testAddresses
}

func (t testBase) testReverse(series ipaddr.ExtendedSegmentSeries, bitsReversedIsSame, bitsReversedPerByteIsSame bool) {
	segmentsReversed := series.ReverseSegments()
	divCount := series.GetDivisionCount()
	for i := 0; i < series.GetSegmentCount(); i++ {
		seg0 := series.GetSegment(i)
		seg1 := segmentsReversed.GetSegment(divCount - i - 1)
		if !seg0.Equals(seg1) {
			t.addFailure(newAddrSegmentSeriesFailure("reversal: "+series.String()+" "+segmentsReversed.String(), series))
			return
		}
	}
	bytesReversed, err := segmentsReversed.ReverseBytes()
	if err != nil {
		t.addFailure(newAddrSegmentSeriesFailure("failed "+err.Error(), series))
		return
	}
	bytesReversed, err = bytesReversed.ReverseBytes()
	if err != nil {
		t.addFailure(newAddrSegmentSeriesFailure("failed "+err.Error(), series))
		return
	}
	bytesReversed = bytesReversed.ReverseSegments()
	if !series.Equals(bytesReversed) {
		t.addFailure(newAddrSegmentSeriesFailure("bytes reversal: "+series.String(), series))
		return
	}
	bitsReversed, err := series.ReverseBits(false)
	if err != nil {
		t.addFailure(newAddrSegmentSeriesFailure("failed "+err.Error(), series))
		return
	}
	var equalityResult = series.Equals(bitsReversed)
	if bitsReversedIsSame {
		equalityResult = !equalityResult
	}
	if equalityResult {
		//if(bitsReversedIsSame ? !series.equals(bitsReversed) : series.equals(bitsReversed)) {
		t.addFailure(newAddrSegmentSeriesFailure("bit reversal 2a: "+series.String()+" "+bitsReversed.String(), series))
		return
	}
	bitsReversed, err = bitsReversed.ReverseBits(false)
	if err != nil {
		t.addFailure(newAddrSegmentSeriesFailure("failed "+err.Error(), series))
		return
	}
	if !series.Equals(bitsReversed) {
		t.addFailure(newAddrSegmentSeriesFailure("bit reversal 2: "+series.String(), series))
		return
	}

	bitsReversed2, err := series.ReverseBits(true)
	if err != nil {
		t.addFailure(newAddrSegmentSeriesFailure("failed "+err.Error(), series))
		return
	}
	equalityResult = series.Equals(bitsReversed2)
	if bitsReversedPerByteIsSame {
		equalityResult = !equalityResult
	}
	if equalityResult {
		//if(bitsReversedPerByteIsSame ? !series.equals(bitsReversed2) : series.equals(bitsReversed2)) {
		t.addFailure(newAddrSegmentSeriesFailure("bit reversal 3a: "+series.String(), series))
		return
	}
	bitsReversed2, err = bitsReversed2.ReverseBits(true)
	if err != nil {
		t.addFailure(newAddrSegmentSeriesFailure("failed "+err.Error(), series))
		return
	}
	if !series.Equals(bitsReversed2) {
		t.addFailure(newAddrSegmentSeriesFailure("bit reversal 3: "+series.String(), series))
		return
	}

	bytes := series.GetBytes() // ab cd ef becomes fe dc ba
	bitsReversed3, err := series.ReverseBytes()
	if err != nil {
		t.addFailure(newAddrSegmentSeriesFailure("failed "+err.Error(), series))
		return
	}
	//bitsReversed3 = bitsReversed3.ReverseBytesPerSegment();
	for i, j := 0, len(bytes)-1; i < bitsReversed3.GetSegmentCount(); i++ {
		seg := bitsReversed3.GetSegment(i)
		segBytes := seg.GetBytes()
		if !seg.IsMultiple() {
			bytesLen := len(segBytes) >> 1
			last := len(segBytes) - 1
			for m := 0; m < bytesLen; m++ {
				first, lastByte := segBytes[m], segBytes[last-m]
				segBytes[m], segBytes[last-m] = lastByte, first
			}
		}
		//for k := 0; k < seg.GetByteCount(); k++ {
		for k := seg.GetByteCount() - 1; k >= 0; k-- {
			if segBytes[k] != bytes[j] { //reversal 4: 1:1:1:1-fffe:2:3:3:3 300:300:300:200:1-fffe:100:100:100
				t.addFailure(newAddrSegmentSeriesFailure("reversal 4: "+series.String()+" "+bitsReversed3.String(), series))
				return
			}
			j--
		}
	}
}

type failure struct {
	str string

	addr       *ipaddr.IPAddress
	addrStr    *ipaddr.IPAddressString
	macAddr    *ipaddr.MACAddress
	macAddrStr *ipaddr.MACAddressString
	ipseries   ipaddr.ExtendedIPSegmentSeries
	series     ipaddr.ExtendedSegmentSeries
}

func (f *failure) String() string {
	return concat(
		concat(
			concat(
				concat(
					concat(
						concat(f.str, f.addr),
						f.addrStr),
					f.macAddr),
				f.macAddrStr),
			f.ipseries),
		f.series)
}

func concat(str string, stringer fmt.Stringer) string {
	if stringer != nil {
		if str != "" {
			return stringer.String() + ": " + str
		}
		return stringer.String()
	}
	return str
}

func newIPAddrFailure(str string, addr *ipaddr.IPAddress) failure {
	return failure{
		str:  str,
		addr: addr,
	}
}

func newMACAddrFailure(str string, addr *ipaddr.MACAddress) failure {
	return failure{
		str:     str,
		macAddr: addr,
	}
}

func newMACFailure(str string, addrStr *ipaddr.MACAddressString) failure {
	return failure{
		str:        str,
		macAddrStr: addrStr,
	}
}
func newFailure(str string, addrStr *ipaddr.IPAddressString) failure {
	return failure{
		str:     str,
		addrStr: addrStr,
	}
}

func newAddrSegmentSeriesFailure(str string, series ipaddr.ExtendedSegmentSeries) failure {
	return failure{
		str:    str,
		series: series,
	}
}

func newAddrSegmentIPSeriesFailure(str string, series ipaddr.ExtendedIPSegmentSeries) failure {
	return failure{
		str:      str,
		ipseries: series,
	}
}

var cachedPrefixLens = initPrefLens()

func initPrefLens() []ipaddr.PrefixLen {
	cachedPrefLens := make([]ipaddr.PrefixLen, ipaddr.IPv6BitCount+1)
	for i := ipaddr.BitCount(0); i <= ipaddr.IPv6BitCount; i++ {
		bc := i
		cachedPrefLens[i] = &bc
	}
	return cachedPrefLens
}

func cacheTestBits(i ipaddr.BitCount) ipaddr.PrefixLen {
	if i >= 0 && int(i) < len(cachedPrefixLens) {
		return cachedPrefixLens[i]

	}
	return &i
}

func bigOne() *big.Int {
	return big.NewInt(1)
}

var one = bigOne()

func bigOneConst() *big.Int {
	return one
}
