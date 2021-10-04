package test

import (
	"fmt"
	"github.com/seancfoley/ipaddress/ipaddress-go/ipaddr"
	"math/big"
	"reflect"
	"strconv"
	"time"
)

//TODO NEXT you want to reorg the test files so they are in test package and not main
// that way you can just add new files as needed
// use a cmd dir for the main package

func Test() {
	var acc testAccumulator
	var addresses addresses
	fmt.Println("Starting TestRunner")
	startTime := time.Now()

	tester := ipAddressTester{testBase{testResults: &acc, testAddresses: &addresses}}
	macTester := macAddressTester{testBase{testResults: &acc, testAddresses: &addresses}}
	tester.run()
	macTester.run()

	rangedAddresses := rangedAddresses{addresses}
	rangeTester := ipAddressRangeTester{ipAddressTester{testBase{testResults: &acc, testAddresses: &rangedAddresses}}}
	macRangeTester := macAddressRangeTester{macAddressTester{testBase{testResults: &acc, testAddresses: &rangedAddresses}}}
	rangeTester.run()
	macRangeTester.run()

	allAddresses := allAddresses{rangedAddresses}
	allTester := ipAddressAllTester{ipAddressRangeTester{ipAddressTester{testBase{testResults: &acc, testAddresses: &allAddresses}}}}
	allTester.run()

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
			t.addFailure(newSegmentSeriesFailure("reversal: "+series.String()+" "+segmentsReversed.String(), series))
			return
		}
	}
	bytesReversed, err := segmentsReversed.ReverseBytes()
	if err != nil {
		t.addFailure(newSegmentSeriesFailure("failed "+err.Error(), series))
		return
	}
	bytesReversed, err = bytesReversed.ReverseBytes()
	if err != nil {
		t.addFailure(newSegmentSeriesFailure("failed "+err.Error(), series))
		return
	}
	bytesReversed = bytesReversed.ReverseSegments()
	if !series.Equals(bytesReversed) {
		t.addFailure(newSegmentSeriesFailure("bytes reversal: "+series.String(), series))
		return
	}
	bitsReversed, err := series.ReverseBits(false)
	if err != nil {
		t.addFailure(newSegmentSeriesFailure("failed "+err.Error(), series))
		return
	}
	var equalityResult = series.Equals(bitsReversed)
	if bitsReversedIsSame {
		equalityResult = !equalityResult
	}
	if equalityResult {
		//if(bitsReversedIsSame ? !series.equals(bitsReversed) : series.equals(bitsReversed)) {
		t.addFailure(newSegmentSeriesFailure("bit reversal 2a: "+series.String()+" "+bitsReversed.String(), series))
		return
	}
	bitsReversed, err = bitsReversed.ReverseBits(false)
	if err != nil {
		t.addFailure(newSegmentSeriesFailure("failed "+err.Error(), series))
		return
	}
	if !series.Equals(bitsReversed) {
		t.addFailure(newSegmentSeriesFailure("bit reversal 2: "+series.String(), series))
		return
	}

	bitsReversed2, err := series.ReverseBits(true)
	if err != nil {
		t.addFailure(newSegmentSeriesFailure("failed "+err.Error(), series))
		return
	}
	equalityResult = series.Equals(bitsReversed2)
	if bitsReversedPerByteIsSame {
		equalityResult = !equalityResult
	}
	if equalityResult {
		//if(bitsReversedPerByteIsSame ? !series.equals(bitsReversed2) : series.equals(bitsReversed2)) {
		t.addFailure(newSegmentSeriesFailure("bit reversal 3a: "+series.String(), series))
		return
	}
	bitsReversed2, err = bitsReversed2.ReverseBits(true)
	if err != nil {
		t.addFailure(newSegmentSeriesFailure("failed "+err.Error(), series))
		return
	}
	if !series.Equals(bitsReversed2) {
		t.addFailure(newSegmentSeriesFailure("bit reversal 3: "+series.String(), series))
		return
	}

	bytes := series.GetBytes() // ab cd ef becomes fe dc ba
	bitsReversed3, err := series.ReverseBytes()
	if err != nil {
		t.addFailure(newSegmentSeriesFailure("failed "+err.Error(), series))
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
				t.addFailure(newSegmentSeriesFailure("reversal 4: "+series.String()+" "+bitsReversed3.String(), series))
				return
			}
			j--
		}
	}
}

func (t testBase) testPrefixes(original ipaddr.ExtendedIPSegmentSeries,
	prefix, adjustment ipaddr.BitCount,
	_,
	_,
	adjusted,
	prefixSet,
	_ ipaddr.ExtendedIPSegmentSeries) {
	for j := 0; j < 2; j++ {
		var removed ipaddr.ExtendedIPSegmentSeries
		var err error
		if j == 0 {
			removed, err = original.AdjustPrefixLenZeroed(original.GetBitCount() + 1)
			//fmt.Println("beyond " + removed.String())
			//if removed.IsPrefixed() {
			//	original.AdjustPrefixLenZeroed(original.GetBitCount() + 1)
			//}
			//	removed = original.WithoutPrefixLen() //TODO might have to call AdjustPrefixLenZeroed here too
		} else {
			removed, err = original.AdjustPrefixLenZeroed(original.GetBitCount())
			//removed = original.AdjustPrefixLen(original.GetBitCount()) //TODO might have to call AdjustPrefixLenZeroed
			//fmt.Println("not beyond " + removed.String())
		}
		if err != nil {
			t.addFailure(newIPSegmentSeriesFailure("removed prefix error: "+err.Error(), original))
			break
		}
		if j == 1 && original.GetPrefixLen() != nil && *original.GetPrefixLen() == 0 {
			removed = original.AdjustPrefixLen(original.GetBitCount() + 1)
		}
		if original.IsPrefixed() {
			prefLength := *original.GetPrefixLen()
			bitsSoFar := ipaddr.BitCount(0)
			for i := 0; i < removed.GetSegmentCount(); i++ {
				prevBitsSoFar := bitsSoFar
				seg := removed.GetSegment(i)
				bitsSoFar += seg.GetBitCount()
				if prefLength >= bitsSoFar {
					if !seg.Equals(original.GetSegment(i)) {
						t.addFailure(newIPSegmentSeriesFailure("removed prefix: "+removed.String(), original))
						break
					}
				} else if prefLength <= prevBitsSoFar {
					if !seg.IsZero() {
						t.addFailure(newIPSegmentSeriesFailure("removed prefix all: "+removed.String(), original))
						break
					}
				} else {
					segPrefix := prefLength - prevBitsSoFar
					mask := ^ipaddr.SegInt(0) << uint(seg.GetBitCount()-segPrefix)
					lower := seg.GetSegmentValue()
					upper := seg.GetUpperSegmentValue()
					if (lower&mask) != lower || (upper&mask) != upper {
						//removed = original.removePrefixLength();
						t.addFailure(newIPSegmentSeriesFailure("prefix app: "+removed.String()+" "+strconv.Itoa(int(lower&mask))+" "+strconv.Itoa(int(upper&mask)), original))
						break
					}
				}
			}
			//if removed.IsPrefixed() {
			//	t.addFailure(newSegmentSeriesFailure("prefix not removed: "+removed.String(), original))
			//}
		} else if !removed.Equals(original) {
			t.addFailure(newIPSegmentSeriesFailure("prefix removed: "+removed.String(), original))
		} //else if removed.IsPrefixed() {
		//	t.addFailure(newSegmentSeriesFailure("prefix not removed from non-prefixed: "+removed.String(), original))
		//}
	}
	var adjustedSeries ipaddr.ExtendedIPSegmentSeries
	//AddressSegmentSeries adjustedSeries = original.adjustPrefixBySegment(true);
	//Integer nextPrefix = adjustedSeries.getPrefixLength();
	//if(!adjustedSeries.equals(next)) {
	//	addFailure(new Failure("prefix next: " + adjustedSeries, next));
	//} else {
	//adjustedSeries = original.adjustPrefixBySegment(false);
	//Integer prevPrefix = adjustedSeries.getPrefixLength();
	//if(!adjustedSeries.equals(previous)) {
	//	addFailure(new Failure("prefix previous: " + adjustedSeries, previous));
	//} else {
	adjustedSeries, err := original.AdjustPrefixLenZeroed(adjustment)
	if err != nil {
		t.addFailure(newIPSegmentSeriesFailure("adjusted prefix error: "+err.Error(), original))
		return
	}
	adjustedPrefix := adjustedSeries.GetPrefixLen()

	//ok, either I implement all this zero max host shit on mac, or I just have two different test methods
	//going halfway is senseless
	//
	//ok let us go back and remove the toZeroHost and isZeroHost and just use separate methods
	//
	//thankfully I have not committed the shit i did so far

	//if original.IsPrefixBlock() && adjustment < 0 {
	//if original.IsPrefixed() && *adjustedPrefix >= original.GetBitCount()+adjustment {
	if (original.IsPrefixed() && adjustedPrefix.Matches(original.GetBitCount()+adjustment)) ||
		(!original.IsPrefixBlock() && adjustedSeries.IsZeroHost()) { //xxxxx if we do not have prefix block, then our positive adjustment creates what would be one, then our expected is one which is wrong
		//xxx if adjustment is negative and original is pref block xxx
		// TODO case 3 - original is prefix block, adjustment is negative, so we are not prefix block but expected is
		// either we are converted to prefix block or what? that is the only option
		// OR consider that we do have the correct expected but it is converted to prefix block: 255.96.*.*/11
		// maybe we need to change the fact that address is converted to prefix block
		// I think we do.

		// all host bits of matching address are zeroed out, so we must get the zero host and not the prefix subnet
		adjusted, err = adjusted.ToZeroHost() //TODO xxxx when original not prefixed, we do not zero, we just set xxxx
		if err != nil {
			t.addFailure(newIPSegmentSeriesFailure("adjusted prefix error: "+err.Error(), original))
			return
		}
	}

	if !adjustedSeries.Equals(adjusted) {
		//TWO things wrong: 1. the new series is not a prefix subnet (which is actually correct, I think, since I wanted to stop doing that).  But how am I supposed to specify the result?  I guess with the toZeroHost
		// 2. the canonical string things otherwise!  how is that possible?  wrong, it is correct
		fmt.Println("original " + original.String() + " adjusted series: " + adjustedSeries.String() + " expected: " + adjusted.String() + " increment: " + adjustment.String())
		fmt.Println("original " + original.String() + " adjusted series: " + adjustedSeries.ToNormalizedWildcardString() + " expected: " + adjusted.ToNormalizedWildcardString() + " increment: " + adjustment.String())
		t.addFailure(newIPSegmentSeriesFailure("prefix adjusted: "+adjustedSeries.String(), adjusted))
		original.AdjustPrefixLenZeroed(adjustment)
		//a, berr := original.AdjustPrefixLenZeroed(adjustment)
		//_ = berr
		//a.String()
	} else {
		adjustedSeries, err = original.SetPrefixLenZeroed(prefix)
		//adjustedSeries = original.SetPrefixLen(prefix)
		if err != nil {
			t.addFailure(newIPSegmentSeriesFailure("set prefix error: "+err.Error(), original))
			return
		}
		//if original.IsPrefixBlock() && original.GetPrefixLen().Exceeds(prefix) {
		if (original.IsPrefixed() && original.GetPrefixLen().Matches(original.GetBitCount())) ||
			(!original.IsPrefixBlock() && adjustedSeries.IsZeroHost()) {
			//xxx if diff between prefix set and original is negative and original is pref block xxx

			//if original.IsPrefixed() && *original.GetPrefixLen() == original.GetBitCount() && original.GetPrefixLen().Is(original.GetBitCount()) { //TODO we need a method on prefix len to compare with a bit count
			// all host bits of matching address are zeroed out, so we must get the zero host and not the prefix subnet
			prefixSet, err = prefixSet.ToZeroHost() //TODO xxxx when original not prefixed, we do not zero, we just set xxxx
			if err != nil {
				t.addFailure(newIPSegmentSeriesFailure("set prefix error: "+err.Error(), original))
				return
			}
		}

		setPrefix := adjustedSeries.GetPrefixLen()
		if !adjustedSeries.Equals(prefixSet) {
			fmt.Println(original.String() + " set: " + adjustedSeries.String() + " expected: " + prefixSet.String() + " set prefix: " + prefix.String())
			t.addFailure(newIPSegmentSeriesFailure("prefix set: "+adjustedSeries.String(), prefixSet))
		} else {
			//adjustedSeries = original.ApplyPrefixLen(prefix);
			//appliedPrefix := adjustedSeries.GetPrefixLen();
			//if(!adjustedSeries.Equals(prefixApplied)) {
			//t.addFailure(newFailure("prefix applied: " + adjustedSeries, prefixApplied));
			//} else {

			originalPref := original.GetPrefixLen()
			var expected ExpectedPrefixes
			bitLength := original.GetBitCount()
			//segmentBitLength := original.GetBitsPerSegment()
			if originalPref == nil {
				//_, ok := original.Unwrap().(*ipaddr.MACAddress)
				//if ok {
				//	expected.previous = cacheTestBits(bitLength - segmentBitLength)
				//} else {
				//	expected.previous = cacheTestBits(bitLength)
				//}
				if adjustment <= 0 {
					expected.adjusted = cacheTestBits(bitLength + adjustment)
				} else {
					expected.adjusted = cacheTestBits(adjustment)
				}
				expected.set = cacheTestBits(prefix)
			} else {
				//if *originalPref != bitLength {
				//	expected.next = cacheTestBits(min(bitLength, ((*originalPref + segmentBitLength) / segmentBitLength) * segmentBitLength))
				//}
				//expected.previous = cacheTestBits(max(0, ((*originalPref - 1) / segmentBitLength) * segmentBitLength));
				adj := min(max(0, *originalPref+adjustment), original.GetBitCount())
				//if adj <= bitLength {
				expected.adjusted = cacheTestBits(adj)
				//}
				//this.set = set;
				expected.set = cacheTestBits(prefix)
			}

			//ExpectedPrefixes expected = new ExpectedPrefixes(original instanceof MACAddress, original.getPrefixLength(), original.getBitCount(), original.getBitsPerSegment(), prefix, adjustment);
			if !expected.compare(adjustedPrefix, setPrefix) {
				//if(!expected.compare(nextPrefix, prevPrefix, adjustedPrefix, setPrefix, appliedPrefix)) {
				t.addFailure(newIPSegmentSeriesFailure("expected: "+expected.adjusted.String()+" actual "+adjustedPrefix.String()+" expected: "+expected.set.String()+" actual "+setPrefix.String(), original))
				//t.addFailure(newSegmentSeriesFailure(expected.print(nextPrefix, prevPrefix, adjustedPrefix, setPrefix, appliedPrefix)))
			}
			//}
		}
	}
	//}
	//	}
}

func min(a, b ipaddr.BitCount) ipaddr.BitCount {
	if a < b {
		return a
	}
	return b
}
func max(a, b ipaddr.BitCount) ipaddr.BitCount {
	if a > b {
		return a
	}
	return b
}

type ExpectedPrefixes struct {
	//next, previous, adjusted, set ipaddr.PrefixLen
	adjusted, set ipaddr.PrefixLen
}

func (exp ExpectedPrefixes) compare(adjusted, set ipaddr.PrefixLen) bool {
	return adjusted.Equals(exp.adjusted) && set.Equals(exp.set)
}

/*
	static class ExpectedPrefixes {
			Integer next;
			Integer previous;
			Integer adjusted;
			Integer set;
			Integer applied;

			ExpectedPrefixes(boolean isMac, Integer original, int bitLength, int segmentBitLength, int set, int adjustment) {
				if(original == null) {
					next = null;
					previous = isMac ? bitLength - segmentBitLength : bitLength;//bitLength is not a possible prefix with MAC (a prefix of bitlength is interpreted as null prefix length)
					adjusted = adjustment > 0 ? null : bitLength + adjustment;
					applied = this.set = set;
				} else {
					next = original == bitLength ? null : Math.min(bitLength, ((original + segmentBitLength) / segmentBitLength) * segmentBitLength);
					previous = Math.max(0, ((original - 1) / segmentBitLength) * segmentBitLength);
					int adj = Math.max(0, original + adjustment);
					adjusted = adj > bitLength ? null : adj;
					this.set = set;
					applied = Math.min(original, set);
				}
			}

			boolean compare(Integer next, Integer previous, Integer adjusted, Integer set, Integer applied) {
				return Objects.equals(next, this.next) &&
						Objects.equals(previous, this.previous) &&
						Objects.equals(adjusted, this.adjusted) &&
						Objects.equals(set, this.set) &&
						Objects.equals(applied, this.applied);
			}

			String print(Integer next, Integer previous, Integer adjusted, Integer set, Integer applied) {
				return print(next, this.next, "next") + "\n" +
						print(previous, this.previous, "previous") + "\n" +
						print(adjusted, this.adjusted, "adjusted") + "\n" +
						print(set, this.set, "set") + "\n" +
						print(applied, this.applied, "applied");
			}

			String print(Integer result, Integer expected, String label) {
				return "expected " + label + ": " + expected + " result: " + result;
			}
		}
*/

type failure struct {
	str string

	addr       *ipaddr.IPAddress
	addrStr    *ipaddr.IPAddressString
	macAddr    *ipaddr.MACAddress
	macAddrStr *ipaddr.MACAddressString
	ipseries   ipaddr.ExtendedIPSegmentSeries
	series     ipaddr.ExtendedSegmentSeries
}

func (f failure) String() string {
	//if f == nil {
	//	panic(nil)
	//}
	return f.str
	//return concat( TODO fix this up could not get it to print the strings as I wanted due to interface arg, see below, easy to fix though
	//	concat(
	//		concat(
	//			concat(
	//				concat(
	//					concat(f.str, f.addr),
	//					f.addrStr),
	//				f.macAddr),
	//			f.macAddrStr),
	//		f.ipseries),
	//	f.series)
}

/*
https://groups.google.com/g/golang-nuts/c/wnH302gBa4I
https://stackoverflow.com/questions/13476349/check-for-nil-and-nil-interface-in-go
func isNil(a interface{}) bool {
  defer func() { recover() }()
  return a == nil || reflect.ValueOf(a).IsNil()
}
func isNilFixed(i interface{}) bool {
   if i == nil {
      return true
   }
   switch reflect.TypeOf(i).Kind() {
   case reflect.Ptr, reflect.Map, reflect.Array, reflect.Chan, reflect.Slice:
      return reflect.ValueOf(i).IsNil()
   }
   return false
}
*/
func concat(str string, stringer fmt.Stringer) string {
	val := reflect.ValueOf(stringer)
	if !val.IsValid() {
		return str
	}
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

func newSegmentSeriesFailure(str string, series ipaddr.ExtendedSegmentSeries) failure {
	return failure{
		str:    str,
		series: series,
	}
}

func newIPSegmentSeriesFailure(str string, series ipaddr.ExtendedIPSegmentSeries) failure {
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
