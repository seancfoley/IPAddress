package test

import (
	"fmt"
	"github.com/seancfoley/ipaddress/ipaddress-go/ipaddr"
	"math"
	"math/big"
	"reflect"
	"strconv"
	"strings"
	"time"
)

//TODO NEXT you want to reorg the test files so they are in test package and not main
// that way you can just add new files as needed
// use a cmd dir for the main package

func Test() {
	var acc testAccumulator
	var addresses addresses
	fullTest := true
	fmt.Println("Starting TestRunner")
	startTime := time.Now()

	tester := ipAddressTester{testBase{testResults: &acc, testAddresses: &addresses, fullTest: fullTest}}
	tester.run()

	macTester := macAddressTester{testBase{testResults: &acc, testAddresses: &addresses}}
	macTester.run()

	rangedAddresses := rangedAddresses{addresses}
	rangeTester := ipAddressRangeTester{ipAddressTester{testBase{testResults: &acc, testAddresses: &rangedAddresses, fullTest: fullTest}}}
	rangeTester.run()

	macRangeTester := macAddressRangeTester{macAddressTester{testBase{testResults: &acc, testAddresses: &rangedAddresses}}}
	macRangeTester.run()

	allAddresses := allAddresses{rangedAddresses}
	allTester := ipAddressAllTester{ipAddressRangeTester{ipAddressTester{testBase{testResults: &acc, testAddresses: &allAddresses, fullTest: fullTest}}}}
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
	fullTest bool
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

func (t testBase) testSegmentSeriesPrefixes(original ipaddr.ExtendedSegmentSeries,
	prefix, adjustment ipaddr.BitCount,
	_, _,
	adjusted,
	prefixSet,
	_ ipaddr.ExtendedSegmentSeries) {
	for j := 0; j < 2; j++ {
		var removed ipaddr.ExtendedSegmentSeries
		var err error
		if j == 0 {
			removed, err = original.AdjustPrefixLenZeroed(original.GetBitCount() + 1)
			//fmt.Println("beyond " + removed.String())
			//if removed.IsPrefixed() {
			//	original.AdjustPrefixLenZeroed(original.GetBitCount() + 1)
			//}
			//	removed = original.WithoutPrefixLen()
		} else {
			removed, err = original.AdjustPrefixLenZeroed(original.GetBitCount())
			//removed = original.AdjustPrefixLen(original.GetBitCount())
			//fmt.Println("not beyond " + removed.String())
		}
		if err != nil {
			t.addFailure(newSegmentSeriesFailure("removed prefix error: "+err.Error(), original))
			break
		}
		//if j == 1 && original.GetPrefixLen() != nil && *original.GetPrefixLen() == 0 { why was this here?  beats me
		//	removed = original.AdjustPrefixLen(original.GetBitCount() + 1)
		//}
		if original.IsPrefixed() {
			prefLength := *original.GetPrefixLen()
			bitsSoFar := ipaddr.BitCount(0)
			for i := 0; i < removed.GetSegmentCount(); i++ {
				prevBitsSoFar := bitsSoFar
				seg := removed.GetSegment(i)
				bitsSoFar += seg.GetBitCount()
				if prefLength >= bitsSoFar {
					if !seg.Equals(original.GetSegment(i)) {
						t.addFailure(newSegmentSeriesFailure("removed prefix: "+removed.String(), original))
						break
					}
				} else if prefLength <= prevBitsSoFar {
					if !seg.IsZero() {
						t.addFailure(newSegmentSeriesFailure("removed prefix all: "+removed.String(), original))
						break
					}
				} else {
					segPrefix := prefLength - prevBitsSoFar
					mask := ^ipaddr.SegInt(0) << uint(seg.GetBitCount()-segPrefix)
					lower := seg.GetSegmentValue()
					upper := seg.GetUpperSegmentValue()
					if (lower&mask) != lower || (upper&mask) != upper {
						//removed = original.removePrefixLength();
						t.addFailure(newSegmentSeriesFailure("prefix app: "+removed.String()+" "+strconv.Itoa(int(lower&mask))+" "+strconv.Itoa(int(upper&mask)), original))
						break
					}
				}
			}
			//if removed.IsPrefixed() {
			//	t.addFailure(newSegmentSeriesFailure("prefix not removed: "+removed.String(), original))
			//}
		} else if !removed.Equals(original) {
			t.addFailure(newSegmentSeriesFailure("prefix removed: "+removed.String(), original))
		} //else if removed.IsPrefixed() {
		//	t.addFailure(newSegmentSeriesFailure("prefix not removed from non-prefixed: "+removed.String(), original))
		//}
	}
	//var adjustedSeries ipaddr.ExtendedSegmentSeries
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
	//adjustedSeries, err := original.AdjustPrefixLenZeroed(adjustment)
	//if err != nil {
	//	t.addFailure(newSegmentSeriesFailure("adjusted prefix error: "+err.Error(), original))
	//	return
	//}
	//adjustedPrefix := adjustedSeries.GetPrefixLen()

	//ok, either I implement all this zero max host shit on mac, or I just have two different test methods
	//going halfway is senseless
	//
	//ok let us go back and remove the toZeroHost and isZeroHost and just use separate methods
	//
	//thankfully I have not committed the shit i did so far

	////if original.IsPrefixBlock() && adjustment < 0 {
	////if original.IsPrefixed() && *adjustedPrefix >= original.GetBitCount()+adjustment {
	//if (original.IsPrefixed() && adjustedPrefix.Matches(original.GetBitCount()+adjustment)) ||
	//	(!original.IsPrefixBlock() && adjustedSeries.IsZeroHost()) { //xxxxx if we do not have prefix block, then our positive adjustment creates what would be one, then our expected is one which is wrong
	//	//xxx if adjustment is negative and original is pref block xxx
	//	//  case 3 - original is prefix block, adjustment is negative, so we are not prefix block but expected is
	//	// either we are converted to prefix block or what? that is the only option
	//	// OR consider that we do have the correct expected but it is converted to prefix block: 255.96.*.*/11
	//	// maybe we need to change the fact that address is converted to prefix block
	//	// I think we do.
	//
	//	// all host bits of matching address are zeroed out, so we must get the zero host and not the prefix subnet
	//	adjusted, err = adjusted.ToZeroHost()
	//	if err != nil {
	//		t.addFailure(newSegmentSeriesFailure("adjusted prefix error: "+err.Error(), original))
	//		return
	//	}
	//}

	//if !adjustedSeries.Equals(adjusted) {
	//	//TWO things wrong: 1. the new series is not a prefix subnet (which is actually correct, I think, since I wanted to stop doing that).  But how am I supposed to specify the result?  I guess with the toZeroHost
	//	// 2. the canonical string things otherwise!  how is that possible?  wrong, it is correct
	//	//fmt.Println("original " + original.String() + " adjusted series: " + adjustedSeries.String() + " expected: " + adjusted.String() + " increment: " + adjustment.String())
	//	//fmt.Println("original " + original.String() + " adjusted series: " + adjustedSeries.ToNormalizedWildcardString() + " expected: " + adjusted.ToNormalizedWildcardString() + " increment: " + adjustment.String())
	//	t.addFailure(newSegmentSeriesFailure("prefix adjusted: "+adjustedSeries.String(), adjusted))
	//	original.AdjustPrefixLenZeroed(adjustment)
	//	//a, berr := original.AdjustPrefixLenZeroed(adjustment)
	//	//_ = berr
	//	//a.String()
	//} else {
	//adjustedSeries, err := original.SetPrefixLenZeroed(prefix)
	//adjustedSeries = original.SetPrefixLen(prefix)
	//if err != nil {
	//	t.addFailure(newSegmentSeriesFailure("set prefix error: "+err.Error(), original))
	//	return
	//}
	////if original.IsPrefixBlock() && original.GetPrefixLen().Exceeds(prefix) {
	//if (original.IsPrefixed() && original.GetPrefixLen().Matches(original.GetBitCount())) ||
	//	(!original.IsPrefixBlock() && adjustedSeries.IsZeroHost()) {
	//	//xxx if diff between prefix set and original is negative and original is pref block xxx
	//
	//	//if original.IsPrefixed() && *original.GetPrefixLen() == original.GetBitCount() && original.GetPrefixLen().Is(original.GetBitCount()) { //TODO we need a method on prefix len to compare with a bit count
	//	// all host bits of matching address are zeroed out, so we must get the zero host and not the prefix subnet
	//	prefixSet, err = prefixSet.ToZeroHost()
	//	if err != nil {
	//		t.addFailure(newSegmentSeriesFailure("set prefix error: "+err.Error(), original))
	//		return
	//	}
	//}

	//setPrefix := adjustedSeries.GetPrefixLen()

	//if !adjustedSeries.Equals(prefixSet) {
	//	fmt.Println(original.String() + " set: " + adjustedSeries.String() + " expected: " + prefixSet.String() + " set prefix: " + prefix.String())
	//	t.addFailure(newSegmentSeriesFailure("prefix set: "+adjustedSeries.String(), prefixSet))
	//}
	//else {
	//	//adjustedSeries = original.ApplyPrefixLen(prefix);
	//	//appliedPrefix := adjustedSeries.GetPrefixLen();
	//	//if(!adjustedSeries.Equals(prefixApplied)) {
	//	//t.addFailure(newFailure("prefix applied: " + adjustedSeries, prefixApplied));
	//	//} else {
	//
	//	originalPref := original.GetPrefixLen()
	//	var expected ExpectedPrefixes
	//	bitLength := original.GetBitCount()
	//	//segmentBitLength := original.GetBitsPerSegment()
	//	if originalPref == nil {
	//		//_, ok := original.Unwrap().(*ipaddr.MACAddress)
	//		//if ok {
	//		//	expected.previous = cacheTestBits(bitLength - segmentBitLength)
	//		//} else {
	//		//	expected.previous = cacheTestBits(bitLength)
	//		//}
	//		if adjustment <= 0 {
	//			expected.adjusted = cacheTestBits(bitLength + adjustment)
	//		} else {
	//			expected.adjusted = cacheTestBits(adjustment)
	//		}
	//		expected.set = cacheTestBits(prefix)
	//	} else {
	//		//if *originalPref != bitLength {
	//		//	expected.next = cacheTestBits(min(bitLength, ((*originalPref + segmentBitLength) / segmentBitLength) * segmentBitLength))
	//		//}
	//		//expected.previous = cacheTestBits(max(0, ((*originalPref - 1) / segmentBitLength) * segmentBitLength));
	//		adj := min(max(0, *originalPref+adjustment), original.GetBitCount())
	//		//if adj <= bitLength {
	//		expected.adjusted = cacheTestBits(adj)
	//		//}
	//		//this.set = set;
	//		expected.set = cacheTestBits(prefix)
	//	}
	//
	//	////ExpectedPrefixes expected = new ExpectedPrefixes(original instanceof MACAddress, original.getPrefixLength(), original.getBitCount(), original.getBitsPerSegment(), prefix, adjustment);
	//	//if !expected.compare(adjustedPrefix, setPrefix) {
	//	//	//if(!expected.compare(nextPrefix, prevPrefix, adjustedPrefix, setPrefix, appliedPrefix)) {
	//	//	t.addFailure(newSegmentSeriesFailure("expected: "+expected.adjusted.String()+" actual "+adjustedPrefix.String()+" expected: "+expected.set.String()+" actual "+setPrefix.String(), original))
	//	//	//t.addFailure(newSegmentSeriesFailure(expected.print(nextPrefix, prevPrefix, adjustedPrefix, setPrefix, appliedPrefix)))
	//	//}
	//	//}
	//	//}
	//}
	//}
	//	}
}

func (t testBase) testPrefixes(original ipaddr.ExtendedIPSegmentSeries,
	prefix, adjustment ipaddr.BitCount,
	_, _,
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
			//	removed = original.WithoutPrefixLen()
		} else {
			removed, err = original.AdjustPrefixLenZeroed(original.GetBitCount())
			//removed = original.AdjustPrefixLen(original.GetBitCount())
			//fmt.Println("not beyond " + removed.String())
		}
		if err != nil {
			t.addFailure(newSegmentSeriesFailure("removed prefix error: "+err.Error(), original))
			break
		}
		//if j == 1 && original.GetPrefixLen() != nil && *original.GetPrefixLen() == 0 {
		//	removed = original.AdjustPrefixLen(original.GetBitCount() + 1)
		//}
		if original.IsPrefixed() {
			prefLength := *original.GetPrefixLen()
			bitsSoFar := ipaddr.BitCount(0)
			for i := 0; i < removed.GetSegmentCount(); i++ {
				prevBitsSoFar := bitsSoFar
				seg := removed.GetSegment(i)
				bitsSoFar += seg.GetBitCount()
				if prefLength >= bitsSoFar {
					if !seg.Equals(original.GetSegment(i)) {
						t.addFailure(newSegmentSeriesFailure("removed prefix: "+removed.String(), original))
						break
					}
				} else if prefLength <= prevBitsSoFar {
					if !seg.IsZero() {
						t.addFailure(newSegmentSeriesFailure("removed prefix all: "+removed.String(), original))
						break
					}
				} else {
					segPrefix := prefLength - prevBitsSoFar
					mask := ^ipaddr.SegInt(0) << uint(seg.GetBitCount()-segPrefix)
					lower := seg.GetSegmentValue()
					upper := seg.GetUpperSegmentValue()
					if (lower&mask) != lower || (upper&mask) != upper {
						//removed = original.removePrefixLength();
						t.addFailure(newSegmentSeriesFailure("prefix app: "+removed.String()+" "+strconv.Itoa(int(lower&mask))+" "+strconv.Itoa(int(upper&mask)), original))
						break
					}
				}
			}
			//if removed.IsPrefixed() {
			//	t.addFailure(newSegmentSeriesFailure("prefix not removed: "+removed.String(), original))
			//}
		} else if !removed.Equals(original) {
			t.addFailure(newSegmentSeriesFailure("prefix removed: "+removed.String(), original))
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
		t.addFailure(newSegmentSeriesFailure("adjusted prefix error: "+err.Error(), original))
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
		//  case 3 - original is prefix block, adjustment is negative, so we are not prefix block but expected is
		// either we are converted to prefix block or what? that is the only option
		// OR consider that we do have the correct expected but it is converted to prefix block: 255.96.*.*/11
		// maybe we need to change the fact that address is converted to prefix block
		// I think we do.

		// all host bits of matching address are zeroed out, so we must get the zero host and not the prefix subnet
		adjusted, err = adjusted.ToZeroHost()
		if err != nil {
			t.addFailure(newSegmentSeriesFailure("adjusted prefix error: "+err.Error(), original))
			return
		}
	}

	if !adjustedSeries.Equals(adjusted) {
		//TWO things wrong: 1. the new series is not a prefix subnet (which is actually correct, I think, since I wanted to stop doing that).  But how am I supposed to specify the result?  I guess with the toZeroHost
		// 2. the canonical string things otherwise!  how is that possible?  wrong, it is correct
		//fmt.Println("original " + original.String() + " adjusted series: " + adjustedSeries.String() + " expected: " + adjusted.String() + " increment: " + adjustment.String())
		//fmt.Println("original " + original.String() + " adjusted series: " + adjustedSeries.ToNormalizedWildcardString() + " expected: " + adjusted.ToNormalizedWildcardString() + " increment: " + adjustment.String())
		t.addFailure(newSegmentSeriesFailure("prefix adjusted: "+adjustedSeries.String(), adjusted))
		original.AdjustPrefixLenZeroed(adjustment)
		//a, berr := original.AdjustPrefixLenZeroed(adjustment)
		//_ = berr
		//a.String()
	} else {
		adjustedSeries, err = original.SetPrefixLenZeroed(prefix)
		//adjustedSeries = original.SetPrefixLen(prefix)
		if err != nil {
			t.addFailure(newSegmentSeriesFailure("set prefix error: "+err.Error(), original))
			return
		}
		//if original.IsPrefixBlock() && original.GetPrefixLen().Exceeds(prefix) {
		if (original.IsPrefixed() && original.GetPrefixLen().Matches(original.GetBitCount())) ||
			(!original.IsPrefixBlock() && adjustedSeries.IsZeroHost()) {
			//xxx if diff between prefix set and original is negative and original is pref block xxx

			//if original.IsPrefixed() && *original.GetPrefixLen() == original.GetBitCount() && original.GetPrefixLen().Is(original.GetBitCount()) { //TODO we need a method on prefix len to compare with a bit count
			// all host bits of matching address are zeroed out, so we must get the zero host and not the prefix subnet
			prefixSet, err = prefixSet.ToZeroHost()
			if err != nil {
				t.addFailure(newSegmentSeriesFailure("set prefix error: "+err.Error(), original))
				return
			}
		}

		setPrefix := adjustedSeries.GetPrefixLen()
		if !adjustedSeries.Equals(prefixSet) {
			fmt.Println(original.String() + " set: " + adjustedSeries.String() + " expected: " + prefixSet.String() + " set prefix: " + prefix.String())
			t.addFailure(newSegmentSeriesFailure("prefix set: "+adjustedSeries.String(), prefixSet))
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
				t.addFailure(newSegmentSeriesFailure("expected: "+expected.adjusted.String()+" actual "+adjustedPrefix.String()+" expected: "+expected.set.String()+" actual "+setPrefix.String(), original))
				//t.addFailure(newSegmentSeriesFailure(expected.print(nextPrefix, prevPrefix, adjustedPrefix, setPrefix, appliedPrefix)))
			}
			//}
		}
	}
	//}
	//	}
}

func (t testBase) testReplace(front, back *ipaddr.Address, fronts, backs []string, sep byte, isMac bool) {
	bitsPerSegment := front.GetBitsPerSegment()
	segmentCount := front.GetSegmentCount()
	isIpv4 := !isMac && segmentCount == ipaddr.IPv4SegmentCount
	prefixes := strings.Builder{}
	prefixes.WriteString("[\n")
	//StringBuilder prefixes = new StringBuilder("[\n");//currently unused
	for replaceTargetIndex := 0; replaceTargetIndex < len(fronts); replaceTargetIndex++ {
		if replaceTargetIndex > 0 {
			prefixes.WriteString(",\n")
		}
		prefixes.WriteString("[")
		for replaceCount := 0; replaceCount < len(fronts)-replaceTargetIndex; replaceCount++ {
			if replaceCount > 0 {
				prefixes.WriteString(",\n")
			}
			prefixes.WriteString("    [")
			lowest := strings.Builder{}
			for replaceSourceIndex := 0; replaceSourceIndex < len(backs)-replaceCount; replaceSourceIndex++ {
				//We are replacing replaceCount segments in front at index replaceTargetIndex with the same number of segments starting at replaceSourceIndex in back
				str := strings.Builder{}
				k := 0
				for ; k < replaceTargetIndex; k++ {
					if str.Len() > 0 {
						str.WriteByte(sep)
					}
					str.WriteString(fronts[k])
				}
				current := k
				limit := replaceCount + current
				for ; k < limit; k++ {
					if str.Len() > 0 {
						str.WriteByte(sep)
					}
					str.WriteString(backs[replaceSourceIndex+k-current])
				}
				for ; k < segmentCount; k++ {
					if str.Len() > 0 {
						str.WriteByte(sep)
					}
					str.WriteString(fronts[k])
				}
				var prefix ipaddr.PrefixLen
				frontPrefixed := front.IsPrefixed()
				if frontPrefixed && (*front.GetPrefixLen() <= ipaddr.BitCount(replaceTargetIndex)*bitsPerSegment) && (isMac || replaceTargetIndex > 0) { //when replaceTargetIndex is 0, slight difference between mac and ipvx, for ipvx we do not account for a front prefix of 0
					prefix = front.GetPrefixLen()
				} else if back.IsPrefixed() && (*back.GetPrefixLen() <= ipaddr.BitCount(replaceSourceIndex+replaceCount)*bitsPerSegment) && (isMac || replaceCount > 0) { //when replaceCount 0, slight difference between mac and ipvx, for ipvx we do not account for a back prefix
					prefix = cacheTestBits((ipaddr.BitCount(replaceTargetIndex) * bitsPerSegment) + max(0, *back.GetPrefixLen()-(ipaddr.BitCount(replaceSourceIndex)*bitsPerSegment)))
				} else if frontPrefixed {
					if *front.GetPrefixLen() <= ipaddr.BitCount(replaceTargetIndex+replaceCount)*bitsPerSegment {
						prefix = cacheTestBits(ipaddr.BitCount(replaceTargetIndex+replaceCount) * bitsPerSegment)
					} else {
						prefix = front.GetPrefixLen()
					}
				} //else {
				//	prefix = null;
				//}
				replaceStr := " replacing " + strconv.Itoa(replaceCount) + " segments in " + front.String() + " at index " + strconv.Itoa(replaceTargetIndex) +
					" with segments from " + back.String() + " starting at " + strconv.Itoa(replaceSourceIndex)

				var new1, new2 *ipaddr.Address
				if isMac {
					fromMac := front.ToMACAddress()
					new1 = fromMac.ReplaceLen(replaceTargetIndex, replaceTargetIndex+replaceCount, back.ToMACAddress(), replaceSourceIndex).ToAddress()
					hostIdStr := t.createMACAddress(str.String())
					new2 = hostIdStr.GetAddress().ToAddress()
					if prefix != nil {
						new2 = new2.SetPrefixLen(*prefix)
					}
				} else {
					if prefix != nil {
						str.WriteByte('/')
						str.WriteString(prefix.String())
					}
					hostIdStr := t.createAddress(str.String())
					new2 = hostIdStr.GetAddress().ToAddress()
					if isIpv4 {
						frontIPv4 := front.ToIPv4Address()
						new1 = frontIPv4.ReplaceLen(replaceTargetIndex, replaceTargetIndex+replaceCount, back.ToIPv4Address(), replaceSourceIndex).ToAddress()
					} else {
						frontIPv6 := front.ToIPv6Address()
						new1 = frontIPv6.ReplaceLen(replaceTargetIndex, replaceTargetIndex+replaceCount, back.ToIPv6Address(), replaceSourceIndex).ToAddress()
					}
				}
				if !new1.Equals(new2) {
					failStr := "Replacement was " + new1.String() + " expected was " + new2.String() + " " + replaceStr
					t.addFailure(newIPAddrFailure(failStr, front.ToIPAddress()))

					//this was debug
					//IPv6AddressSection frontSection = ((IPv6Address) front).getSection();
					//IPv6AddressSection backSection = ((IPv6Address) back).getSection();
					//frontSection.replace(replaceTargetIndex, replaceTargetIndex + replaceCount, backSection, replaceSourceIndex, replaceSourceIndex + replaceCount);
				}
				if lowest.Len() > 0 {
					lowest.WriteByte(',')
				}
				lowest.WriteString(prefix.String())
			}
			prefixes.WriteString(lowest.String())
			prefixes.WriteByte(']')
		}
		prefixes.WriteByte(']')
	}
	prefixes.WriteByte(']')
}

func (t testBase) testAppendAndInsert(front, back *ipaddr.Address, fronts, backs []string, sep byte, expectedPref []ipaddr.PrefixLen, isMac bool) {
	//if(front.getSegmentCount() >= expectedPref.length) {
	//	throw new IllegalArgumentException();
	//}
	extra := 0
	if isMac {
		extra = ipaddr.ExtendedUniqueIdentifier64SegmentCount - front.GetSegmentCount()
	}
	bitsPerSegment := front.GetBitsPerSegment()
	isIpv4 := !isMac && front.GetSegmentCount() == ipaddr.IPv4SegmentCount
	for i := 0; i < len(fronts); i++ {
		str := strings.Builder{}
		k := 0
		for ; k < i; k++ {
			if str.Len() > 0 {
				str.WriteByte(sep)
			}
			str.WriteString(fronts[k])
		}
		for ; k < len(fronts); k++ {
			if str.Len() > 0 {
				str.WriteByte(sep)
			}
			str.WriteString(backs[k])
		}
		//var hostIdStr ipaddr.HostIdentifierString

		//Split up into two sections to test append
		frontSection := front.GetSubSection(0, i)
		backSection := back.GetTrailingSection(i)
		var backSectionInvalid, frontSectionInvalid *ipaddr.AddressSection
		if i-(1+extra) >= 0 && i+1+extra <= front.GetSegmentCount() {
			backSectionInvalid = back.GetTrailingSection(i - (1 + extra))
			frontSectionInvalid = front.GetSubSection(0, i+1+extra)
		}

		//Split up even further into 3 sections to test insert
		//List<AddressSection[]> splits = new ArrayList<AddressSection[]>(front.getSegmentCount() + 3);
		var splits [][]*ipaddr.AddressSection
		for m := 0; m <= frontSection.GetSegmentCount(); m++ {
			sub1 := frontSection.GetSubSection(0, m)
			sub2 := frontSection.GetSubSection(m, frontSection.GetSegmentCount())
			splits = append(splits, []*ipaddr.AddressSection{sub1, sub2, backSection})
		}
		for m := 0; m <= backSection.GetSegmentCount(); m++ {
			sub1 := backSection.GetSubSection(0, m)
			sub2 := backSection.GetSubSection(m, backSection.GetSegmentCount())
			splits = append(splits, []*ipaddr.AddressSection{frontSection, sub1, sub2})
		}
		//now you can insert the middle one after appending the first and last
		//Keep in mind that inserting the first one is like a prepend, which is like an append
		//Inserting the last one is an append
		//We already test append pretty good
		//So really, just insert the middle one after appending first and last
		var splitsJoined []*ipaddr.Address
		//List<Address> splitsJoined = new ArrayList<Address>(splits.size());
		//try {
		var mixed, mixed2 *ipaddr.Address
		if isMac {
			hostIdStr := t.createMACAddress(str.String())
			mixed = hostIdStr.GetAddress().ToAddress()
			if front.IsPrefixed() && *front.GetPrefixLen() <= ipaddr.BitCount(i)*bitsPerSegment {
				mixed = mixed.SetPrefixLen(*front.GetPrefixLen())
			} else if back.IsPrefixed() {
				mixed = mixed.SetPrefixLen(max(ipaddr.BitCount(i)*bitsPerSegment, *back.GetPrefixLen()))
			}
			sec := frontSection.ToMACAddressSection().Append(backSection.ToMACAddressSection())
			//mixed2 = (back.ToMACAddress()).GetNetwork().getAddressCreator().createAddress(sec);
			mixed2x, err := ipaddr.NewMACAddress(sec)
			if err != nil {
				t.addFailure(newSegmentSeriesFailure("unexpected error: "+err.Error(), sec))
			}
			mixed2 = mixed2x.ToAddress()

			if frontSectionInvalid != nil && backSectionInvalid != nil {
				//This doesn't fail anymore because we allow large sections
				//try {
				newSec := (frontSection.ToMACAddressSection()).Append(backSectionInvalid.ToMACAddressSection())
				if newSec.GetSegmentCount() != frontSection.GetSegmentCount()+backSectionInvalid.GetSegmentCount() {
					t.addFailure(newSegmentSeriesFailure("unexpected seg count: "+strconv.Itoa(newSec.GetSegmentCount()), newSec))
				}
				//addFailure(new Failure("invalid segment length should have failed in join of " + frontSection + " with " + backSectionInvalid, front));
				//} catch(AddressValueException e) {
				//pass
				//}
				//try {
				newSec = (frontSectionInvalid.ToMACAddressSection()).Append(backSection.ToMACAddressSection())
				if newSec.GetSegmentCount() != frontSectionInvalid.GetSegmentCount()+backSection.GetSegmentCount() {
					t.addFailure(newSegmentSeriesFailure("unexpected seg count: "+strconv.Itoa(newSec.GetSegmentCount()), newSec))
				}
				//addFailure(new Failure("invalid segment length should have failed in join of " + frontSectionInvalid + " with " + backSection, front));
				//} catch(AddressValueException e) {
				//pass
				//}
			}
			for o := 0; o < len(splits); o++ {
				split := splits[o]
				f := split[0]
				g := split[1]
				h := split[2]
				sec = f.ToMACAddressSection().Append(h.ToMACAddressSection())
				//if(h.IsPrefixed() && h.GetPrefixLen() == 0 && !f.IsPrefixed()) {
				//	sec = sec.AppendToPrefix((MACAddressSection) g);
				//} else {
				sec = sec.Insert(f.GetSegmentCount(), g.ToMACAddressSection())
				if h.IsPrefixed() && *h.GetPrefixLen() == 0 && !f.IsPrefixed() {
					gPref := ipaddr.BitCount(g.GetSegmentCount()) * ipaddr.MACBitsPerSegment
					if g.IsPrefixed() {
						gPref = *g.GetPrefixLen()
					}
					sec = sec.SetPrefixLen(ipaddr.BitCount(f.GetSegmentCount())*ipaddr.MACBitsPerSegment + gPref)
				}

				//}
				mixed3, err := ipaddr.NewMACAddress(sec)

				//MACAddress mixed3 = ((MACAddress) back).getNetwork().getAddressCreator().createAddress(sec);
				if err != nil {
					t.addFailure(newSegmentSeriesFailure("unexpected error: "+err.Error(), sec))
				}
				splitsJoined = append(splitsJoined, mixed3.ToAddress())
			}
		} else {
			if front.IsPrefixed() && *front.GetPrefixLen() <= (ipaddr.BitCount(i)*bitsPerSegment) && i > 0 {
				str.WriteByte('/')
				str.WriteString(strconv.Itoa(int(*front.GetPrefixLen())))
			} else if back.IsPrefixed() {
				str.WriteByte('/')
				if ipaddr.BitCount(i)*bitsPerSegment > *back.GetPrefixLen() {
					str.WriteString(strconv.Itoa(i * int(bitsPerSegment)))
				} else {
					str.WriteString(strconv.Itoa(int(*back.GetPrefixLen())))
				}
			}
			hostIdStr := t.createAddress(str.String())
			mixed = hostIdStr.GetAddress().ToAddress()

			if isIpv4 {
				sec := (frontSection.ToIPv4AddressSection()).Append(backSection.ToIPv4AddressSection())
				mixed2x, err := ipaddr.NewIPv4Address(sec)
				//mixed2 = ( back.ToIPv4Address()).GetNetwork().GetAddressCreator().createAddress(sec);
				if err != nil {
					t.addFailure(newSegmentSeriesFailure("unexpected error: "+err.Error(), sec))
				}
				mixed2 = mixed2x.ToAddress()

				if frontSectionInvalid != nil && backSectionInvalid != nil {
					//try {
					newSec := (frontSection.ToIPv4AddressSection()).Append(backSectionInvalid.ToIPv4AddressSection())
					if newSec.GetSegmentCount() != frontSection.GetSegmentCount()+backSectionInvalid.GetSegmentCount() {
						t.addFailure(newSegmentSeriesFailure("unexpected seg count: "+strconv.Itoa(newSec.GetSegmentCount()), newSec))
					}
					//((IPv4AddressSection) frontSection).append((IPv4AddressSection) backSectionInvalid);
					//addFailure(new Failure("invalid segment length should have failed in join of " + frontSection + " with " + backSectionInvalid, front));
					//} catch(AddressValueException e) {
					//pass
					//}
					//try {
					newSec = (frontSectionInvalid.ToIPv4AddressSection()).Append(backSection.ToIPv4AddressSection())
					if newSec.GetSegmentCount() != frontSectionInvalid.GetSegmentCount()+backSection.GetSegmentCount() {
						t.addFailure(newSegmentSeriesFailure("unexpected seg count: "+strconv.Itoa(newSec.GetSegmentCount()), newSec))
					}
					//((IPv4AddressSection) frontSectionInvalid).append((IPv4AddressSection) backSection);
					//addFailure(new Failure("invalid segment length should have failed in join of " + frontSectionInvalid + " with " + backSection, front));
					//} catch(AddressValueException e) {
					//pass
					//}
				}
				for o := 0; o < len(splits); o++ {
					split := splits[o]
					f := split[0]
					g := split[1]
					h := split[2]
					sec = (f.ToIPv4AddressSection()).Append(h.ToIPv4AddressSection())
					//if(h.isPrefixed() && h.getPrefixLength() == 0 && !f.isPrefixed()) {
					//	sec = sec.appendToNetwork((IPv4AddressSection) g);
					//} else {
					sec = sec.Insert(f.GetSegmentCount(), g.ToIPv4AddressSection())
					if h.IsPrefixed() && *h.GetPrefixLen() == 0 && !f.IsPrefixed() {
						gPref := ipaddr.BitCount(g.GetSegmentCount()) * ipaddr.IPv4BitsPerSegment
						if g.IsPrefixed() {
							gPref = *g.GetPrefixLen()
						}
						sec = sec.SetPrefixLen(ipaddr.BitCount(f.GetSegmentCount())*ipaddr.IPv4BitsPerSegment + gPref)
					}
					//}
					mixed3, err := ipaddr.NewIPv4Address(sec)
					//MACAddress mixed3 = ((MACAddress) back).getNetwork().getAddressCreator().createAddress(sec);
					if err != nil {
						t.addFailure(newSegmentSeriesFailure("unexpected error: "+err.Error(), sec))
					}
					splitsJoined = append(splitsJoined, mixed3.ToAddress())
					//IPv4Address mixed3 = ((IPv4Address) back).getNetwork().getAddressCreator().createAddress(sec);
					//splitsJoined.add(mixed3);
				}
			} else { // IPv6
				sec := frontSection.ToIPv6AddressSection().Append(backSection.ToIPv6AddressSection())
				mixed2x, err := ipaddr.NewIPv6Address(sec)
				//mixed2x, err := ((IPv6Address) back).getNetwork().getAddressCreator().createAddress(sec);
				if err != nil {
					t.addFailure(newSegmentSeriesFailure("unexpected error: "+err.Error(), sec))
				}
				mixed2 = mixed2x.ToAddress()
				if frontSectionInvalid != nil && backSectionInvalid != nil {
					//try {
					newSec := (frontSection.ToIPv6AddressSection()).Append(backSectionInvalid.ToIPv6AddressSection())
					if newSec.GetSegmentCount() != frontSection.GetSegmentCount()+backSectionInvalid.GetSegmentCount() {
						t.addFailure(newSegmentSeriesFailure("unexpected seg count: "+strconv.Itoa(newSec.GetSegmentCount()), newSec))
					}
					//	addFailure(new Failure("invalid segment length should have failed in join of " + frontSection + " with " + backSectionInvalid, front));
					//} catch(AddressValueException e) {
					//pass
					//}
					//try {
					newSec = (frontSectionInvalid.ToIPv6AddressSection()).Append(backSection.ToIPv6AddressSection())
					if newSec.GetSegmentCount() != frontSectionInvalid.GetSegmentCount()+backSection.GetSegmentCount() {
						t.addFailure(newSegmentSeriesFailure("unexpected seg count: "+strconv.Itoa(newSec.GetSegmentCount()), newSec))
					}
					//addFailure(new Failure("invalid segment length should have failed in join of " + frontSectionInvalid + " with " + backSection, front));
					//} catch(AddressValueException e) {
					//pass
					//}
				}
				for o := 0; o < len(splits); o++ {
					split := splits[o]
					f := split[0]
					g := split[1]
					h := split[2]
					sec = f.ToIPv6AddressSection().Append(h.ToIPv6AddressSection())
					//if(h.isPrefixed() && h.getPrefixLength() == 0 && !f.isPrefixed()) {
					//	sec = sec.appendToNetwork((IPv6AddressSection) g);
					//} else {
					sec = sec.Insert(f.GetSegmentCount(), g.ToIPv6AddressSection())
					//}
					if h.IsPrefixed() && *h.GetPrefixLen() == 0 && !f.IsPrefixed() {
						gPref := ipaddr.BitCount(g.GetSegmentCount()) * ipaddr.IPv6BitsPerSegment
						if g.IsPrefixed() {
							gPref = *g.GetPrefixLen()
						}
						sec = sec.SetPrefixLen(ipaddr.BitCount(f.GetSegmentCount())*ipaddr.IPv6BitsPerSegment + gPref)
					}
					mixed3, err := ipaddr.NewIPv6Address(sec)
					//MACAddress mixed3 = ((MACAddress) back).getNetwork().getAddressCreator().createAddress(sec);
					if err != nil {
						t.addFailure(newSegmentSeriesFailure("unexpected error: "+err.Error(), sec))
					}
					splitsJoined = append(splitsJoined, mixed3.ToAddress())
					//IPv6Address mixed3 = ((IPv6Address) back).getNetwork().getAddressCreator().createAddress(sec);
					//splitsJoined.add(mixed3);
				}
			}
		}
		if !mixed.Equals(mixed2) {
			t.addFailure(newSegmentSeriesFailure("mixed was "+mixed.String()+" expected was "+mixed2.String(), mixed))
			//hostIdStr = createMACAddress(str.toString());
			//mixed = hostIdStr.GetAddress();
			//if(front.isPrefixed() && front.getPrefixLength() <= i * bitsPerSegment) {
			//	mixed = mixed.setPrefixLength(front.getPrefixLength(), false);
			//} else if(back.isPrefixed()) {
			//	mixed = mixed.setPrefixLength(Math.max(i * bitsPerSegment, back.getPrefixLength()), false);
			//}
			//MACAddressSection sec = ((MACAddressSection) frontSection).append((MACAddressSection) backSection);
			//mixed2 = ((MACAddress) back).getNetwork().getAddressCreator().createAddress(sec);
			//System.out.println("mixed is " + mixed);
			//System.out.println("mixed2 is " + mixed2);
		}
		if !expectedPref[i].Equals(mixed.GetPrefixLen()) {
			t.addFailure(newSegmentSeriesFailure("mixed prefix was "+mixed.GetPrefixLen().String()+" expected was "+expectedPref[i].String(), mixed))
		}
		if !expectedPref[i].Equals(mixed2.GetPrefixLen()) {
			t.addFailure(newSegmentSeriesFailure("mixed2 prefix was "+mixed2.GetPrefixLen().String()+" expected was "+expectedPref[i].String(), mixed2))
		}
		for o := 0; o < len(splitsJoined); o++ {
			mixed3 := splitsJoined[o]
			if !mixed.Equals(mixed3) {
				t.addFailure(newSegmentSeriesFailure("mixed was "+mixed3.String()+" expected was "+mixed.String(), mixed3))
			}
			if !mixed3.Equals(mixed2) {
				t.addFailure(newSegmentSeriesFailure("mixed was "+mixed3.String()+" expected was "+mixed2.String(), mixed3))
			}
			if !expectedPref[i].Equals(mixed3.GetPrefixLen()) {
				fmt.Printf("%v\n", splitsJoined)
				fmt.Printf("%v\n", splits)
				t.addFailure(newSegmentSeriesFailure("mixed3 prefix was "+mixed3.GetPrefixLen().String()+" expected was "+expectedPref[i].String(), mixed3))
			}
		}
		//} catch(IncompatibleAddressException e) {
		//	if(expectedPref[i] == null || expectedPref[i] >= 0) {
		//		addFailure(new Failure("expected prefix " + expectedPref[i] + ", but append failed due to prefix for " + frontSection + " and " + backSection, hostIdStr));
		//	}
		//} catch(IllegalArgumentException e) {
		//	if(expectedPref[i] == null || expectedPref[i] >= 0) {
		//		addFailure(new Failure("expected prefix " + expectedPref[i] + ", but append failed due to prefix for " + frontSection + " and " + backSection, hostIdStr));
		//	}
		//}
	}
	t.incrementTestCount()
}

func (t testBase) testIncrement(orig *ipaddr.Address, increment int64, expectedResult *ipaddr.Address) {
	t.testIncrementF(orig, increment, expectedResult, true)
}

func (t testBase) testIncrementF(orig *ipaddr.Address, increment int64, expectedResult *ipaddr.Address, first bool) {
	//try {
	result := orig.Increment(increment)
	if expectedResult == nil {
		if result != nil {
			t.addFailure(newSegmentSeriesFailure("increment mismatch result "+result.String()+" vs none expected", orig))
		}
	} else {
		if !result.Equals(expectedResult) {
			t.addFailure(newSegmentSeriesFailure("increment mismatch result "+result.String()+" vs expected "+expectedResult.String(), orig))
		}
		if first && !orig.IsMultiple() && increment > math.MinInt64 { //negating Long.MIN_VALUE results in same address
			//if(first && !orig.isMultiple() && increment > Long.MIN_VALUE) {//negating Long.MIN_VALUE results in same address
			t.testIncrementF(expectedResult, -increment, orig, false)
		}
	}
	//} catch(AddressValueException e) {
	//if(expectedResult != null) {
	//	addFailure(newIPAddrFailure("increment mismatch exception " +  e.Error() + ", expected " + expectedResult, orig));
	//}
	//}
	t.incrementTestCount()
}

func (t testBase) testPrefix(original ipaddr.AddressSegmentSeries, prefixLength ipaddr.PrefixLen, minPrefix ipaddr.BitCount, equivalentPrefix ipaddr.PrefixLen) {
	if !original.GetPrefixLen().Equals(prefixLength) {
		t.addFailure(newSegmentSeriesFailure("prefix: "+original.GetPrefixLen().String()+" expected: "+prefixLength.String(), original))
	} else if !cacheTestBits(original.GetMinPrefixLenForBlock()).Equals(cacheTestBits(minPrefix)) {
		t.addFailure(newSegmentSeriesFailure("min prefix: "+strconv.Itoa(int(original.GetMinPrefixLenForBlock()))+" expected: "+minPrefix.String(), original))
	} else if !original.GetPrefixLenForSingleBlock().Equals(equivalentPrefix) {
		t.addFailure(newSegmentSeriesFailure("equivalent prefix: "+original.GetPrefixLenForSingleBlock().String()+" expected: "+equivalentPrefix.String(), original))
	}
}

func (t testBase) testIPv6Strings(w *ipaddr.IPAddressString, ipAddr *ipaddr.IPAddress,
	normalizedString,
	normalizedWildcardString,
	canonicalWildcardString,
	sqlString,
	fullString,
	compressedString,
	canonicalString,
	subnetString,
	compressedWildcardString,
	mixedStringNoCompressMixed,
	mixedStringNoCompressHost,
	mixedStringCompressCoveredHost,
	mixedString,
	reverseDNSString,
	uncHostString,
	base85String,
	singleHex,
	singleOctal string) {

	t.testStrings(w, ipAddr, normalizedString, normalizedWildcardString, canonicalWildcardString, sqlString, fullString, compressedString, canonicalString, subnetString, subnetString, compressedWildcardString, reverseDNSString, uncHostString, singleHex, singleOctal)

	//now test some IPv6-only strings
	t.testIPv6OnlyStrings(w, ipAddr.ToIPv6Address(), mixedStringNoCompressMixed,
		mixedStringNoCompressHost, mixedStringCompressCoveredHost, mixedString, base85String)
}

func (t testBase) testIPv6OnlyStrings(w *ipaddr.IPAddressString, ipAddr *ipaddr.IPv6Address,
	mixedStringNoCompressMixed,
	mixedStringNoCompressHost,
	mixedStringCompressCoveredHost,
	mixedString,
	base85String string) {

	//try {
	base85 := ""
	//try { TODO LATER base85
	//	base85 = ipAddr.toBase85String();
	//	boolean b85Match = base85.equals(base85String);
	//	if(!b85Match) {
	//		addFailure(new Failure("failed expected: " + base85String + " actual: " + base85, w));
	//	}
	//} catch(IncompatibleAddressException e) {
	//	boolean isMatch = base85String == null;
	//	if(!isMatch) {
	//		addFailure(new Failure("failed expected non-null, actual: " + e, w));
	//	}
	//}

	m, _ := ipAddr.ToMixedString()

	compressOpts := new(ipaddr.CompressOptionsBuilder).SetCompressSingle(true).SetRangeSelection(ipaddr.ZEROS_OR_HOST).SetMixedOptions(ipaddr.COVERED_BY_HOST)
	mixedParams := new(ipaddr.IPv6StringOptionsBuilder).SetMixed(true).SetCompressOptions(compressOpts).ToOptions()
	mixedCompressCoveredHost, _ := ipAddr.ToCustomString(mixedParams)

	compressOpts = new(ipaddr.CompressOptionsBuilder).SetCompressSingle(true).SetRangeSelection(ipaddr.ZEROS_OR_HOST).SetMixedOptions(ipaddr.NO_HOST)
	mixedParams = new(ipaddr.IPv6StringOptionsBuilder).SetMixed(true).SetCompressOptions(compressOpts).ToOptions()
	mixedNoCompressHost, _ := ipAddr.ToCustomString(mixedParams)

	compressOpts = new(ipaddr.CompressOptionsBuilder).SetCompressSingle(true).SetRangeSelection(ipaddr.ZEROS_OR_HOST).SetMixedOptions(ipaddr.NO_MIXED_COMPRESSION)
	mixedParams = new(ipaddr.IPv6StringOptionsBuilder).SetMixed(true).SetCompressOptions(compressOpts).ToOptions()
	mixedNoCompressMixed, _ := ipAddr.ToCustomString(mixedParams)

	t.confirmAddrStrings(ipAddr.ToIPAddress(), m, mixedCompressCoveredHost, mixedNoCompressHost, mixedNoCompressMixed, base85)

	nMatch := m == (mixedString)
	if !nMatch {
		t.addFailure(newFailure("failed expected: "+mixedString+" actual: "+m, w))
	} else {
		mccMatch := mixedCompressCoveredHost == (mixedStringCompressCoveredHost)
		if !mccMatch {
			t.addFailure(newFailure("failed expected: "+mixedStringCompressCoveredHost+" actual: "+mixedCompressCoveredHost, w))
		} else {
			msMatch := mixedNoCompressHost == (mixedStringNoCompressHost)
			if !msMatch {
				t.addFailure(newFailure("failed expected: "+mixedStringNoCompressHost+" actual: "+mixedNoCompressHost, w))
			} else {
				mncmMatch := mixedNoCompressMixed == (mixedStringNoCompressMixed)
				if !mncmMatch {
					t.addFailure(newFailure("failed expected: "+mixedStringNoCompressMixed+" actual: "+mixedNoCompressMixed, w))
				}
			}
		}
	}
	//} catch(IncompatibleAddressException e) {
	//	addFailure(new Failure("unexpected throw " + e.toString()));
	//}
	t.incrementTestCount()
}

func (t testBase) confirmMACAddrStrings(macAddr *ipaddr.MACAddress, strs ...string) bool {
	for _, str := range strs {
		addrString := ipaddr.NewMACAddressString(str)
		addr := addrString.GetAddress()
		if !macAddr.Equals(addr) {
			t.addFailure(newSegmentSeriesFailure("failed produced string: "+str, macAddr))
			return false
		}
	}
	t.incrementTestCount()
	return true
}

//private static final IPAddressStringParameters DEFAULT_BASIC_VALIDATION_OPTIONS = new IPAddressStringParameters.Builder().toParams();

func (t testBase) confirmAddrStrings(ipAddr *ipaddr.IPAddress, strs ...string) bool {
	for _, str := range strs {
		if str == "" {
			continue
		}

		addrString := t.createParamsAddress(str, defaultOptions)
		addr := addrString.GetAddress()
		if !ipAddr.Equals(addr) {
			t.addFailure(newIPAddrFailure("failed produced string: "+str, ipAddr))
			//fmt.Println("failed: " + str)
			//fmt.Println(fmt.Sprintf("original: "+ipAddr.String()+" others: %v", strs))
			//t.confirmAddrStrings(ipAddr, strs...)
			//addrString = createAddress(str, DEFAULT_BASIC_VALIDATION_OPTIONS);
			//addrString.GetAddress();
			return false
		}
	}
	t.incrementTestCount()
	return true
}

func (t testBase) confirmIPAddrStrings(ipAddr *ipaddr.IPAddress, strs ...*ipaddr.IPAddressString) bool {
	for _, str := range strs {
		addr := str.GetAddress()
		if !ipAddr.Equals(addr) {
			t.addFailure(newIPAddrFailure("failed produced string: "+str.String(), ipAddr))
			return false
		}
	}
	t.incrementTestCount()
	return true
}

func (t testBase) confirmHostStrings(ipAddr *ipaddr.IPAddress, omitZone bool, strs ...string) bool {
	for _, str := range strs {
		hostName := ipaddr.NewHostName(str)
		a := hostName.GetAddress()
		if omitZone {
			ipv6Addr := ipAddr.ToIPv6Address()
			ipv6Addr, _ = ipaddr.NewIPv6Address(ipv6Addr.GetSection())
			ipAddr = ipv6Addr.ToIPAddress()
		}
		if !ipAddr.Equals(a) {
			t.addFailure(newIPAddrFailure("failed produced string: "+str, ipAddr))
			return false
		}
		again := hostName.ToNormalizedString()
		hostName = ipaddr.NewHostName(again)
		a = hostName.GetAddress()
		if !ipAddr.Equals(a) {
			t.addFailure(newIPAddrFailure("failed produced string: "+str, ipAddr))
			return false
		}
	}
	t.incrementTestCount()
	return true
}

func (t testBase) confirmHostNameStrings(ipAddr *ipaddr.IPAddress, strs ...*ipaddr.HostName) bool {
	for _, str := range strs {
		a := str.GetAddress()
		if !ipAddr.Equals(a) {
			t.addFailure(newIPAddrFailure("failed produced string: "+str.String(), ipAddr))
			return false
		}
		again := str.ToNormalizedString()
		str = ipaddr.NewHostName(again)
		a = str.GetAddress()
		if !ipAddr.Equals(a) {
			t.addFailure(newIPAddrFailure("failed produced string: "+str.String(), ipAddr))
			return false
		}
	}
	t.incrementTestCount()
	return true
}

func (t testBase) testMACStrings(w *ipaddr.MACAddressString,
	ipAddr *ipaddr.MACAddress,
	normalizedString, //toColonDelimitedString
	compressedString,
	canonicalString, //toDashedString
	dottedString,
	spaceDelimitedString,
	singleHex string) {
	// testing: could test a leading zero split digit non-reverse string - a funky range string with split digits and leading zeros, like 100-299.*.10-19.4-7 which should be 1-2.0-9.0-9.*.*.*.0.1.0-9.0.0.4-7
	c := ipAddr.ToCompressedString()
	canonical := ipAddr.ToCanonicalString()
	d := ipAddr.ToDashedString()
	n := ipAddr.ToNormalizedString()
	cd := ipAddr.ToColonDelimitedString()
	sd := ipAddr.ToSpaceDelimitedString()

	var hex, hexNoPrefix string
	var err error
	//try {
	hex, err = ipAddr.ToHexString(true)
	if err != nil {
		isMatch := singleHex == ""
		if !isMatch {
			t.addFailure(newMACFailure("failed expected: "+singleHex+" actual: "+err.Error(), w))
		}
	} else {
		t.confirmMACAddrStrings(ipAddr, hex)
	}
	//} catch(IncompatibleAddressException | IllegalStateException e) {
	//	boolean isMatch = singleHex == null;
	//	if(!isMatch) {
	//		addFailure(new Failure("failed expected: " + singleHex + " actual: " + e, w));
	//	}
	//}
	//try {
	hexNoPrefix, err = ipAddr.ToHexString(false)
	if err != nil {
		isMatch := singleHex == ""
		if !isMatch {
			t.addFailure(newMACFailure("failed expected non-null, actual: "+err.Error(), w))
		}
	} else {

		isMatch := singleHex == (hexNoPrefix)
		if !isMatch {
			t.addFailure(newMACFailure("failed expected: "+singleHex+" actual: "+hexNoPrefix, w))
		}
		t.confirmMACAddrStrings(ipAddr, hexNoPrefix) //For ipv4, no 0x means decimal
	}
	//} catch(IncompatibleAddressException | IllegalStateException e) {
	//	boolean isMatch = singleHex == null;
	//	if(!isMatch) {
	//		addFailure(new Failure("failed expected non-null, actual: " + e, w));
	//	}
	//}

	t.confirmMACAddrStrings(ipAddr, c, canonical, d, n, cd, sd)

	nMatch := normalizedString == (n)
	if !nMatch {
		t.addFailure(newMACFailure("failed expected: "+normalizedString+" actual: "+n, w))
	} else {
		nwMatch := normalizedString == (cd)
		if !nwMatch {
			t.addFailure(newMACFailure("failed expected: "+normalizedString+" actual: "+cd, w))
		} else {
			cawMatch := spaceDelimitedString == (sd)
			if !cawMatch {
				t.addFailure(newMACFailure("failed expected: "+spaceDelimitedString+" actual: "+sd, w))
			} else {
				cMatch := compressedString == (c)
				if !cMatch {
					t.addFailure(newMACFailure("failed expected: "+compressedString+" actual: "+c, w))
				} else {
					var sMatch bool
					var dotted string
					//try {
					dotted, err = ipAddr.ToDottedString()
					if err != nil {
						sMatch = (dottedString == "")
					} else {
						t.confirmMACAddrStrings(ipAddr, dotted)
						sMatch = dotted == (dottedString)
					}
					//} catch(IncompatibleAddressException e) {
					//	sMatch = (dottedString == null);
					//}
					if !sMatch {
						t.addFailure(newMACFailure("failed expected: "+dottedString+" actual: "+dotted, w))
					} else {
						dashedMatch := canonicalString == (d)
						if !dashedMatch {
							t.addFailure(newMACFailure("failed expected: "+canonicalString+" actual: "+d, w))
						} else {
							canonicalMatch := canonicalString == (canonical)
							if !canonicalMatch {
								t.addFailure(newMACFailure("failed expected: "+canonicalString+" actual: "+canonical, w))
							}
						}
					}
				}
			}
		}
	}
	t.incrementTestCount()
}

func (t testBase) testHostAddress(addressStr string) {
	str := t.createAddress(addressStr)
	address := str.GetAddress()
	if address != nil {
		hostAddress := str.GetHostAddress()
		prefixIndex := strings.IndexByte(addressStr, ipaddr.PrefixLenSeparator)
		if prefixIndex < 0 {
			if !address.Equals(hostAddress) || !address.Contains(hostAddress) {
				t.addFailure(newFailure("failed host address with no prefix: "+hostAddress.String()+" expected: "+address.String(), str))
			}
		} else {
			substr := addressStr[:prefixIndex]
			str2 := t.createAddress(substr)
			address2 := str2.GetAddress()
			if !address2.Equals(hostAddress) {
				t.addFailure(newFailure("failed host address: "+hostAddress.String()+" expected: "+address2.String(), str))
			}
		}
	}
}

func (t testBase) testStrings(w *ipaddr.IPAddressString,
	ipAddr *ipaddr.IPAddress,
	normalizedString,
	normalizedWildcardString,
	canonicalWildcardString,
	sqlString,
	fullString,
	compressedString,
	canonicalString,
	subnetString,
	cidrString,
	compressedWildcardString,
	reverseDNSString,
	uncHostString,
	singleHex,
	singleOctal string) {
	// testing: could test a leading zero split digit non-reverse string - a funky range string with split digits and leading zeros, like 100-299.*.10-19.4-7 which should be 1-2.0-9.0-9.*.*.*.0.1.0-9.0.0.4-7
	//try {
	t.testHostAddress(w.String())

	c := ipAddr.ToCompressedString()
	canonical := ipAddr.ToCanonicalString()
	s := ipAddr.ToSubnetString()
	cidr := ipAddr.ToPrefixLenString()
	n := ipAddr.ToNormalizedString()
	nw := ipAddr.ToNormalizedWildcardString()
	caw := ipAddr.ToCanonicalWildcardString()
	cw := ipAddr.ToCompressedWildcardString()
	sql := ipAddr.ToSQLWildcardString()
	full := ipAddr.ToFullString()
	//rDNS := ipAddr.ToReverseDNSLookupString(); //TODO LATER reinstate
	//unc := ipAddr.ToUNCHostName();

	var hex, hexNoPrefix, octal string
	var err error
	//try {
	hex, err = ipAddr.ToHexString(true)
	if err != nil {
		isMatch := singleHex == ""
		if !isMatch {
			t.addFailure(newFailure("failed expected: "+singleHex+" actual: "+err.Error(), w))
		}
	} else {
		isMatch := singleHex == hex
		if !isMatch {
			t.addFailure(newFailure("failed expected: "+singleHex+" actual: "+hex, w))
		}
		t.confirmAddrStrings(ipAddr, hex)
	}
	//} catch(IncompatibleAddressException | IllegalStateException e) {
	//	boolean isMatch = singleHex == null;
	//	if(!isMatch) {
	//		addFailure(new Failure("failed expected: " + singleHex + " actual: " + e, w));
	//	}
	//}
	//try {
	hexNoPrefix, err = ipAddr.ToHexString(false)
	if err != nil {
		isMatch := singleHex == ""
		if !isMatch {
			t.addFailure(newFailure("failed expected: "+singleHex+" actual: "+err.Error(), w))
		}
	} else {
		if ipAddr.IsIPv6() {
			t.confirmAddrStrings(ipAddr, hexNoPrefix) //For ipv4, no 0x means decimal
		}
	}
	//} catch(IncompatibleAddressException | IllegalStateException e) {
	//	boolean isMatch = singleHex == null;
	//	if(!isMatch) {
	//		addFailure(new Failure("failed expected non-null, actual: " + e, w));
	//	}
	//}
	//try {
	octal, err = ipAddr.ToOctalString(true)
	if err != nil {
		isMatch := singleOctal == ""
		if !isMatch {
			t.addFailure(newFailure("failed expected: "+singleOctal+" actual: "+err.Error(), w))
		}
	} else {
		isMatch := singleOctal == (octal)
		if !isMatch {
			t.addFailure(newFailure("failed expected: "+singleOctal+" actual: "+octal, w))
		}
		if ipAddr.IsIPv4() {
			t.confirmAddrStrings(ipAddr, octal)
		}
	}
	//} catch(IncompatibleAddressException | IllegalStateException e) {
	//	boolean isMatch = singleOctal == null;
	//	if(!isMatch) {
	//		addFailure(new Failure("failed expected: " + singleOctal + " actual: " + e, w));
	//	}
	//}

	//try {
	binary, err := ipAddr.ToBinaryString(false)
	if err != nil {
		isMatch := singleHex == "" //iff hex is null is binary null
		if !isMatch {
			t.addFailure(newFailure("failed expected non-null binary string but got: "+err.Error(), w))
		}
	} else {
		for i := 0; i < len(binary); i++ {
			c2 := binary[i]
			if c2 == '%' || c2 == '/' { //in most cases we handle prefixed strings by printing the whole address as a range.
				//however, for prefixed non-multiple addresses we still have the prefix
				next := strings.IndexByte(binary[i+1:], '-')
				if next >= 0 {
					i = next + 1
				} else {
					if c2 == '/' && len(binary)-i > 4 {
						t.addFailure(newFailure("failed binary prefix: "+binary, w))
					}
					break
				}
			}
			if c2 != '0' && c2 != '1' && c2 != '-' {
				t.addFailure(newFailure("failed expected non-null binary string but got: "+binary, w))
				break
			}
		}

		var withStrPrefix string

		next := strings.IndexByte(binary, '-')
		if next >= 0 {
			withStrPrefix = ipaddr.BinaryPrefix + binary[:next+1] + ipaddr.BinaryPrefix + binary[next+1:]
		} else {
			withStrPrefix = ipaddr.BinaryPrefix + binary
		}
		t.confirmAddrStrings(ipAddr, withStrPrefix)
	}
	//} catch(IncompatibleAddressException | IllegalStateException e) {
	//	boolean isMatch = singleHex == null;//iff hex is null is binary null
	//	if(!isMatch) {
	//		addFailure(new Failure("failed expected non-null binary string but got: " + e, w));
	//	}
	//}
	binary = ipAddr.ToSegmentedBinaryString()
	t.confirmAddrStrings(ipAddr, c, canonical, s, cidr, n, nw, caw, cw, binary)
	if ipAddr.IsIPv6() {
		t.confirmAddrStrings(ipAddr, full)
		//t.confirmHostStrings(ipAddr, true, rDNS);//these two are valid hosts with embedded addresses //TODO LATER reinstate
		//t.confirmHostStrings(ipAddr, false, unc);//these two are valid hosts with embedded addresses
	} else {
		params := new(ipaddr.IPAddressStringParametersBuilder).Allow_inet_aton(false).ToParams()
		fullAddrString := ipaddr.NewIPAddressStringParams(full, params)
		t.confirmIPAddrStrings(ipAddr, fullAddrString)
		//t.confirmHostStrings(ipAddr, false, rDNS, unc);//these two are valid hosts with embedded addresses //TODO LATER reinstate
	}
	t.confirmHostStrings(ipAddr, false, c, canonical, s, cidr, n, nw, caw, cw)
	if ipAddr.IsIPv6() {
		t.confirmHostStrings(ipAddr, false, full)
	} else {
		params := new(ipaddr.HostNameParametersBuilder).GetIPAddressParametersBuilder().Allow_inet_aton(false).GetParentBuilder().ToParams()
		fullAddrString := ipaddr.NewHostNameParams(full, params)
		t.confirmHostNameStrings(ipAddr, fullAddrString)
	}

	nMatch := normalizedString == (n)
	if !nMatch {
		t.addFailure(newFailure("failed expected: "+normalizedString+" actual: "+n, w))
	} else {
		nwMatch := normalizedWildcardString == (nw)
		if !nwMatch {
			t.addFailure(newFailure("failed expected: "+normalizedWildcardString+" actual: "+nw, w))
		} else {
			cawMatch := canonicalWildcardString == (caw)
			if !cawMatch {
				t.addFailure(newFailure("failed expected: "+canonicalWildcardString+" actual: "+caw, w))
			} else {
				cMatch := compressedString == (c)
				if !cMatch {
					t.addFailure(newFailure("failed expected: "+compressedString+" actual: "+c, w))
				} else {
					sMatch := subnetString == (s)
					if !sMatch {
						t.addFailure(newFailure("failed expected: "+subnetString+" actual: "+s, w))
					} else {
						cwMatch := compressedWildcardString == (cw)
						if !cwMatch {
							t.addFailure(newFailure("failed expected: "+compressedWildcardString+" actual: "+cw, w))
						} else {
							wMatch := sqlString == (sql)
							if !wMatch {
								t.addFailure(newFailure("failed expected: "+sqlString+" actual: "+sql, w))
							} else {
								cidrMatch := cidrString == (cidr)
								if !cidrMatch {
									t.addFailure(newFailure("failed expected: "+cidrString+" actual: "+cidr, w))
								} else {
									canonicalMatch := canonicalString == (canonical)
									if !canonicalMatch {
										t.addFailure(newFailure("failed expected: "+canonicalString+" actual: "+canonical, w))
									} else {
										fullMatch := fullString == (full)
										if !fullMatch {
											t.addFailure(newFailure("failed expected: "+fullString+" actual: "+full, w))
										} else {
											// rdnsMatch := reverseDNSString==rDNS // TODO LATER reinstate
											//if(!rdnsMatch) {
											//	t.addFailure(newFailure("failed expected: " + reverseDNSString + " actual: " + rDNS, w));
											//} else {
											//	 uncMatch := uncHostString==unc
											//	if(!uncMatch) {
											//		t.addFailure(newFailure("failed expected: " + uncHostString + " actual: " + unc, w));
											//	}
											//}
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}
	//} catch(RuntimeException e) {
	//	addFailure(new Failure("unexpected throw: " + e));
	//}
	t.incrementTestCount()
}

func (t testBase) testCountRedirect(w ipaddr.ExtendedIdentifierString, number uint64, excludeZerosNumber uint64) {
	t.testCountImpl(w, number, false)
	if excludeZerosNumber != math.MaxUint64 { // this is used to filter out mac tests
		t.testCountImpl(w, excludeZerosNumber, true)
	}
}

func (t testBase) testCountImpl(w ipaddr.ExtendedIdentifierString, number uint64, excludeZeroHosts bool) {
	if !t.fullTest && number > countLimit {
		return
	}
	val := w.GetAddress()
	var count *big.Int
	if excludeZeroHosts {
		count = getNonZeroHostCount(val.ToAddress().ToIPAddress())
	} else {
		count = val.GetCount()
	}
	//BigInteger count = excludeZeroHosts ? ((IPAddress)val).getNonZeroHostCount() : val.getCount(); // non zero host count: check if includesZeroHost, and if not, 0, if so, then get prefix count, subtract from total count
	var set []ipaddr.AddressItem
	//Set<AddressItem> set = new HashSet<AddressItem>();
	if count.Cmp(new(big.Int).SetUint64(number)) != 0 {
		//IPAddressString w3 = t.createAddress(w.toString());
		//Address val3 = w3.getAddress();
		//count = excludeZeroHosts ? ((IPAddress)val3).getNonZeroHostCount() : val3.getCount();
		t.addFailure(newSegmentSeriesFailure("count was "+count.String()+" instead of expected count "+strconv.FormatUint(number, 10), val))
	} else {
		var addrIterator ipaddr.AddressIterator
		if excludeZeroHosts {
			addrIterator = ipaddr.UnwrappedIPddressIterator{ipaddr.NewFilteredIPAddrIterator(val.ToAddress().ToIPAddress().Iterator(), (*ipaddr.IPAddress).IsZeroHost)} // need to create a iterator that takes a functor to alter an existing iterator, FilteredIPAddrIterator
		} else {
			addrIterator = val.ToAddress().Iterator()
		}
		//Iterator<? extends Address> addrIterator = excludeZeroHosts ? ((IPAddress)val).nonZeroHostIterator() : val.iterator();
		var counter uint64
		var next *ipaddr.Address
		for addrIterator.HasNext() {
			next = addrIterator.Next()
			if counter == 0 {
				lower := val.ToAddress().GetLower()
				if excludeZeroHosts {
					if lower.ToIPAddress().IsZeroHost() && next.Equals(lower) {
						t.addFailure(newIPAddrFailure("lowest: "+lower.String()+" next: "+next.String(), next.ToIPAddress()))
					}
				} else {
					if !next.Equals(lower) {
						t.addFailure(newSegmentSeriesFailure("lowest: "+lower.String()+" next: "+next.String(), next))
					}
				}

				if !next.GetPrefixLen().Equals(val.GetPrefixLen()) {
					t.addFailure(newSegmentSeriesFailure("val prefix length: "+val.GetPrefixLen().String()+" upper prefix length: "+next.GetPrefixLen().String(), next))
				}
				if !lower.GetPrefixLen().Equals(val.GetPrefixLen()) {
					t.addFailure(newSegmentSeriesFailure("val prefix length: "+val.GetPrefixLen().String()+" lowest prefix length: "+lower.GetPrefixLen().String(), lower))
				}
			} else if counter == 1 {
				if !next.GetPrefixLen().Equals(val.GetPrefixLen()) {
					t.addFailure(newSegmentSeriesFailure("val prefix length: "+val.GetPrefixLen().String()+" upper prefix length: "+next.GetPrefixLen().String(), next))
				}
			}
			set = append(set, next)
			counter++
		}
		if number < uint64(maxInt) && len(set) != int(number) {
			t.addFailure(newSegmentSeriesFailure("set count was "+strconv.Itoa(len(set))+" instead of expected "+strconv.FormatUint(number, 10), val.ToAddress()))
		} else if counter != number {
			t.addFailure(newSegmentSeriesFailure("set count was "+strconv.Itoa(len(set))+" instead of expected "+strconv.FormatUint(number, 10), val.ToAddress()))
		} else if number > 0 {
			if !next.Equals(val.ToAddress().GetUpper()) {
				t.addFailure(newSegmentSeriesFailure("highest: "+val.ToAddress().GetUpper().String(), next))
			} else {
				lower := val.ToAddress().GetLower()
				if counter == 1 && !val.ToAddress().GetUpper().Equals(lower) {
					t.addFailure(newSegmentSeriesFailure("highest: "+val.ToAddress().GetUpper().String()+" lowest: "+val.ToAddress().GetLower().String(), next))
				}
				if !next.GetPrefixLen().Equals(val.GetPrefixLen()) {
					t.addFailure(newSegmentSeriesFailure("val prefix length: "+val.GetPrefixLen().String()+" upper prefix length: "+next.GetPrefixLen().String(), next))
				}
				if !val.ToAddress().GetUpper().GetPrefixLen().Equals(val.GetPrefixLen()) {
					t.addFailure(newSegmentSeriesFailure("val prefix length: "+val.GetPrefixLen().String()+" upper prefix length: "+val.ToAddress().GetUpper().GetPrefixLen().String(), next))
				}
			}
		} else {
			if excludeZeroHosts {
				if !val.ToAddress().ToIPAddress().IsZeroHost() {
					t.addFailure(newSegmentSeriesFailure("unexpected non-zero-host: "+val.ToAddress().ToIPAddress().String(), val))
				}
			} else {
				t.addFailure(newSegmentSeriesFailure("unexpected zero count ", val))
			}
		}

		//if(!excludeZeroHosts){
		//
		//	//				Function<Address, Spliterator<? extends AddressItem>> spliteratorFunc = excludeZeroHosts ?
		//	//						addr -> ((IPAddress)addr).nonZeroHostSpliterator() : Address::spliterator;
		//	Function<Address, AddressComponentRangeSpliterator<?,? extends AddressItem>> spliteratorFunc = Address::spliterator;
		//
		//	testSpliterate(t, val, 0, number, spliteratorFunc);
		//	testSpliterate(t, val, 1, number, spliteratorFunc);
		//	testSpliterate(t, val, 8, number, spliteratorFunc);
		//	testSpliterate(t, val, -1, number, spliteratorFunc);
		//
		//	testStream(t, val, set, Address::stream);
		//
		//	AddressSection section = val.getSection();
		//
		//	//				Function<AddressSection, Spliterator<? extends AddressItem>> sectionFunc = excludeZeroHosts ?
		//	//						addr -> ((IPAddressSection)section).nonZeroHostSpliterator() : AddressSection::spliterator;
		//	Function<AddressSection, AddressComponentRangeSpliterator<?,? extends AddressItem>> sectionFunc = AddressSection::spliterator;
		//
		//	testSpliterate(t, section, 0, number, sectionFunc);
		//	testSpliterate(t, section, 1, number, sectionFunc);
		//	testSpliterate(t, section, 2, number, sectionFunc);
		//	set = testSpliterate(t, section, 7, number, sectionFunc);
		//	testSpliterate(t, section, -1, number, sectionFunc);
		//
		//	testStream(t, section, set, AddressSection::stream);
		//
		//	Set<AddressItem> createdSet = null;
		//	if(section instanceof IPv6AddressSection) {
		//		createdSet = ((IPv6AddressSection) section).segmentsStream().map(IPv6AddressSection::new).collect(Collectors.toSet());
		//	} else if(section instanceof IPv4AddressSection) {
		//		createdSet = ((IPv4AddressSection) section).segmentsStream().map(IPv4AddressSection::new).collect(Collectors.toSet());
		//	} else if(section instanceof MACAddressSection) {
		//		createdSet = ((MACAddressSection) section).segmentsStream().map(MACAddressSection::new).collect(Collectors.toSet());
		//	}
		//
		//	testStream(t, section, createdSet, AddressSection::stream);
		//
		//}
	}
	t.incrementTestCount()
}

const (
	intSize = 32 << (^uint(0) >> 63) // 32 or 64
	maxInt  = 1<<uint(intSize-1) - 1
)

func (t testBase) testPrefixCountImpl(w ipaddr.ExtendedIdentifierString, number uint64) {
	if !t.fullTest && number > countLimit {
		return
	}
	val := w.GetAddress()
	_, isIp := val.(*ipaddr.IPAddress)
	isPrefixed := val.IsPrefixed()
	count := val.GetPrefixCount()
	var prefixSet, prefixBlockSet []ipaddr.AddressItem
	//HashSet<AddressItem> prefixSet = new HashSet<AddressItem>();
	//HashSet<AddressItem> prefixBlockSet = new HashSet<AddressItem>();
	if count.Cmp(new(big.Int).SetUint64(number)) != 0 {
		t.addFailure(newSegmentSeriesFailure("count was "+count.String()+" instead of expected count "+strconv.FormatUint(number, 10), val))
	} else {
		loopCount := 0
		totalCount := val.GetCount()
		var countedCount *big.Int
		originalIsPrefixBlock := val.IsPrefixBlock()
		for loopCount++; loopCount <= 2; loopCount++ {
			countedCount = bigZero()
			isBlock := loopCount == 1
			var addrIterator ipaddr.AddressIterator
			var set []ipaddr.AddressItem
			if isBlock {
				set = prefixBlockSet
				addrIterator = val.ToAddress().PrefixBlockIterator()
			} else {
				set = prefixSet
				addrIterator = val.ToAddress().PrefixIterator()
			}
			var counter uint64
			var previous, next *ipaddr.Address
			for addrIterator.HasNext() {
				next = addrIterator.Next()
				if isBlock || (originalIsPrefixBlock && previous != nil && addrIterator.HasNext()) {
					if isPrefixed {
						if !next.IsPrefixBlock() {
							t.addFailure(newSegmentSeriesFailure("not prefix block next: "+next.String(), next))
							break
						}
						if !next.IsSinglePrefixBlock() {
							t.addFailure(newSegmentSeriesFailure("not single prefix block next: "+next.String(), next))
							break
						}
					} else {
						if next.IsPrefixBlock() {
							t.addFailure(newSegmentSeriesFailure("not prefix block next: "+next.String(), next))
							break
						}
						if next.IsPrefixBlock() {
							t.addFailure(newSegmentSeriesFailure("not single prefix block next: "+next.String(), next))
							break
						}
					}
				}
				if !isBlock {
					countedCount.Add(countedCount, next.GetCount())
				}
				if isIp && previous != nil {
					if next.ToIPAddress().Intersect(previous.ToIPAddress()) != nil {
						t.addFailure(newSegmentSeriesFailure("intersection of "+previous.String()+" when iterating: "+next.ToIPAddress().Intersect(previous.ToIPAddress()).String(), next))
						break
					}
				}
				set = append(set, next)

				counter++
				previous = next
			}
			if number < uint64(maxInt) && len(set) != int(number) {
				t.addFailure(newSegmentSeriesFailure("set count was "+strconv.Itoa(len(set))+" instead of expected "+strconv.FormatUint(number, 10), val.ToAddress()))
			} else if counter != number {
				t.addFailure(newSegmentSeriesFailure("set count was "+strconv.Itoa(len(set))+" instead of expected "+strconv.FormatUint(number, 10), val.ToAddress()))
			} else if number < 0 {
				t.addFailure(newSegmentSeriesFailure("unexpected zero count ", val.ToAddress()))
			} else if !isBlock && countedCount.Cmp(totalCount) != 0 {
				t.addFailure(newSegmentSeriesFailure("count mismatch, expected "+totalCount.String()+" got "+countedCount.String(), val.ToAddress()))
			}

			//	Function<Address, AddressComponentRangeSpliterator<?,? extends AddressItem>> spliteratorFunc = isBlock ?
			//Address::prefixBlockSpliterator : Address::prefixSpliterator;
			//
			//	testSpliterate(t, val, 0, number, spliteratorFunc);
			//	testSpliterate(t, val, 1, number, spliteratorFunc);
			//	testSpliterate(t, val, 8, number, spliteratorFunc);
			//	testSpliterate(t, val, -1, number, spliteratorFunc);
			//
			//	if(isIp && isPrefixed) {
			//		// use val to indicate prefix length,
			//		// but we actually iterate on a value with different prefix length, while assigning the prefix length with the spliterator call
			//		IPAddress ipAddr = ((IPAddress) val);
			//		Integer prefLength = ipAddr.getPrefixLength();
			//		IPAddress iteratedVal = null;
			//		if(prefLength >= val.getBitCount() - 3) {
			//			if(!val.getNetwork().getPrefixConfiguration().allPrefixedAddressesAreSubnets()) {
			//				iteratedVal = ipAddr.setPrefixLength(prefLength - 3, false, false);
			//			}
			//		} else {
			//			iteratedVal = ipAddr.adjustPrefixLength(3, false);
			//		}
			//
			//
			//		if(iteratedVal != null) {
			//			IPAddress ival = iteratedVal;
			//			spliteratorFunc = isBlock ? addr -> ival.prefixBlockSpliterator(prefLength):
			//			addr -> ival.prefixSpliterator(prefLength);
			//
			//			testSpliterate(t, val, 0, number, spliteratorFunc);
			//			testSpliterate(t, val, 1, number, spliteratorFunc);
			//			testSpliterate(t, val, 3, number, spliteratorFunc);
			//		}
			//	}
		}
		//testStream(t, val, prefixSet, Address::prefixStream);
		//testStream(t, val, prefixBlockSet, Address::prefixBlockStream);
	}
	// segment tests
	//AddressSegment lastSeg = null;
	//for(int i = 0; i < val.getSegmentCount(); i++) {// note this can be a little slow with IPv6
	//	AddressSegment seg = val.getSegment(i);
	//if(i == 0 || !seg.equals(lastSeg)) {
	//Function<AddressSegment, AddressComponentRangeSpliterator<?,? extends AddressItem>> funct = segm -> segm.spliterator();
	//int segCount = seg.getValueCount();
	//Set<AddressItem> segmentSet = testSpliterate(t, seg, 0, segCount, funct);
	//testSpliterate(t, seg, 1, segCount, funct);
	//testSpliterate(t, seg, 8, segCount, funct);
	//testSpliterate(t, seg, -1, segCount, funct);
	//
	//testStream(t, seg, segmentSet, AddressSegment::stream);
	//
	//if(seg instanceof IPAddressSegment) {
	//	IPAddressSegment ipseg = ((IPAddressSegment)seg);
	//	if(ipseg.isPrefixed()) {
	//		Function<IPAddressSegment, AddressComponentRangeSpliterator<?,? extends AddressItem>> func = segm -> segm.prefixSpliterator();
	//		segCount = ipseg.getPrefixValueCount();
	//		testSpliterate(t, ipseg, 0, segCount, func);
	//		testSpliterate(t, ipseg, 1, segCount, func);
	//		segmentSet = testSpliterate(t, ipseg, 8, segCount, func);
	//		testSpliterate(t, ipseg, -1, segCount, func);
	//
	//		testStream(t, ipseg, segmentSet, IPAddressSegment::prefixStream);
	//
	//		func = segm -> segm.prefixBlockSpliterator();
	//		testSpliterate(t, ipseg, 0, segCount, func);
	//		testSpliterate(t, ipseg, 1, segCount, func);
	//		testSpliterate(t, ipseg, 8, segCount, func);
	//		segmentSet = testSpliterate(t, ipseg, -1, segCount, func);
	//
	//		testStream(t, ipseg, segmentSet, IPAddressSegment::prefixBlockStream);
	//	}
	//}
	//}
	//lastSeg = seg;
	//}
	t.incrementTestCount()
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

type failure struct {
	str string

	addr       *ipaddr.IPAddress
	addrStr    *ipaddr.IPAddressString
	macAddr    *ipaddr.MACAddress
	macAddrStr *ipaddr.MACAddressString
	rng        *ipaddr.IPAddressSeqRange
	//ipseries   ipaddr.ExtendedIPSegmentSeries
	//exseries     ipaddr.ExtendedSegmentSeries
	series ipaddr.AddressSegmentSeries //TODO fold the addresses into this
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

func newSegmentSeriesFailure(str string, series ipaddr.AddressSegmentSeries) failure {
	return failure{
		str:    str,
		series: series,
	}
}

func newSeqRangeFailure(str string, rng *ipaddr.IPAddressSeqRange) failure {
	return failure{
		str: str,
		rng: rng,
	}
}

//func newSegmentSeriesFailure(str string, series ipaddr.ExtendedSegmentSeries) failure {
//	return failure{
//		str:    str,
//		series: series,
//	}
//}
//
//func newSegmentSeriesFailure(str string, series ipaddr.ExtendedIPSegmentSeries) failure {
//	return failure{
//		str:      str,
//		series: series,
//	}
//}

var cachedPrefixLens = initPrefLens()

func initPrefLens() []ipaddr.PrefixLen {
	cachedPrefLens := make([]ipaddr.PrefixLen, ipaddr.IPv6BitCount+1)
	for i := ipaddr.BitCount(0); i <= ipaddr.IPv6BitCount; i++ {
		bc := i
		cachedPrefLens[i] = &bc
	}
	return cachedPrefLens
}

//var px = ipaddr.PrefixX{}
//var one ipaddr.BitCount = 1
//var px = ipaddr.PrefixX{&one}

var (
	p0   = cacheTestBits(0)
	p4   = cacheTestBits(4)
	p8   = cacheTestBits(8)
	p9   = cacheTestBits(9)
	p11  = cacheTestBits(11)
	p15  = cacheTestBits(15)
	p16  = cacheTestBits(16)
	p17  = cacheTestBits(17)
	p23  = cacheTestBits(23)
	p24  = cacheTestBits(24)
	p31  = cacheTestBits(31)
	p32  = cacheTestBits(32)
	p33  = cacheTestBits(33)
	p48  = cacheTestBits(48)
	p49  = cacheTestBits(49)
	p56  = cacheTestBits(56)
	p63  = cacheTestBits(63)
	p64  = cacheTestBits(64)
	p65  = cacheTestBits(65)
	p97  = cacheTestBits(97)
	p104 = cacheTestBits(104)
	p112 = cacheTestBits(112)
	p127 = cacheTestBits(127)
	p128 = cacheTestBits(128)
)

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

func bigZero() *big.Int {
	return new(big.Int)
}

var zero = bigZero()

func bigZeroConst() *big.Int {
	return zero
}
