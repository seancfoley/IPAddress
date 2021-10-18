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
	macTester := macAddressTester{testBase{testResults: &acc, testAddresses: &addresses}}
	tester.run()
	macTester.run()

	rangedAddresses := rangedAddresses{addresses}
	rangeTester := ipAddressRangeTester{ipAddressTester{testBase{testResults: &acc, testAddresses: &rangedAddresses, fullTest: fullTest}}}
	macRangeTester := macAddressRangeTester{macAddressTester{testBase{testResults: &acc, testAddresses: &rangedAddresses}}}
	rangeTester.run()
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
