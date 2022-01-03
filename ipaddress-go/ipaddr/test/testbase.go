//
// Copyright 2020-2022 Sean C Foley
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package test

import (
	"fmt"
	"math"
	"math/big"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/seancfoley/ipaddress/ipaddress-go/ipaddr"
	"github.com/seancfoley/ipaddress/ipaddress-go/ipaddr/addrstr"
	"github.com/seancfoley/ipaddress/ipaddress-go/ipaddr/addrstrparam"
)

func Test(isLimited bool) {
	acc := testAccumulator{lock: &sync.Mutex{}}
	var addresses addresses
	fullTest := false
	fmt.Println("Starting TestRunner")
	startTime := time.Now()

	rangedAddresses := rangedAddresses{addresses: addresses}

	allAddresses := allAddresses{rangedAddresses: rangedAddresses}

	if isLimited {
		acc = testAll(addresses, rangedAddresses, allAddresses, fullTest)
	} else {
		// warm up
		acc = testAll(addresses, rangedAddresses, allAddresses, fullTest)
		allAddresses.useCache(true)
		routineCount := 100
		var wg sync.WaitGroup
		wg.Add(routineCount)
		for i := 0; i < routineCount; i++ {
			go func() {
				defer wg.Done()
				newAcc := testAll(addresses, rangedAddresses, allAddresses, fullTest)
				acc.add(newAcc)
			}()
		}
		wg.Wait()
	}

	endTime := time.Now().Sub(startTime)
	fmt.Printf("TestRunner\ntest count: %d\nfail count: %d\n", acc.counter, len(acc.failures))
	if len(acc.failures) > 0 {
		fmt.Printf("%v\n", acc.failures)
	}
	fmt.Printf("Done: TestRunner\nDone in %v\n", endTime)
}

func testAll(addresses addresses, rangedAddresses rangedAddresses, allAddresses allAddresses, fullTest bool) testAccumulator {
	acc := testAccumulator{lock: &sync.Mutex{}}

	tester := ipAddressTester{testBase{testResults: &acc, testAddresses: &addresses, fullTest: fullTest}}
	tester.run()

	hTester := hostTester{testBase{testResults: &acc, testAddresses: &addresses, fullTest: fullTest}}
	hTester.run()

	macTester := macAddressTester{testBase{testResults: &acc, testAddresses: &addresses}}
	macTester.run()

	rangeTester := ipAddressRangeTester{ipAddressTester{testBase{testResults: &acc, testAddresses: &rangedAddresses, fullTest: fullTest}}}
	rangeTester.run()

	hostRTester := hostRangeTester{hostTester{testBase{testResults: &acc, testAddresses: &rangedAddresses, fullTest: fullTest}}}
	hostRTester.run()

	macRangeTester := macAddressRangeTester{macAddressTester{testBase{testResults: &acc, testAddresses: &rangedAddresses}}}
	macRangeTester.run()

	allTester := ipAddressAllTester{ipAddressRangeTester{ipAddressTester{testBase{testResults: &acc, testAddresses: &allAddresses, fullTest: fullTest}}}}
	allTester.run()

	hostATester := hostAllTester{hostRangeTester{hostTester{testBase{testResults: &acc, testAddresses: &rangedAddresses, fullTest: fullTest}}}}
	hostATester.run()

	sTypesTester := specialTypesTester{testBase{testResults: &acc, testAddresses: &addresses, fullTest: fullTest}}
	sTypesTester.run()

	addressOrderTester := addressOrderTest{testBase{testResults: &acc, testAddresses: &addresses, fullTest: fullTest}}
	addressOrderTester.run()

	return acc
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
	lock     *sync.Mutex
}

func (t *testAccumulator) add(other testAccumulator) {
	t.lock.Lock()
	t.failures = append(t.failures, other.failures...)
	t.counter += other.counter
	//fmt.Printf("added %d to get %d in counter\n", other.counter, t.counter)
	t.lock.Unlock()
}

func (t *testAccumulator) addFailure(f failure) {
	t.failures = append(t.failures, f)
}

func (t *testAccumulator) incrementTestCount() {
	t.counter++
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
		if !seg0.Equal(seg1) {
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
	if !series.Equal(bytesReversed) {
		t.addFailure(newSegmentSeriesFailure("bytes reversal: "+series.String(), series))
		return
	}
	bitsReversed, err := series.ReverseBits(false)
	if err != nil {
		t.addFailure(newSegmentSeriesFailure("failed "+err.Error(), series))
		return
	}
	var equalityResult = series.Equal(bitsReversed)
	if bitsReversedIsSame {
		equalityResult = !equalityResult
	}
	if equalityResult {
		t.addFailure(newSegmentSeriesFailure("bit reversal 2a: "+series.String()+" "+bitsReversed.String(), series))
		return
	}
	bitsReversed, err = bitsReversed.ReverseBits(false)
	if err != nil {
		t.addFailure(newSegmentSeriesFailure("failed "+err.Error(), series))
		return
	}
	if !series.Equal(bitsReversed) {
		t.addFailure(newSegmentSeriesFailure("bit reversal 2: "+series.String(), series))
		return
	}

	bitsReversed2, err := series.ReverseBits(true)
	if err != nil {
		t.addFailure(newSegmentSeriesFailure("failed "+err.Error(), series))
		return
	}
	equalityResult = series.Equal(bitsReversed2)
	if bitsReversedPerByteIsSame {
		equalityResult = !equalityResult
	}
	if equalityResult {
		t.addFailure(newSegmentSeriesFailure("bit reversal 3a: "+series.String(), series))
		return
	}
	bitsReversed2, err = bitsReversed2.ReverseBits(true)
	if err != nil {
		t.addFailure(newSegmentSeriesFailure("failed "+err.Error(), series))
		return
	}
	if !series.Equal(bitsReversed2) {
		t.addFailure(newSegmentSeriesFailure("bit reversal 3: "+series.String(), series))
		return
	}

	bytes := series.Bytes() // ab cd ef becomes fe dc ba
	bitsReversed3, err := series.ReverseBytes()
	if err != nil {
		t.addFailure(newSegmentSeriesFailure("failed "+err.Error(), series))
		return
	}
	for i, j := 0, len(bytes)-1; i < bitsReversed3.GetSegmentCount(); i++ {
		seg := bitsReversed3.GetSegment(i)
		segBytes := seg.Bytes()
		if !seg.IsMultiple() {
			bytesLen := len(segBytes) >> 1
			last := len(segBytes) - 1
			for m := 0; m < bytesLen; m++ {
				first, lastByte := segBytes[m], segBytes[last-m]
				segBytes[m], segBytes[last-m] = lastByte, first
			}
		}
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
		} else {
			removed, err = original.AdjustPrefixLenZeroed(original.GetBitCount())
		}
		if err != nil {
			t.addFailure(newSegmentSeriesFailure("removed prefix error: "+err.Error(), original))
			break
		}
		if original.IsPrefixed() {
			prefLength := original.GetPrefixLen().Len()
			bitsSoFar := ipaddr.BitCount(0)
			for i := 0; i < removed.GetSegmentCount(); i++ {
				prevBitsSoFar := bitsSoFar
				seg := removed.GetSegment(i)
				bitsSoFar += seg.GetBitCount()
				if prefLength >= bitsSoFar {
					if !seg.Equal(original.GetSegment(i)) {
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
						t.addFailure(newSegmentSeriesFailure("prefix app: "+removed.String()+" "+strconv.Itoa(int(lower&mask))+" "+strconv.Itoa(int(upper&mask)), original))
						break
					}
				}
			}
		} else if !removed.Equal(original) {
			t.addFailure(newSegmentSeriesFailure("prefix removed: "+removed.String(), original))
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
		} else {
			removed, err = original.AdjustPrefixLenZeroed(original.GetBitCount())
		}
		if err != nil {
			t.addFailure(newSegmentSeriesFailure("removed prefix error: "+err.Error(), original))
			break
		}
		if original.IsPrefixed() {
			prefLength := original.GetPrefixLen().Len()
			bitsSoFar := ipaddr.BitCount(0)
			for i := 0; i < removed.GetSegmentCount(); i++ {
				prevBitsSoFar := bitsSoFar
				seg := removed.GetSegment(i)
				bitsSoFar += seg.GetBitCount()
				if prefLength >= bitsSoFar {
					if !seg.Equal(original.GetSegment(i)) {
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
		} else if !removed.Equal(original) {
			t.addFailure(newSegmentSeriesFailure("prefix removed: "+removed.String(), original))
		}
	}
	var adjustedSeries ipaddr.ExtendedIPSegmentSeries
	adjustedSeries, err := original.AdjustPrefixLenZeroed(adjustment)
	if err != nil {
		t.addFailure(newSegmentSeriesFailure("adjusted prefix error: "+err.Error(), original))
		return
	}
	adjustedPrefix := adjustedSeries.GetPrefixLen()
	if (original.IsPrefixed() && adjustedPrefix.Matches(original.GetBitCount()+adjustment)) ||
		(!original.IsPrefixBlock() && adjustedSeries.IsZeroHost()) { //xxxxx if we do not have prefix block, then our positive adjustment creates what would be one, then our expected is one which is wrong
		// all host bits of matching address are zeroed out, so we must get the zero host and not the prefix subnet
		adjusted, err = adjusted.ToZeroHost()
		if err != nil {
			t.addFailure(newSegmentSeriesFailure("adjusted prefix error: "+err.Error(), original))
			return
		}
	}

	if !adjustedSeries.Equal(adjusted) {
		t.addFailure(newSegmentSeriesFailure("prefix adjusted: "+adjustedSeries.String(), adjusted))
		_, _ = original.AdjustPrefixLenZeroed(adjustment)
	} else {
		adjustedSeries, err = original.SetPrefixLenZeroed(prefix)
		if err != nil {
			t.addFailure(newSegmentSeriesFailure("set prefix error: "+err.Error(), original))
			return
		}
		if (original.IsPrefixed() && original.GetPrefixLen().Matches(original.GetBitCount())) ||
			(!original.IsPrefixBlock() && adjustedSeries.IsZeroHost()) {
			// all host bits of matching address are zeroed out, so we must get the zero host and not the prefix subnet
			prefixSet, err = prefixSet.ToZeroHost()
			if err != nil {
				t.addFailure(newSegmentSeriesFailure("set prefix error: "+err.Error(), original))
				return
			}
		}

		setPrefix := adjustedSeries.GetPrefixLen()
		if !adjustedSeries.Equal(prefixSet) {
			fmt.Println(original.String() + " set: " + adjustedSeries.String() + " expected: " + prefixSet.String() + " set prefix: " + bitCountToString(prefix))
			t.addFailure(newSegmentSeriesFailure("prefix set: "+adjustedSeries.String(), prefixSet))
		} else {
			originalPref := original.GetPrefixLen()
			var expected ExpectedPrefixes
			bitLength := original.GetBitCount()
			if originalPref == nil {
				if adjustment <= 0 {
					expected.adjusted = cacheTestBits(bitLength + adjustment)
				} else {
					expected.adjusted = cacheTestBits(adjustment)
				}
				expected.set = cacheTestBits(prefix)
			} else {
				adj := min(max(0, originalPref.Len()+adjustment), original.GetBitCount())
				expected.adjusted = cacheTestBits(adj)
				expected.set = cacheTestBits(prefix)
			}
			if !expected.compare(adjustedPrefix, setPrefix) {
				t.addFailure(newSegmentSeriesFailure("expected: "+expected.adjusted.String()+" actual "+adjustedPrefix.String()+" expected: "+expected.set.String()+" actual "+setPrefix.String(), original))
			}
		}
	}
}

func (t testBase) testReplace(front, back *ipaddr.Address, fronts, backs []string, sep byte, isMac bool) {
	bitsPerSegment := front.GetBitsPerSegment()
	segmentCount := front.GetSegmentCount()
	isIpv4 := !isMac && segmentCount == ipaddr.IPv4SegmentCount
	prefixes := strings.Builder{}
	prefixes.WriteString("[\n")
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
				if frontPrefixed && (front.GetPrefixLen().Len() <= ipaddr.BitCount(replaceTargetIndex)*bitsPerSegment) && (isMac || replaceTargetIndex > 0) { //when replaceTargetIndex is 0, slight difference between mac and ipvx, for ipvx we do not account for a front prefix of 0
					prefix = front.GetPrefixLen()
				} else if back.IsPrefixed() && (back.GetPrefixLen().Len() <= ipaddr.BitCount(replaceSourceIndex+replaceCount)*bitsPerSegment) && (isMac || replaceCount > 0) { //when replaceCount 0, slight difference between mac and ipvx, for ipvx we do not account for a back prefix
					prefix = cacheTestBits((ipaddr.BitCount(replaceTargetIndex) * bitsPerSegment) + max(0, back.GetPrefixLen().Len()-(ipaddr.BitCount(replaceSourceIndex)*bitsPerSegment)))
				} else if frontPrefixed {
					if front.GetPrefixLen().Len() <= ipaddr.BitCount(replaceTargetIndex+replaceCount)*bitsPerSegment {
						prefix = cacheTestBits(ipaddr.BitCount(replaceTargetIndex+replaceCount) * bitsPerSegment)
					} else {
						prefix = front.GetPrefixLen()
					}
				}
				replaceStr := " replacing " + strconv.Itoa(replaceCount) + " segments in " + front.String() + " at index " + strconv.Itoa(replaceTargetIndex) +
					" with segments from " + back.String() + " starting at " + strconv.Itoa(replaceSourceIndex)

				var new1, new2 *ipaddr.Address
				if isMac {
					fromMac := front.ToMAC()
					new1 = fromMac.ReplaceLen(replaceTargetIndex, replaceTargetIndex+replaceCount, back.ToMAC(), replaceSourceIndex).ToAddressBase()
					hostIdStr := t.createMACAddress(str.String())
					new2 = hostIdStr.GetAddress().ToAddressBase()
					if prefix != nil {
						new2 = new2.SetPrefixLen(prefix.Len())
					}
				} else {
					if prefix != nil {
						str.WriteByte('/')
						str.WriteString(prefix.String())
					}
					hostIdStr := t.createAddress(str.String())
					new2 = hostIdStr.GetAddress().ToAddressBase()
					if isIpv4 {
						frontIPv4 := front.ToIPv4()
						new1 = frontIPv4.ReplaceLen(replaceTargetIndex, replaceTargetIndex+replaceCount, back.ToIPv4(), replaceSourceIndex).ToAddressBase()
					} else {
						frontIPv6 := front.ToIPv6()
						new1 = frontIPv6.ReplaceLen(replaceTargetIndex, replaceTargetIndex+replaceCount, back.ToIPv6(), replaceSourceIndex).ToAddressBase()
					}
				}
				if !new1.Equal(new2) {
					failStr := "Replacement was " + new1.String() + " expected was " + new2.String() + " " + replaceStr
					t.addFailure(newIPAddrFailure(failStr, front.ToIP()))

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

		var mixed, mixed2 *ipaddr.Address
		if isMac {
			hostIdStr := t.createMACAddress(str.String())
			mixed = hostIdStr.GetAddress().ToAddressBase()
			ignoreFrontPrefLen := i == 0 // we ignore the front prefix len if we are taking 0 bits from the front
			if !ignoreFrontPrefLen && front.IsPrefixed() && front.GetPrefixLen().Len() <= ipaddr.BitCount(i)*bitsPerSegment {
				mixed = mixed.SetPrefixLen(front.GetPrefixLen().Len())
			} else if back.IsPrefixed() {
				mixed = mixed.SetPrefixLen(max(ipaddr.BitCount(i)*bitsPerSegment, back.GetPrefixLen().Len()))
			}
			sec := frontSection.ToMAC().Append(backSection.ToMAC())
			mixed2x, err := ipaddr.NewMACAddress(sec)
			if err != nil {
				t.addFailure(newSegmentSeriesFailure("unexpected error: "+err.Error(), sec))
			}
			mixed2 = mixed2x.ToAddressBase()

			if frontSectionInvalid != nil && backSectionInvalid != nil {
				//This doesn't fail anymore because we allow large sections
				newSec := (frontSection.ToMAC()).Append(backSectionInvalid.ToMAC())
				if newSec.GetSegmentCount() != frontSection.GetSegmentCount()+backSectionInvalid.GetSegmentCount() {
					t.addFailure(newSegmentSeriesFailure("unexpected seg count: "+strconv.Itoa(newSec.GetSegmentCount()), newSec))
				}
				newSec = (frontSectionInvalid.ToMAC()).Append(backSection.ToMAC())
				if newSec.GetSegmentCount() != frontSectionInvalid.GetSegmentCount()+backSection.GetSegmentCount() {
					t.addFailure(newSegmentSeriesFailure("unexpected seg count: "+strconv.Itoa(newSec.GetSegmentCount()), newSec))
				}
			}
			for o := 0; o < len(splits); o++ {
				split := splits[o]
				f := split[0]
				g := split[1]
				h := split[2]
				sec = f.ToMAC().Append(h.ToMAC())
				sec = sec.Insert(f.GetSegmentCount(), g.ToMAC())
				if h.IsPrefixed() && h.GetPrefixLen().Len() == 0 && !f.IsPrefixed() {
					gPref := ipaddr.BitCount(g.GetSegmentCount()) * ipaddr.MACBitsPerSegment
					if g.IsPrefixed() {
						gPref = g.GetPrefixLen().Len()
					}
					sec = sec.SetPrefixLen(ipaddr.BitCount(f.GetSegmentCount())*ipaddr.MACBitsPerSegment + gPref)
				}
				mixed3, err := ipaddr.NewMACAddress(sec)
				if err != nil {
					t.addFailure(newSegmentSeriesFailure("unexpected error: "+err.Error(), sec))
				}
				splitsJoined = append(splitsJoined, mixed3.ToAddressBase())
			}
		} else {
			if front.IsPrefixed() && front.GetPrefixLen().Len() <= (ipaddr.BitCount(i)*bitsPerSegment) && i > 0 {
				str.WriteByte('/')
				str.WriteString(strconv.Itoa(int(front.GetPrefixLen().Len())))
			} else if back.IsPrefixed() {
				str.WriteByte('/')
				if ipaddr.BitCount(i)*bitsPerSegment > back.GetPrefixLen().Len() {
					str.WriteString(strconv.Itoa(i * int(bitsPerSegment)))
				} else {
					str.WriteString(strconv.Itoa(int(back.GetPrefixLen().Len())))
				}
			}
			hostIdStr := t.createAddress(str.String())
			mixed = hostIdStr.GetAddress().ToAddressBase()

			if isIpv4 {
				sec := (frontSection.ToIPv4()).Append(backSection.ToIPv4())
				mixed2x, err := ipaddr.NewIPv4Address(sec)
				if err != nil {
					t.addFailure(newSegmentSeriesFailure("unexpected error: "+err.Error(), sec))
				}
				mixed2 = mixed2x.ToAddressBase()

				if frontSectionInvalid != nil && backSectionInvalid != nil {
					newSec := (frontSection.ToIPv4()).Append(backSectionInvalid.ToIPv4())
					if newSec.GetSegmentCount() != frontSection.GetSegmentCount()+backSectionInvalid.GetSegmentCount() {
						t.addFailure(newSegmentSeriesFailure("unexpected seg count: "+strconv.Itoa(newSec.GetSegmentCount()), newSec))
					}
					newSec = (frontSectionInvalid.ToIPv4()).Append(backSection.ToIPv4())
					if newSec.GetSegmentCount() != frontSectionInvalid.GetSegmentCount()+backSection.GetSegmentCount() {
						t.addFailure(newSegmentSeriesFailure("unexpected seg count: "+strconv.Itoa(newSec.GetSegmentCount()), newSec))
					}
				}
				for o := 0; o < len(splits); o++ {
					split := splits[o]
					f := split[0]
					g := split[1]
					h := split[2]
					sec = (f.ToIPv4()).Append(h.ToIPv4())
					sec = sec.Insert(f.GetSegmentCount(), g.ToIPv4())
					if h.IsPrefixed() && h.GetPrefixLen().Len() == 0 && !f.IsPrefixed() {
						gPref := ipaddr.BitCount(g.GetSegmentCount()) * ipaddr.IPv4BitsPerSegment
						if g.IsPrefixed() {
							gPref = g.GetPrefixLen().Len()
						}
						sec = sec.SetPrefixLen(ipaddr.BitCount(f.GetSegmentCount())*ipaddr.IPv4BitsPerSegment + gPref)
					}
					mixed3, err := ipaddr.NewIPv4Address(sec)
					if err != nil {
						t.addFailure(newSegmentSeriesFailure("unexpected error: "+err.Error(), sec))
					}
					splitsJoined = append(splitsJoined, mixed3.ToAddressBase())
				}
			} else { // IPv6
				sec := frontSection.ToIPv6().Append(backSection.ToIPv6())
				mixed2x, err := ipaddr.NewIPv6Address(sec)
				if err != nil {
					t.addFailure(newSegmentSeriesFailure("unexpected error: "+err.Error(), sec))
				}
				mixed2 = mixed2x.ToAddressBase()
				if frontSectionInvalid != nil && backSectionInvalid != nil {
					newSec := (frontSection.ToIPv6()).Append(backSectionInvalid.ToIPv6())
					if newSec.GetSegmentCount() != frontSection.GetSegmentCount()+backSectionInvalid.GetSegmentCount() {
						t.addFailure(newSegmentSeriesFailure("unexpected seg count: "+strconv.Itoa(newSec.GetSegmentCount()), newSec))
					}
					newSec = (frontSectionInvalid.ToIPv6()).Append(backSection.ToIPv6())
					if newSec.GetSegmentCount() != frontSectionInvalid.GetSegmentCount()+backSection.GetSegmentCount() {
						t.addFailure(newSegmentSeriesFailure("unexpected seg count: "+strconv.Itoa(newSec.GetSegmentCount()), newSec))
					}
				}
				for o := 0; o < len(splits); o++ {
					split := splits[o]
					f := split[0]
					g := split[1]
					h := split[2]
					sec = f.ToIPv6().Append(h.ToIPv6())
					sec = sec.Insert(f.GetSegmentCount(), g.ToIPv6())
					if h.IsPrefixed() && h.GetPrefixLen().Len() == 0 && !f.IsPrefixed() {
						gPref := ipaddr.BitCount(g.GetSegmentCount()) * ipaddr.IPv6BitsPerSegment
						if g.IsPrefixed() {
							gPref = g.GetPrefixLen().Len()
						}
						sec = sec.SetPrefixLen(ipaddr.BitCount(f.GetSegmentCount())*ipaddr.IPv6BitsPerSegment + gPref)
					}
					mixed3, err := ipaddr.NewIPv6Address(sec)
					if err != nil {
						t.addFailure(newSegmentSeriesFailure("unexpected error: "+err.Error(), sec))
					}
					splitsJoined = append(splitsJoined, mixed3.ToAddressBase())
				}
			}
		}
		if !mixed.Equal(mixed2) {
			t.addFailure(newSegmentSeriesFailure("mixed was "+mixed.String()+" expected was "+mixed2.String(), mixed))
		}
		if !expectedPref[i].Equal(mixed.GetPrefixLen()) {
			t.addFailure(newSegmentSeriesFailure("mixed prefix was "+mixed.GetPrefixLen().String()+" expected was "+expectedPref[i].String(), mixed))
		}
		if !expectedPref[i].Equal(mixed2.GetPrefixLen()) {
			t.addFailure(newSegmentSeriesFailure("mixed2 prefix was "+mixed2.GetPrefixLen().String()+" expected was "+expectedPref[i].String(), mixed2))
		}
		for o := 0; o < len(splitsJoined); o++ {
			mixed3 := splitsJoined[o]
			if !mixed.Equal(mixed3) {
				t.addFailure(newSegmentSeriesFailure("mixed was "+mixed3.String()+" expected was "+mixed.String(), mixed3))
			}
			if !mixed3.Equal(mixed2) {
				t.addFailure(newSegmentSeriesFailure("mixed was "+mixed3.String()+" expected was "+mixed2.String(), mixed3))
			}
			if !expectedPref[i].Equal(mixed3.GetPrefixLen()) {
				t.addFailure(newSegmentSeriesFailure("mixed3 prefix was "+mixed3.GetPrefixLen().String()+" expected was "+expectedPref[i].String(), mixed3))
			}
		}
	}
	t.incrementTestCount()
}

func (t testBase) testIncrement(orig *ipaddr.Address, increment int64, expectedResult *ipaddr.Address) {
	t.testIncrementF(orig, increment, expectedResult, true)
}

func (t testBase) testIncrementF(orig *ipaddr.Address, increment int64, expectedResult *ipaddr.Address, first bool) {
	result := orig.Increment(increment)
	if expectedResult == nil {
		if result != nil {
			t.addFailure(newSegmentSeriesFailure("increment mismatch result "+result.String()+" vs none expected", orig))
		}
	} else {
		if !result.Equal(expectedResult) {
			t.addFailure(newSegmentSeriesFailure("increment mismatch result "+result.String()+" vs expected "+expectedResult.String(), orig))
		}
		if first && !orig.IsMultiple() && increment > math.MinInt64 { //negating Long.MIN_VALUE results in same address
			t.testIncrementF(expectedResult, -increment, orig, false)
		}
	}
	t.incrementTestCount()
}

func (t testBase) testPrefix(original ipaddr.AddressSegmentSeries, prefixLength ipaddr.PrefixLen, minPrefix ipaddr.BitCount, equivalentPrefix ipaddr.PrefixLen) {
	if !original.GetPrefixLen().Equal(prefixLength) {
		t.addFailure(newSegmentSeriesFailure("prefix: "+original.GetPrefixLen().String()+" expected: "+prefixLength.String(), original))
	} else if !cacheTestBits(original.GetMinPrefixLenForBlock()).Equal(cacheTestBits(minPrefix)) {
		t.addFailure(newSegmentSeriesFailure("min prefix: "+strconv.Itoa(int(original.GetMinPrefixLenForBlock()))+" expected: "+bitCountToString(minPrefix), original))
	} else if !original.GetPrefixLenForSingleBlock().Equal(equivalentPrefix) {
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
	t.testIPv6OnlyStrings(w, ipAddr.ToIPv6(), mixedStringNoCompressMixed,
		mixedStringNoCompressHost, mixedStringCompressCoveredHost, mixedString, base85String)
}

func (t testBase) testIPv6OnlyStrings(w *ipaddr.IPAddressString, ipAddr *ipaddr.IPv6Address,
	mixedStringNoCompressMixed,
	mixedStringNoCompressHost,
	mixedStringCompressCoveredHost,
	mixedString,
	base85String string) {

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

	compressOpts := new(addrstr.CompressOptionsBuilder).SetCompressSingle(true).SetRangeSelection(addrstr.ZerosOrHost).SetMixedOptions(addrstr.MixedCompressionCoveredByHost)
	mixedParams := new(addrstr.IPv6StringOptionsBuilder).SetMixed(true).SetCompressOptions(compressOpts).ToOptions()
	mixedCompressCoveredHost, _ := ipAddr.ToCustomString(mixedParams)

	compressOpts = new(addrstr.CompressOptionsBuilder).SetCompressSingle(true).SetRangeSelection(addrstr.ZerosOrHost).SetMixedOptions(addrstr.MixedCompressionNoHost)
	mixedParams = new(addrstr.IPv6StringOptionsBuilder).SetMixed(true).SetCompressOptions(compressOpts).ToOptions()
	mixedNoCompressHost, _ := ipAddr.ToCustomString(mixedParams)

	compressOpts = new(addrstr.CompressOptionsBuilder).SetCompressSingle(true).SetRangeSelection(addrstr.ZerosOrHost).SetMixedOptions(addrstr.NoMixedCompression)
	mixedParams = new(addrstr.IPv6StringOptionsBuilder).SetMixed(true).SetCompressOptions(compressOpts).ToOptions()
	mixedNoCompressMixed, _ := ipAddr.ToCustomString(mixedParams)

	t.confirmAddrStrings(ipAddr.ToIP(), m, mixedCompressCoveredHost, mixedNoCompressHost, mixedNoCompressMixed, base85)

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
		if !macAddr.Equal(addr) {
			t.addFailure(newSegmentSeriesFailure("failed produced string: "+str, macAddr))
			return false
		}
	}
	t.incrementTestCount()
	return true
}

func (t testBase) confirmAddrStrings(ipAddr *ipaddr.IPAddress, strs ...string) bool {
	for _, str := range strs {
		if str == "" {
			continue
		}

		addrString := t.createParamsAddress(str, defaultOptions)
		addr := addrString.GetAddress()
		if !ipAddr.Equal(addr) {
			t.addFailure(newIPAddrFailure("failed produced string: "+str, ipAddr))
			return false
		}
	}
	t.incrementTestCount()
	return true
}

func (t testBase) confirmIPAddrStrings(ipAddr *ipaddr.IPAddress, strs ...*ipaddr.IPAddressString) bool {
	for _, str := range strs {
		addr := str.GetAddress()
		if !ipAddr.Equal(addr) {
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
			ipv6Addr := ipAddr.ToIPv6()
			ipv6Addr, _ = ipaddr.NewIPv6Address(ipv6Addr.GetSection())
			ipAddr = ipv6Addr.ToIP()
		}
		if !ipAddr.Equal(a) {
			t.addFailure(newIPAddrFailure("failed produced string: "+str, ipAddr))
			return false
		}
		again := hostName.ToNormalizedString()
		hostName = ipaddr.NewHostName(again)
		a = hostName.GetAddress()
		if !ipAddr.Equal(a) {
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
		if !ipAddr.Equal(a) {
			t.addFailure(newIPAddrFailure("failed produced string: "+str.String(), ipAddr))
			return false
		}
		again := str.ToNormalizedString()
		str = ipaddr.NewHostName(again)
		a = str.GetAddress()
		if !ipAddr.Equal(a) {
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
	hex, err = ipAddr.ToHexString(true)
	if err != nil {
		isMatch := singleHex == ""
		if !isMatch {
			t.addFailure(newMACFailure("failed expected: "+singleHex+" actual: "+err.Error(), w))
		}
	} else {
		t.confirmMACAddrStrings(ipAddr, hex)
	}
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
					dotted, err = ipAddr.ToDottedString()
					if err != nil {
						sMatch = dottedString == ""
					} else {
						t.confirmMACAddrStrings(ipAddr, dotted)
						sMatch = dotted == (dottedString)
					}
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

func (t testBase) testHostAddressStr(addressStr string) {
	str := t.createAddress(addressStr)
	address := str.GetAddress()
	if address != nil {
		hostAddress := str.GetHostAddress()
		prefixIndex := strings.IndexByte(addressStr, ipaddr.PrefixLenSeparator)
		if prefixIndex < 0 {
			if !address.Equal(hostAddress) || !address.Contains(hostAddress) {
				t.addFailure(newFailure("failed host address with no prefix: "+hostAddress.String()+" expected: "+address.String(), str))
			}
		} else {
			substr := addressStr[:prefixIndex]
			str2 := t.createAddress(substr)
			address2 := str2.GetAddress()
			if !address2.Equal(hostAddress) {
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

	if !ipAddr.IsIPv6() || !ipAddr.ToIPv6().HasZone() {
		if singleHex != "" && singleOctal != "" {
			fmtStr := fmt.Sprintf("%s %v %#x %#o", ipAddr, ipAddr, ipAddr, ipAddr)
			expectedFmtStr := canonicalString + " " + canonicalString + " " + singleHex + " " + singleOctal
			if fmtStr != expectedFmtStr {
				t.addFailure(newFailure("failed expected: "+expectedFmtStr+" actual: "+fmtStr, w))
			}
		} else if singleHex == "" && singleOctal == "" {
			fmtStr := fmt.Sprintf("%s %v", ipAddr, ipAddr)
			expectedFmtStr := canonicalString + " " + canonicalString
			if fmtStr != expectedFmtStr {
				t.addFailure(newFailure("failed expected: "+expectedFmtStr+" actual: "+fmtStr, w))
			}
		}
	}

	t.testHostAddressStr(w.String())

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
	rDNS, _ := ipAddr.ToReverseDNSString()
	//unc := ipAddr.ToUNCHostName(); //TODO LATER reinstate

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

	binary, err := ipAddr.ToBinaryString(false)
	if err != nil {
		isMatch := singleHex == "" //iff hex is null is binary null
		if !isMatch {
			t.addFailure(newFailure("failed expected non-null binary string but got: "+err.Error(), w))
		}
	} else if ipAddr == nil {
		if binary != "<nil>" {
			t.addFailure(newFailure("failed expected <nil> for nil binary string but got: "+binary, w))
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

	binary = ipAddr.ToSegmentedBinaryString()
	t.confirmAddrStrings(ipAddr, c, canonical, s, cidr, n, nw, caw, cw, binary)
	if ipAddr.IsIPv6() {
		t.confirmAddrStrings(ipAddr, full)
		//TODO LATER reinstate //t.confirmHostStrings(ipAddr, true, rDNS);//these two are valid hosts with embedded addresses
		//t.confirmHostStrings(ipAddr, false, unc);//these two are valid hosts with embedded addresses
	} else {
		params := new(addrstrparam.IPAddressStringParamsBuilder).Allow_inet_aton(false).ToParams()
		fullAddrString := ipaddr.NewIPAddressStringParams(full, params)
		t.confirmIPAddrStrings(ipAddr, fullAddrString)
		//TODO LATER reinstate //t.confirmHostStrings(ipAddr, false, rDNS, unc);//these two are valid hosts with embedded addresses
	}
	t.confirmHostStrings(ipAddr, false, c, canonical, s, cidr, n, nw, caw, cw)
	if ipAddr.IsIPv6() {
		t.confirmHostStrings(ipAddr, false, full)
	} else {
		params := new(addrstrparam.HostNameParamsBuilder).GetIPAddressParamsBuilder().Allow_inet_aton(false).GetParentBuilder().ToParams()
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
											rdnsMatch := reverseDNSString == rDNS
											if !rdnsMatch {
												t.addFailure(newFailure("failed expected: "+reverseDNSString+" actual: "+rDNS, w))
											} else {
												// TODO LATER reinstate
												//	 uncMatch := uncHostString==unc
												//	if(!uncMatch) {
												//		t.addFailure(newFailure("failed expected: " + uncHostString + " actual: " + unc, w));
												//	}
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
	}
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
		count = getNonZeroHostCount(val.ToAddressBase().ToIP())
	} else {
		count = val.GetCount()
	}
	var set []ipaddr.AddressItem
	if count.Cmp(new(big.Int).SetUint64(number)) != 0 {
		t.addFailure(newSegmentSeriesFailure("count was "+count.String()+" instead of expected count "+strconv.FormatUint(number, 10), val))
	} else {
		var addrIterator ipaddr.AddressIterator
		if excludeZeroHosts {
			addrIterator = ipaddr.UnwrappedIPAddressIterator{getNonZeroHostIterator(val.ToAddressBase().ToIP())}
		} else {
			addrIterator = val.ToAddressBase().Iterator()
		}
		var counter uint64
		var next *ipaddr.Address
		for addrIterator.HasNext() {
			next = addrIterator.Next()
			if counter == 0 {
				lower := val.ToAddressBase().GetLower()
				if excludeZeroHosts {
					if lower.ToIP().IsZeroHost() && next.Equal(lower) {
						t.addFailure(newIPAddrFailure("lowest: "+lower.String()+" next: "+next.String(), next.ToIP()))
					}
				} else {
					if !next.Equal(lower) {
						t.addFailure(newSegmentSeriesFailure("lowest: "+lower.String()+" next: "+next.String(), next))
					}
				}

				if !next.GetPrefixLen().Equal(val.GetPrefixLen()) {
					t.addFailure(newSegmentSeriesFailure("val prefix length: "+val.GetPrefixLen().String()+" upper prefix length: "+next.GetPrefixLen().String(), next))
				}
				if !lower.GetPrefixLen().Equal(val.GetPrefixLen()) {
					t.addFailure(newSegmentSeriesFailure("val prefix length: "+val.GetPrefixLen().String()+" lowest prefix length: "+lower.GetPrefixLen().String(), lower))
				}
			} else if counter == 1 {
				if !next.GetPrefixLen().Equal(val.GetPrefixLen()) {
					t.addFailure(newSegmentSeriesFailure("val prefix length: "+val.GetPrefixLen().String()+" upper prefix length: "+next.GetPrefixLen().String(), next))
				}
			}
			set = append(set, next)
			counter++
		}
		if number < uint64(maxInt) && len(set) != int(number) {
			t.addFailure(newSegmentSeriesFailure("set count was "+strconv.Itoa(len(set))+" instead of expected "+strconv.FormatUint(number, 10), val.ToAddressBase()))
		} else if counter != number {
			t.addFailure(newSegmentSeriesFailure("set count was "+strconv.Itoa(len(set))+" instead of expected "+strconv.FormatUint(number, 10), val.ToAddressBase()))
		} else if number > 0 {
			if !next.Equal(val.ToAddressBase().GetUpper()) {
				t.addFailure(newSegmentSeriesFailure("highest: "+val.ToAddressBase().GetUpper().String(), next))
			} else {
				lower := val.ToAddressBase().GetLower()
				if excludeZeroHosts {
					addr := val.ToAddressBase().ToIP()
					if counter == 1 && (!addr.GetUpper().Equal(lower) && !addr.GetUpper().IsZeroHost() && !lower.ToIP().IsZeroHost()) {
						t.addFailure(newSegmentSeriesFailure("highest: "+val.ToAddressBase().GetUpper().String()+" lowest: "+val.ToAddressBase().GetLower().String(), next))
					}
				} else {
					if counter == 1 && !val.ToAddressBase().GetUpper().Equal(lower) {
						t.addFailure(newSegmentSeriesFailure("highest: "+val.ToAddressBase().GetUpper().String()+" lowest: "+val.ToAddressBase().GetLower().String(), next))
					}
				}
				if !next.GetPrefixLen().Equal(val.GetPrefixLen()) {
					t.addFailure(newSegmentSeriesFailure("val prefix length: "+val.GetPrefixLen().String()+" upper prefix length: "+next.GetPrefixLen().String(), next))
				}
				if !val.ToAddressBase().GetUpper().GetPrefixLen().Equal(val.GetPrefixLen()) {
					t.addFailure(newSegmentSeriesFailure("val prefix length: "+val.GetPrefixLen().String()+" upper prefix length: "+val.ToAddressBase().GetUpper().GetPrefixLen().String(), next))
				}
			}
		} else {
			if excludeZeroHosts {
				if !val.ToAddressBase().ToIP().IsZeroHost() {
					t.addFailure(newSegmentSeriesFailure("unexpected non-zero-host: "+val.ToAddressBase().ToIP().String(), val))
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
				addrIterator = val.ToAddressBase().PrefixBlockIterator()
			} else {
				set = prefixSet
				addrIterator = val.ToAddressBase().PrefixIterator()
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
					if next.ToIP().Intersect(previous.ToIP()) != nil {
						t.addFailure(newSegmentSeriesFailure("intersection of "+previous.String()+" when iterating: "+next.ToIP().Intersect(previous.ToIP()).String(), next))
						break
					}
				}
				set = append(set, next)

				counter++
				previous = next
			}
			if number < uint64(maxInt) && len(set) != int(number) {
				t.addFailure(newSegmentSeriesFailure("set count was "+strconv.Itoa(len(set))+" instead of expected "+strconv.FormatUint(number, 10), val.ToAddressBase()))
			} else if counter != number {
				t.addFailure(newSegmentSeriesFailure("set count was "+strconv.Itoa(len(set))+" instead of expected "+strconv.FormatUint(number, 10), val.ToAddressBase()))
			} else if number < 0 {
				t.addFailure(newSegmentSeriesFailure("unexpected zero count ", val.ToAddressBase()))
			} else if !isBlock && countedCount.Cmp(totalCount) != 0 {
				t.addFailure(newSegmentSeriesFailure("count mismatch, expected "+totalCount.String()+" got "+countedCount.String(), val.ToAddressBase()))
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

func (t testBase) hostLabelsTest(x string, labels []string) {
	host := t.createHost(x)
	t.hostLabelsHostTest(host, labels)
}

func (t testBase) hostLabelsHostTest(host *ipaddr.HostName, labels []string) {
	normalizedLabels := host.GetNormalizedLabels()
	if len(normalizedLabels) != len(labels) {
		t.addFailure(newHostFailure("normalization length "+strconv.Itoa(len(host.GetNormalizedLabels())), host))
	} else {
		for i := 0; i < len(labels); i++ {
			normalizedLabels := host.GetNormalizedLabels()
			if labels[i] != (normalizedLabels[i]) {
				t.addFailure(newHostFailure("normalization label "+host.GetNormalizedLabels()[i]+" not expected label "+labels[i], host))
				break
			}
		}
	}
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
	return adjusted.Equal(exp.adjusted) && set.Equal(exp.set)
}

type failure struct {
	str string

	rng    *ipaddr.IPAddressSeqRange
	idStr  ipaddr.HostIdentifierString
	series ipaddr.AddressSegmentSeries
	div    ipaddr.DivisionType
	item   ipaddr.AddressItem
}

func (f failure) String() string {
	return concat(
		concat(
			concat(
				concat(
					concat(f.str, f.series),
					f.idStr),
				f.rng),
			f.div),
		f.item)
}

func concat(str string, stringer fmt.Stringer) string {
	if stringer != nil {
		stringerStr := stringer.String()
		if stringerStr == "<nil>" {
			stringerStr = ""
		}
		if str != "" {
			return stringer.String() + ": " + str
		}
		return stringer.String()
	}
	return str
}

func newAddressItemFailure(str string, item ipaddr.AddressItem) failure {
	return failure{
		str:  str,
		item: item,
	}
}

func newDivisionFailure(str string, div ipaddr.DivisionType) failure {
	return failure{
		str: str,
		div: div,
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

func newHostIdFailure(str string, idStr ipaddr.HostIdentifierString) failure {
	return failure{
		str:   str,
		idStr: idStr,
	}
}

func newIPAddrFailure(str string, addr *ipaddr.IPAddress) failure {
	return newSegmentSeriesFailure(str, addr)
}

func newMACAddrFailure(str string, addr *ipaddr.MACAddress) failure {
	return newSegmentSeriesFailure(str, addr)
}

func newHostFailure(str string, host *ipaddr.HostName) failure {
	return newHostIdFailure(str, host)
}

func newMACFailure(str string, addrStr *ipaddr.MACAddressString) failure {
	return newHostIdFailure(str, addrStr)
}

func newFailure(str string, addrStr *ipaddr.IPAddressString) failure {
	return newHostIdFailure(str, addrStr)
}

func cacheTestBits(i ipaddr.BitCount) ipaddr.PrefixLen {
	res := ipaddr.PrefixBitCount(i)
	return &res
}

var (
	pnil ipaddr.PrefixLen = nil

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
	p40  = cacheTestBits(40)
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
