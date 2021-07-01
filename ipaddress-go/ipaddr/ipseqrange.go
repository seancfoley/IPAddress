package ipaddr

import (
	"fmt"
	"math/big"
	"net"
	"sync/atomic"
	"unsafe"
)

type rangeCache struct {
	cachedCount *big.Int
}

type ipAddressSeqRangeInternal struct {
	lower, upper *IPAddress
	isMultiple   bool // set on construction, even for zero values
	cache        *rangeCache
}

func (rng *ipAddressSeqRangeInternal) IsMultiple() bool {
	return rng.isMultiple
}

func (rng *ipAddressSeqRangeInternal) GetCount() *big.Int {
	return rng.GetCachedCount(true)
}

func (rng *ipAddressSeqRangeInternal) GetCachedCount(copy bool) (res *big.Int) {
	cache := rng.cache
	count := cache.cachedCount
	if count == nil {
		if !rng.IsMultiple() {
			count = bigOne()
		} else if ipv4Range := rng.toIPv4SequentialRange(); ipv4Range != nil {
			upper := int64(ipv4Range.GetUpper().IntValue())
			lower := int64(ipv4Range.GetLower().IntValue())
			val := upper - lower + 1
			count = new(big.Int).SetInt64(val)
		} else {
			count = rng.upper.GetValue()
			res = rng.lower.GetValue()
			count.Sub(count, res).Add(count, bigOneConst())
			res.Set(count)
		}
		dataLoc := (*unsafe.Pointer)(unsafe.Pointer(&cache.cachedCount))
		atomic.StorePointer(dataLoc, unsafe.Pointer(count))
	}
	if res == nil {
		if copy {
			res = new(big.Int).Set(count)
		} else {
			res = count
		}
	}
	return
}

func (rng *ipAddressSeqRangeInternal) GetPrefixCount(prefixLen BitCount) *big.Int {
	if !rng.IsMultiple() { // also checks for zero-ranges
		return bigOne()
	}
	bitCount := rng.lower.GetBitCount()
	if prefixLen <= 0 {
		return bigOne()
	} else if prefixLen >= bitCount {
		return rng.GetCount()
	}
	shiftAdjustment := bitCount - prefixLen
	if ipv4Range := rng.toIPv4SequentialRange(); ipv4Range != nil {
		upper := ipv4Range.GetUpper()
		lower := ipv4Range.GetLower()
		upperAdjusted := upper.IntValue() >> shiftAdjustment
		lowerAdjusted := lower.IntValue() >> shiftAdjustment
		result := int64(upperAdjusted) - int64(lowerAdjusted) + 1
		return new(big.Int).SetInt64(result)
	}
	upper := rng.upper.GetValue()
	ushiftAdjustment := uint(shiftAdjustment)
	upper.Rsh(upper, ushiftAdjustment)
	lower := rng.lower.GetValue()
	lower.Rsh(lower, ushiftAdjustment)
	upper.Sub(upper, lower).Add(upper, bigOneConst())
	return upper
}

// CompareSize returns whether this range has a large count than the other
func (rng *ipAddressSeqRangeInternal) CompareSize(other *IPAddressSeqRange) int {
	if !rng.IsMultiple() {
		if other.IsMultiple() {
			return -1
		}
		return 0
	}
	return rng.GetCachedCount(false).CmpAbs(other.init().GetCachedCount(false))
}

func (rng *ipAddressSeqRangeInternal) contains(other IPAddressType) bool {
	otherAddr := other.ToIPAddress()
	return compareLowIPAddressValues(otherAddr.GetLower(), rng.lower) >= 0 &&
		compareLowIPAddressValues(otherAddr.GetUpper(), rng.upper) <= 0
}

func (rng *ipAddressSeqRangeInternal) equals(other IPAddressSeqRangeType) bool {
	otherRng := other.ToIPAddressSeqRange()
	return rng.lower.Equals(otherRng.GetLower()) && rng.upper.Equals(otherRng.GetUpper())
}

func (rng *ipAddressSeqRangeInternal) containsRange(other IPAddressSeqRangeType) bool {
	otherRange := other.ToIPAddressSeqRange()
	return compareLowIPAddressValues(otherRange.GetLower(), rng.lower) >= 0 &&
		compareLowIPAddressValues(otherRange.GetUpper(), rng.upper) <= 0
}

func (rng *ipAddressSeqRangeInternal) toIPv4SequentialRange() *IPv4AddressSeqRange {
	if rng.lower != nil && rng.lower.getAddrType().isIPv4() {
		return (*IPv4AddressSeqRange)(unsafe.Pointer(rng))
	}
	return nil
}

func (rng *ipAddressSeqRangeInternal) toIPSequentialRange() *IPAddressSeqRange {
	return (*IPAddressSeqRange)(unsafe.Pointer(rng))
}

func (rng ipAddressSeqRangeInternal) String() string { // using non-pointer receiver makes it work well with fmt
	return fmt.Sprintf("%v -> %v", rng.lower, rng.upper)
}

//TODO NEXT the methods below (and the few ones in ipv4/6 seq range) complete the range types

//public String toNormalizedString(String separator) {
//		Function<IPAddress, String> stringer = IPAddress::toNormalizedString;
//		return toString(stringer, separator, stringer);
//	}
//
//	@Override
//	public String toNormalizedString() {
//		return toNormalizedString(" -> ");
//	}
//
//	public String toCanonicalString(String separator) {
//		Function<IPAddress, String> stringer = IPAddress::toCanonicalString;
//		return toString(stringer, separator, stringer);
//	}
//
//	@Override
//	public String toCanonicalString() {
//		return toCanonicalString(" -> ");
//	}
//
//	public String toString(Function<? super IPAddress, String> lowerStringer, String separator, Function<? super IPAddress, String> upperStringer) {
//		return lowerStringer.apply(getLower()) + separator + upperStringer.apply(getUpper());
//	}
//
//	@Override
//	public String toString() {
//		return toCanonicalString();
//	}
//
//	@Override
//	public abstract IPAddress coverWithPrefixBlock();
//
//	@Override
//	public abstract IPAddress[] spanWithPrefixBlocks();
//
//	@Override
//	public abstract IPAddress[] spanWithSequentialBlocks();
//
// TODO I think this one should become a method, so that we can have ipv4 and v6 versions.
// We also need to change the name of the other join, maybe to joinTo or joinSingle
//	/**
//	 * Joins the given ranges into the fewest number of ranges.
//	 * The returned array will be sorted by ascending lowest range value.
//	 *
//	 * @param ranges
//	 * @return
//	 */
//	public static IPAddressSeqRange[] join(IPAddressSeqRange... ranges) {
//		ranges = ranges.clone();
//		// null entries are automatic joins
//		int joinedCount = 0;
//		for(int i = 0, j = ranges.length - 1; i <= j; i++) {
//			if(ranges[i] == null) {
//				joinedCount++;
//				while(ranges[j] == null && j > i) {
//					j--;
//					joinedCount++;
//				}
//				if(j > i) {
//					ranges[i] = ranges[j];
//					ranges[j] = null;
//					j--;
//				}
//			}
//		}
//		int len = ranges.length - joinedCount;
//		Arrays.sort(ranges, 0, len, Address.ADDRESS_LOW_VALUE_COMPARATOR);
//		for(int i = 0; i < len; i++) {
//			IPAddressSeqRange range = ranges[i];
//			if(range == null) {
//				continue;
//			}
//			IPAddress currentLower = range.getLower();
//			IPAddress currentUpper = range.getUpper();
//			boolean didJoin = false;
//			for(int j = i + 1; j < ranges.length; j++) {
//				IPAddressSeqRange range2 = ranges[j];
//				if(range2 == null) {
//					continue;
//				}
//				IPAddress nextLower = range2.getLower();
//				if(compareLowValues(currentUpper, nextLower) >= 0
//						|| currentUpper.increment(1).equals(nextLower)) {
//					//join them
//					IPAddress nextUpper = range2.getUpper();
//					if(compareLowValues(currentUpper, nextUpper) < 0) {
//						currentUpper = nextUpper;
//					}
//					ranges[j] = null;
//					didJoin = true;
//					joinedCount++;
//				} else break;
//			}
//			if(didJoin) {
//				ranges[i] = range.create(currentLower, currentUpper);
//			}
//		}
//		if(joinedCount == 0) {
//			return ranges;
//		}
//		IPAddressSeqRange joined[] = new IPAddressSeqRange[ranges.length - joinedCount];
//		for(int i = 0, j = 0; i < ranges.length; i++) {
//			IPAddressSeqRange range = ranges[i];
//			if(range == null) {
//				continue;
//			}
//			joined[j++] = range;
//			if(j >= joined.length) {
//				break;
//			}
//		}
//		return joined;
//	}
//
func (rng *ipAddressSeqRangeInternal) overlaps(other *IPAddressSeqRange) bool {
	return compareLowIPAddressValues(other.GetLower(), rng.upper) <= 0 && compareLowIPAddressValues(other.GetUpper(), rng.lower) >= 0
}

func (rng *ipAddressSeqRangeInternal) IsSequential() bool {
	return true
}

// Returns the intersection of this range with the given range, a range which includes those addresses in both this and the given range.
func (rng *ipAddressSeqRangeInternal) intersect(other *IPAddressSeqRange) *IPAddressSeqRange {
	otherLower, otherUpper := other.GetLower(), other.GetUpper()
	lower, upper := rng.lower, rng.upper
	if compareLowIPAddressValues(lower, otherLower) <= 0 {
		if compareLowIPAddressValues(upper, otherUpper) >= 0 { // l, ol, ou, u
			return other
		}
		comp := compareLowIPAddressValues(upper, otherLower)
		if comp < 0 { // l, u, ol, ou
			return nil
		}
		return newSeqRangeUnchecked(otherLower, upper, comp != 0) // l, ol, u,  ou
	} else if compareLowIPAddressValues(otherUpper, upper) >= 0 {
		return rng.toIPSequentialRange()
	}
	comp := compareLowIPAddressValues(otherUpper, lower)
	if comp < 0 {
		return nil
	}
	return newSeqRangeUnchecked(lower, otherUpper, comp != 0)
}

// TODO these too need to be done.
//	/**
//	 * If this range overlaps with the given range,
//	 * or if the highest value of the lower range is one below the lowest value of the higher range,
//	 * then the two are joined into a new larger range that is returned.
//	 * <p>
//	 * Otherwise null is returned.
//	 *
//	 * @param other
//	 * @return
//	 */
//	public IPAddressSeqRange join(IPAddressSeqRange other) {
//		IPAddress otherLower = other.getLower();
//		IPAddress otherUpper = other.getUpper();
//		IPAddress lower = getLower();
//		IPAddress upper = getUpper();
//		int lowerComp = compareLowValues(lower, otherLower);
//		if(!overlaps(other)) {
//			if(lowerComp >= 0) {
//				if(otherUpper.increment(1).equals(lower)) {
//					return create(otherLower, upper);
//				}
//			} else {
//				if(upper.increment(1).equals(otherLower)) {
//					return create(lower, otherUpper);
//				}
//			}
//			return null;
//		}
//		int upperComp = compareLowValues(upper, otherUpper);
//		IPAddress lowestLower, highestUpper;
//		if(lowerComp >= 0) {
//			if(lowerComp == 0 && upperComp == 0) {
//				return this;
//			}
//			lowestLower = otherLower;
//		} else {
//			lowestLower = lower;
//		}
//		highestUpper = upperComp >= 0 ? upper : otherUpper;
//		return create(lowestLower, highestUpper);
//	}
//
///**
// * Extend this sequential range to include all address in the given range, which can be an IPAddress or IPAddressSeqRange.
// * If the argument has a different IP version than this, null is returned.
// * Otherwise, this method returns the range that includes this range, the given range, and all addresses in-between.
// *
// * @param other
// * @return
// */
//public IPAddressSeqRange extend(IPAddressRange other) {
//	IPAddress otherLower = other.getLower();
//	IPAddress otherUpper = other.getUpper();
//	IPAddress lower = getLower();
//	IPAddress upper = getUpper();
//	int lowerComp = compareLowValues(lower, otherLower);
//	int upperComp = compareLowValues(upper, otherUpper);
//	if(lowerComp > 0) { //
//		if(upperComp <= 0) { // ol l u ou
//			return other.toSequentialRange();
//		}
//		IPAddress max = otherUpper.getNetwork().getNetworkMask(getBitCount(), false);
//		int versionComp = compareLowValues(lower, max);
//		if(versionComp > 0) { // different versions: ol ou max l u
//			return null;
//		}
//		// ol l ou u
//		return create(otherLower, upper);
//	}
//	// lowerComp <= 0
//	if(upperComp >= 0) { // l ol ou u
//		return this;
//	}
//	IPAddress max = upper.getNetwork().getNetworkMask(getBitCount(), false);
//	int versionComp = compareLowValues(otherLower, max);
//	if(versionComp > 0) { // different versions: l u max ol ou
//		return null;
//	}
//	return create(lower, otherUpper);// l ol u ou
//}
//
///**
// * Subtracts the given range from this range, to produce either zero, one, or two address ranges that contain the addresses in this range and not in the given range.
// * If the result has length 2, the two ranges are ordered by ascending lowest range value.
// *
// * @param other
// * @return
// */
//public IPAddressSeqRange[] subtract(IPAddressSeqRange other) {
//	IPAddress otherLower = other.getLower();
//	IPAddress otherUpper = other.getUpper();
//	IPAddress lower = getLower();
//	IPAddress upper = getUpper();
//	if(compareLowValues(lower, otherLower) < 0) {
//		if(compareLowValues(upper, otherUpper) > 0) { // l ol ou u
//			return createPair(lower, otherLower.increment(-1), otherUpper.increment(1), upper);
//		} else {
//			int comp = compareLowValues(upper, otherLower);
//			if(comp < 0) { // l u ol ou
//				return createSingle();
//			} else if(comp == 0) { // l u == ol ou
//				return createSingle(lower, upper.increment(-1));
//			}
//			return createSingle(lower, otherLower.increment(-1)); // l ol u ou
//		}
//	} else if(compareLowValues(otherUpper, upper) >= 0) { // ol l u ou
//		return createEmpty();
//	} else {
//		int comp = compareLowValues(otherUpper, lower);
//		if(comp < 0) {
//			return createSingle(); // ol ou l u
//		} else if(comp == 0) {
//			return createSingle(lower.increment(1), upper); // ol ou == l u
//		}
//		return createSingle(otherUpper.increment(1), upper); // ol l ou u
//	}
//}
//
//protected abstract IPAddressSeqRange create(IPAddress lower, IPAddress upper);
//
//protected abstract IPAddressSeqRange[] createPair(IPAddress lower1, IPAddress upper1, IPAddress lower2, IPAddress upper2);
//
//protected abstract IPAddressSeqRange[] createSingle(IPAddress lower, IPAddress upper);
//
//protected abstract IPAddressSeqRange[] createSingle();
//
//protected abstract IPAddressSeqRange[] createEmpty();

func (rng *ipAddressSeqRangeInternal) ContainsPrefixBlock(prefixLen BitCount) bool {
	lower := rng.lower
	if lower == nil {
		return true // returns true for 0 bits
	}
	prefixLen = checkSubnet(lower, prefixLen)
	upper := rng.upper
	divCount := lower.GetDivisionCount()
	bitsPerSegment := lower.GetBitsPerSegment()
	i := getHostSegmentIndex(prefixLen, lower.GetBytesPerSegment(), bitsPerSegment)
	if i < divCount {
		div := lower.GetSegment(i)
		upperDiv := upper.GetSegment(i)
		segmentPrefixLength := getPrefixedSegmentPrefixLength(bitsPerSegment, prefixLen, i)
		if !div.isPrefixBlockVals(div.getDivisionValue(), upperDiv.getDivisionValue(), *segmentPrefixLength) {
			return false
		}
		for i++; i < divCount; i++ {
			div = lower.GetSegment(i)
			upperDiv = upper.GetSegment(i)
			//is full range?
			if !div.IncludesZero() || !upperDiv.IncludesMax() {
				return false
			}
		}
	}
	return true
}

func (rng *ipAddressSeqRangeInternal) ContainsSinglePrefixBlock(prefixLen BitCount) bool {
	lower := rng.lower
	if lower == nil {
		return true // returns true for 0 bits
	}
	prefixLen = checkSubnet(lower, prefixLen)
	var prevBitCount BitCount
	upper := rng.upper
	divCount := lower.GetDivisionCount()
	for i := 0; i < divCount; i++ {
		div := lower.GetSegment(i)
		upperDiv := upper.GetSegment(i)
		bitCount := div.GetBitCount()
		totalBitCount := bitCount + prevBitCount
		if prefixLen >= totalBitCount {
			if !divValSame(div.getDivisionValue(), upperDiv.getDivisionValue()) {
				return false
			}
		} else {
			divPrefixLen := prefixLen - prevBitCount
			if !div.isPrefixBlockVals(div.getDivisionValue(), upperDiv.getDivisionValue(), divPrefixLen) {
				return false
			}
			for i++; i < divCount; i++ {
				div = lower.GetSegment(i)
				upperDiv = upper.GetSegment(i)
				if !div.IncludesZero() || !upperDiv.IncludesMax() {
					return false
				}
			}
			return true
		}
		prevBitCount = totalBitCount
	}
	return true
}

func (rng *ipAddressSeqRangeInternal) IsZero() bool {
	return rng.IncludesZero() && !rng.IsMultiple()
}

func (rng *ipAddressSeqRangeInternal) IncludesZero() bool {
	lower := rng.lower
	return lower == nil || lower.IsZero()
}

func (rng *ipAddressSeqRangeInternal) IsMax() bool {
	return rng.IncludesMax() && !rng.IsMultiple()
}

func (rng *ipAddressSeqRangeInternal) IncludesMax() bool {
	upper := rng.upper
	return upper == nil || upper.IsMax()
}

// Iterates through the range of prefixes in this range instance using the given prefix length.
//
// Since a range between two arbitrary addresses cannot always be represented with a single IPAddress instance,
// the returned iterator iterates through {@link IPAddressSeqRange} instances.
//
// For instance, if iterating from 1.2.3.4 to 1.2.4.5 with prefix 8, the range shares the same prefix 1,
// but the range cannot be represented by the address 1.2.3-4.4-5 which does not include 1.2.3.255 or 1.2.4.0 both of which are in the original range.
// Nor can the range be represented by 1.2.3-4.0-255 which includes 1.2.4.6 and 1.2.3.3, both of which were not in the original range.
// An IPAddressSeqRange is thus required to represent that prefixed range.
func (rng *ipAddressSeqRangeInternal) prefixIterator(prefLength BitCount) IPAddressSeqRangeIterator {
	lower := rng.lower
	if !rng.IsMultiple() {
		return &singleRangeIterator{original: rng.toIPSequentialRange()}
	}
	prefLength = checkSubnet(lower, prefLength)
	return &rangeIterator{
		rng:                 rng.toIPSequentialRange(),
		creator:             newSeqRange,
		prefixBlockIterator: ipAddrIterator{rng.prefixBlockIterator(prefLength)},
		prefixLength:        prefLength,
	}
}

func (rng *ipAddressSeqRangeInternal) prefixBlockIterator(prefLength BitCount) AddressIterator {
	lower := rng.lower
	if !rng.IsMultiple() {
		return &singleAddrIterator{original: lower.ToPrefixBlockLen(prefLength).ToAddress()}
	} else if prefLength >= lower.GetBitCount() {
		return rng.iterator()
	}
	prefLength = checkSubnet(lower, prefLength)
	bitsPerSegment := lower.GetBitsPerSegment()
	bytesPerSegment := lower.GetBytesPerSegment()
	segCount := lower.GetSegmentCount()
	type segPrefData struct {
		prefLen PrefixLen
		shift   BitCount
	}
	segPrefs := make([]segPrefData, segCount)
	networkSegIndex := getNetworkSegmentIndex(prefLength, bytesPerSegment, bitsPerSegment)
	for i := networkSegIndex; i < segCount; i++ {
		segPrefLength := getPrefixedSegmentPrefixLength(bitsPerSegment, prefLength, i)
		segPrefs[i] = segPrefData{segPrefLength, bitsPerSegment - *segPrefLength}
	}
	hostSegIndex := getHostSegmentIndex(prefLength, bytesPerSegment, bitsPerSegment)
	return rng.rangeIterator(
		true,
		(*IPAddress).GetSegment,
		func(seg *IPAddressSegment, index int) IPSegmentIterator {
			return seg.Iterator()
		},
		func(addr1, addr2 *IPAddress, index int) bool {
			segPref := segPrefs[index]
			if segPref.prefLen == nil {
				return addr1.GetSegment(index).GetSegmentValue() == addr2.GetSegment(index).GetSegmentValue()
			}
			shift := segPref.shift
			return addr1.GetSegment(index).GetSegmentValue()>>shift == addr2.GetSegment(index).GetSegmentValue()>>shift

		},
		networkSegIndex,
		hostSegIndex,
		func(seg *IPAddressSegment, index int) IPSegmentIterator {
			segPref := segPrefs[index]
			segPrefLen := segPref.prefLen
			if segPrefLen == nil {
				return seg.Iterator()
			}
			return seg.PrefixedBlockIterator(*segPrefLen)
		},
	)
}

func (rng *ipAddressSeqRangeInternal) iterator() AddressIterator {
	lower := rng.lower
	if !rng.IsMultiple() {
		return &singleAddrIterator{original: lower.ToAddress()}
	}
	divCount := lower.GetSegmentCount()
	return rng.rangeIterator(
		false,
		//lower.getAddrType().getCreator(),
		(*IPAddress).GetSegment,
		func(seg *IPAddressSegment, index int) IPSegmentIterator {
			return seg.Iterator()
		},
		func(addr1, addr2 *IPAddress, index int) bool {
			return addr1.getSegment(index).getSegmentValue() == addr2.getSegment(index).getSegmentValue()
		},
		divCount-1,
		divCount,
		nil)
}

func (rng *ipAddressSeqRangeInternal) rangeIterator(
	//creator ParsedAddressCreator, /* nil for zero sections */
	valsAreMultiple bool,
	segProducer func(addr *IPAddress, index int) *IPAddressSegment,
	segmentIteratorProducer func(seg *IPAddressSegment, index int) IPSegmentIterator,
	segValueComparator func(seg1, seg2 *IPAddress, index int) bool,
	networkSegmentIndex,
	hostSegmentIndex int,
	prefixedSegIteratorProducer func(seg *IPAddressSegment, index int) IPSegmentIterator,
) AddressIterator {
	lower := rng.lower
	upper := rng.upper
	divCount := lower.getDivisionCount()

	// at any given point in time, this list provides an iterator for the segment at each index
	segIteratorProducerList := make([]func() IPSegmentIterator, divCount)

	// at any given point in time, finalValue[i] is true if and only if we have reached the very last value for segment i - 1
	// when that happens, the next iterator for the segment at index i will be the last
	finalValue := make([]bool, divCount+1)

	// here is how the segment iterators will work:
	// the low and high values of the range at each segment are low, high
	// the maximum possible values for any segment are min, max
	// we first find the first k >= 0 such that low != high for the segment at index k

	//	the initial set of iterators at each index are as follows:
	//    for i < k finalValue[i] is set to true right away.
	//		we create an iterator from seg = new Seg(low)
	//    for i == k we create a wrapped iterator from Seg(low, high), wrapper will set finalValue[i] once we reach the final value of the iterator
	//    for i > k we create an iterator from Seg(low, max)
	//
	// after the initial iterator has been supplied, any further iterator supplied for the same segment is as follows:
	//    for i <= k, there was only one iterator, there will be no further iterator
	//    for i > k,
	//	  	if i == 0 or of if flagged[i - 1] is true, we create a wrapped iterator from Seg(low, high), wrapper will set finalValue[i] once we reach the final value of the iterator
	//      otherwise we create an iterator from Seg(min, max)
	//
	// By following these rules, we iterate through all possible addresses

	notDiffering := true
	finalValue[0] = true
	var allSegShared *IPAddressSegment
	for i := 0; i < divCount; i++ {
		var segIteratorProducer func(seg *IPAddressSegment, index int) IPSegmentIterator
		if prefixedSegIteratorProducer != nil && i >= networkSegmentIndex {
			segIteratorProducer = prefixedSegIteratorProducer
		} else {
			segIteratorProducer = segmentIteratorProducer
		}
		lowerSeg := segProducer(lower, i)
		indexi := i
		if notDiffering {
			notDiffering = segValueComparator(lower, upper, i)
			if notDiffering {
				// there is only one iterator and it produces only one value
				finalValue[i+1] = true
				iterator := segIteratorProducer(lowerSeg, i)
				segIteratorProducerList[i] = func() IPSegmentIterator { return iterator }
			} else {
				// in the first differing segment the only iterator will go from segment value of lower address to segment value of upper address
				iterator := segIteratorProducer(
					createAddressDivision(lowerSeg.deriveNewMultiSeg(lowerSeg.getSegmentValue(), upper.getSegment(i).getSegmentValue(), nil)).ToIPAddressSegment(),
					i)
				//creator.createSegment(lowerSeg.getSegmentValue(), upper.getSegment(i).getSegmentValue(), nil).ToIPAddressSegment(), i)
				wrappedFinalIterator := &wrappedIterator{
					iterator:   iterator,
					finalValue: finalValue,
					indexi:     indexi,
				}
				segIteratorProducerList[i] = func() IPSegmentIterator { return wrappedFinalIterator }
			}
		} else {
			// in the second and all following differing segments, rather than go from segment value of lower address to segment value of upper address
			// we go from segment value of lower address to the max seg value the first time through
			// then we go from the min value of the seg to the max seg value each time until the final time,
			// the final time we go from the min value to the segment value of upper address
			// we know it is the final time through when the previous iterator has reached its final value, which we track

			// the first iterator goes from the segment value of lower address to the max value of the segment
			firstIterator := segIteratorProducer(
				createAddressDivision(lowerSeg.deriveNewMultiSeg(lowerSeg.getSegmentValue(), lower.GetMaxSegmentValue(), nil)).ToIPAddressSegment(),
				//creator.createSegment(lowerSeg.getSegmentValue(), lower.GetMaxSegmentValue(), nil).ToIPAddressSegment(),
				i)

			// the final iterator goes from 0 to the segment value of our upper address
			finalIterator := segIteratorProducer(
				createAddressDivision(lowerSeg.deriveNewMultiSeg(0, upper.getSegment(i).getSegmentValue(), nil)).ToIPAddressSegment(),
				//creator.createSegment(0, upper.getSegment(i).getSegmentValue(), nil).ToIPAddressSegment(),
				i)

			// the wrapper iterator detects when the final iterator has reached its final value
			wrappedFinalIterator := &wrappedIterator{
				iterator:   finalIterator,
				finalValue: finalValue,
				indexi:     indexi,
			}
			if allSegShared == nil {
				allSegShared = createAddressDivision(lowerSeg.deriveNewMultiSeg(0, lower.getMaxSegmentValue(), nil)).ToIPAddressSegment()
				//allSegShared = creator.createSegment(0, lower.getMaxSegmentValue(), nil).ToIPAddressSegment()
			}
			// all iterators after the first iterator and before the final iterator go from 0 the max segment value,
			// and there will be many such iterators
			finalIteratorProducer := func() IPSegmentIterator {
				if finalValue[indexi] {
					return wrappedFinalIterator
				}
				return segIteratorProducer(allSegShared, indexi)
			}
			segIteratorProducerList[i] = func() IPSegmentIterator {
				//the first time through, we replace the iterator producer so the first iterator used only once (ie we remove this function from the list)
				segIteratorProducerList[indexi] = finalIteratorProducer
				return firstIterator
			}
		}
	}
	iteratorProducer := func(iteratorIndex int) SegmentIterator {
		iter := segIteratorProducerList[iteratorIndex]()
		return WrappedIPSegmentIterator{iter}
	}
	return rangeAddrIterator(
		false,
		lower.ToAddress(),
		valsAreMultiple,
		rangeSegmentsIterator(
			divCount,
			iteratorProducer,
			networkSegmentIndex,
			hostSegmentIndex,
			iteratorProducer,
		),
	)
}

var zeroRange = newSeqRange(zeroIPAddr, zeroIPAddr)

type IPAddressSeqRange struct {
	ipAddressSeqRangeInternal
}

func (rng IPAddressSeqRange) String() string {
	return rng.init().ipAddressSeqRangeInternal.String()
}

func (rng *IPAddressSeqRange) init() *IPAddressSeqRange {
	if rng.lower == nil {
		return zeroRange
	}
	return rng
}

func (rng *IPAddressSeqRange) GetLower() *IPAddress {
	return rng.init().lower
}

func (rng *IPAddressSeqRange) GetUpper() *IPAddress {
	return rng.init().upper
}

func (rng *IPAddressSeqRange) GetBitCount() BitCount {
	return rng.GetLower().GetBitCount()
}

func (rng *IPAddressSeqRange) GetByteCount() int {
	return rng.GetLower().GetByteCount()
}

func (rng *IPAddressSeqRange) GetIP() net.IP {
	return rng.GetBytes()
}

func (rng *IPAddressSeqRange) CopyIP(bytes net.IP) net.IP {
	return rng.CopyBytes(bytes)
}

func (rng *IPAddressSeqRange) GetUpperIP() net.IP {
	return rng.GetUpperBytes()
}

func (rng *IPAddressSeqRange) CopyUpperIP(bytes net.IP) net.IP {
	return rng.CopyUpperBytes(bytes)
}

func (rng *IPAddressSeqRange) GetBytes() []byte {
	return rng.GetLower().GetBytes()
}

func (rng *IPAddressSeqRange) CopyBytes(bytes []byte) []byte {
	return rng.GetLower().CopyBytes(bytes)
}

func (rng *IPAddressSeqRange) GetUpperBytes() []byte {
	return rng.GetUpper().GetUpperBytes()
}

func (rng *IPAddressSeqRange) CopyUpperBytes(bytes []byte) []byte {
	return rng.GetUpper().CopyUpperBytes(bytes)
}

func (rng *IPAddressSeqRange) Contains(other IPAddressType) bool {
	return rng.init().contains(other)
}

func (rng *IPAddressSeqRange) ContainsRange(other IPAddressSeqRangeType) bool {
	return rng.containsRange(other)
}

func (rng *IPAddressSeqRange) Equals(other IPAddressSeqRangeType) bool {
	return rng.init().equals(other)
}

func (rng *IPAddressSeqRange) GetValue() *big.Int {
	return rng.GetLower().GetValue()
}

func (rng *IPAddressSeqRange) GetUpperValue() *big.Int {
	return rng.GetUpper().GetValue()
}

func (rng *IPAddressSeqRange) Iterator() IPAddressIterator {
	return &ipAddrIterator{rng.init().iterator()}
}

func (rng *IPAddressSeqRange) PrefixBlockIterator(prefLength BitCount) IPAddressIterator {
	return &ipAddrIterator{rng.init().prefixBlockIterator(prefLength)}
}

func (rng *IPAddressSeqRange) PrefixIterator(prefLength BitCount) IPAddressSeqRangeIterator {
	return rng.init().prefixIterator(prefLength)
}

func (rng *IPAddressSeqRange) ToIPAddressSeqRange() *IPAddressSeqRange {
	return rng
}

func (rng *IPAddressSeqRange) IsIPv4SequentialRange() bool { // returns false when lower is nil
	return rng != nil && rng.GetLower().IsIPv4()
}

func (rng *IPAddressSeqRange) IsIPv6SequentialRange() bool { // returns false when lower is nil
	return rng != nil && rng.GetLower().IsIPv6()
}

func (rng *IPAddressSeqRange) ToIPv4SequentialRange() *IPv4AddressSeqRange {
	if rng.IsIPv4SequentialRange() {
		return (*IPv4AddressSeqRange)(rng)
	}
	return nil
}

func (rng *IPAddressSeqRange) ToIPv6SequentialRange() *IPv6AddressSeqRange {
	if rng.IsIPv6SequentialRange() {
		return (*IPv6AddressSeqRange)(rng)
	}
	return nil
}

func (rng *IPAddressSeqRange) Overlaps(other *IPAddressSeqRange) bool {
	return rng.init().overlaps(other)
}

func (rng *IPAddressSeqRange) Intersect(other *IPAddressSeqRange) *IPAddressSeqRange {
	return rng.init().intersect(other)
}

func newSeqRangeUnchecked(lower, upper *IPAddress, isMult bool) *IPAddressSeqRange {
	return &IPAddressSeqRange{
		ipAddressSeqRangeInternal{
			lower:      lower,
			upper:      upper,
			isMultiple: isMult,
			cache:      &rangeCache{},
		},
	}
}

func newSeqRange(first, other *IPAddress) *IPAddressSeqRange {
	var lower, upper *IPAddress
	var isMult bool
	if f := first.contains(other); f || other.contains(first) {
		var addr *IPAddress
		if f {
			addr = first.WithoutPrefixLen()
		} else {
			addr = other.WithoutPrefixLen()
		}
		lower = addr.GetLower()
		if isMult = addr.IsMultiple(); isMult {
			upper = addr.GetUpper()
		} else {
			upper = lower
		}
	} else {
		firstLower := first.GetLower()
		otherLower := other.GetLower()
		firstUpper := first.GetUpper()
		otherUpper := other.GetUpper()
		if comp := compareLowIPAddressValues(firstLower, otherLower); comp > 0 {
			isMult = true
			lower = otherLower
		} else {
			isMult = comp < 0
			lower = firstLower
		}
		if comp := compareLowIPAddressValues(firstUpper, otherUpper); comp < 0 {
			isMult = true
			upper = otherUpper
		} else {
			isMult = comp > 0
			upper = firstUpper
		}
		lower = lower.WithoutPrefixLen()
		if isMult = isMult || compareLowIPAddressValues(lower, upper) != 0; isMult {
			upper = upper.WithoutPrefixLen()
		} else {
			upper = lower
		}
	}
	return newSeqRangeUnchecked(lower, upper, isMult)
}

func compareLowValues(one, two *Address) int {
	return LowValueComparator.CompareAddresses(one, two)
}

func compareLowIPAddressValues(one, two *IPAddress) int {
	return LowValueComparator.CompareAddresses(one, two)
}

func checkSubnet(series AddressDivisionSeries, prefixLength BitCount) BitCount {
	return checkBitCount(prefixLength, series.GetBitCount())
}

func checkDiv(div DivisionType, prefixLength BitCount) BitCount {
	return checkBitCount(prefixLength, div.GetBitCount())
}

func checkBitCount(prefixLength, max BitCount) BitCount {
	if prefixLength > max {
		return max
	} else if prefixLength < 0 {
		return 0
	}
	return prefixLength
}

// wrapperIterator notifies the iterator to the right when wrapperIterator reaches its final value
type wrappedIterator struct {
	iterator   IPSegmentIterator
	finalValue []bool
	indexi     int
}

func (wrapped *wrappedIterator) HasNext() bool {
	return wrapped.iterator.HasNext()
}

func (wrapped *wrappedIterator) Next() *IPAddressSegment {
	iter := wrapped.iterator
	next := iter.Next()
	if !iter.HasNext() {
		wrapped.finalValue[wrapped.indexi+1] = true
	}
	return next
}
