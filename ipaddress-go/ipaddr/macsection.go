package ipaddr

import (
	"math/big"
	"unsafe"
)

//func (section *ipAddressSectionInternal) GetIPVersion() IPVersion (TODO need the MAC equivalent (ie EUI 64 or MAC 48, butcannot remember if there is a MAC equivalent)
//	if section.IsIPv4() {
//		return IPv4
//	}
//	return IPv6
//}

func createMACSection(segments []*AddressDivision) *MACAddressSection {
	return &MACAddressSection{
		addressSectionInternal{
			addressDivisionGroupingInternal{
				addressDivisionGroupingBase: addressDivisionGroupingBase{
					divisions: standardDivArray{segments},
					addrType:  macType,
					cache: &valueCache{
						stringCache: stringCache{
							macStringCache: &macStringCache{},
						},
					},
				},
			},
		},
	}
}

//TODO the constructors for MAC

func newMACAddressSectionParsed(segments []*AddressDivision) (res *MACAddressSection) {
	res = createMACSection(segments)
	_ = res.init()
	return
}

type MACAddressSection struct {
	addressSectionInternal
}

func (section *MACAddressSection) GetBitsPerSegment() BitCount {
	return MACBitsPerSegment
}

func (section *MACAddressSection) GetBytesPerSegment() int {
	return MACBytesPerSegment
}

func (section *MACAddressSection) GetCount() *big.Int {
	return section.cacheCount(func() *big.Int {
		return count(func(index int) uint64 {
			return section.GetSegment(index).GetValueCount()
		}, section.GetSegmentCount(), 6, 0x7fffffffffffff)
	})
}

func (section *MACAddressSection) GetPrefixCount() *big.Int {
	return section.cachePrefixCount(func() *big.Int {
		return section.GetPrefixCountLen(*section.GetPrefixLength())
	})
}

func (section *MACAddressSection) GetPrefixCountLen(prefixLen BitCount) *big.Int {
	if prefixLen <= 0 {
		return bigOne()
	} else if bc := section.GetBitCount(); prefixLen >= bc {
		return section.GetCount()
	}
	networkSegmentIndex := getNetworkSegmentIndex(prefixLen, section.GetBytesPerSegment(), section.GetBitsPerSegment())
	hostSegmentIndex := getHostSegmentIndex(prefixLen, section.GetBytesPerSegment(), section.GetBitsPerSegment())
	return section.calcCount(func() *big.Int {
		return count(func(index int) uint64 {
			if (networkSegmentIndex == hostSegmentIndex) && index == networkSegmentIndex {
				segmentPrefixLength := getPrefixedSegmentPrefixLength(section.GetBitsPerSegment(), prefixLen, index)
				return getPrefixValueCount(section.GetSegment(index).ToAddressSegment(), *segmentPrefixLength)
			}
			return section.GetSegment(index).GetValueCount()
		}, networkSegmentIndex+1, 6, 0x7fffffffffffff)
	})
}

func (section *MACAddressSection) WithoutPrefixLen() *MACAddressSection {
	return section.withoutPrefixLen().ToMACAddressSection()
}

func (section *MACAddressSection) SetPrefixLen(prefixLen BitCount) *MACAddressSection {
	return section.setPrefixLen(prefixLen).ToMACAddressSection()
}

func (section *MACAddressSection) SetPrefixLenZeroed(prefixLen BitCount) (*MACAddressSection, IncompatibleAddressError) {
	res, err := section.setPrefixLenZeroed(prefixLen)
	return res.ToMACAddressSection(), err
}

func (section *MACAddressSection) AssignPrefixForSingleBlock() *MACAddressSection {
	return section.assignPrefixForSingleBlock().ToMACAddressSection()
}

func (section *MACAddressSection) AssignMinPrefixForBlock() *MACAddressSection {
	return section.assignMinPrefixForBlock().ToMACAddressSection()
}

func (section *MACAddressSection) GetSegment(index int) *MACAddressSegment {
	return section.getDivision(index).ToMACAddressSegment()
}

func (section *MACAddressSection) ToAddressSection() *AddressSection {
	return (*AddressSection)(unsafe.Pointer(section))
}

// Gets the subsection from the series starting from the given index
// The first segment is at index 0.
func (section *MACAddressSection) GetTrailingSection(index int) *MACAddressSection {
	return section.GetSubSection(index, section.GetSegmentCount())
}

//// Gets the subsection from the series starting from the given index and ending just before the give endIndex
//// The first segment is at index 0.
func (section *MACAddressSection) GetSubSection(index, endIndex int) *MACAddressSection {
	return section.getSubSection(index, endIndex).ToMACAddressSection()
}

// CopySubSegments copies the existing segments from the given start index until but not including the segment at the given end index,
// into the given slice, as much as can be fit into the slice, returning the number of segments copied
func (section *MACAddressSection) CopySubSegments(start, end int, segs []*MACAddressSegment) (count int) {
	return section.visitSubSegments(start, end, func(index int, div *AddressDivision) bool { segs[index] = div.ToMACAddressSegment(); return false }, len(segs))
}

// CopySubSegments copies the existing segments from the given start index until but not including the segment at the given end index,
// into the given slice, as much as can be fit into the slice, returning the number of segments copied
func (section *MACAddressSection) CopySegments(segs []*MACAddressSegment) (count int) {
	return section.visitSegments(func(index int, div *AddressDivision) bool { segs[index] = div.ToMACAddressSegment(); return false }, len(segs))
}

// GetSegments returns a slice with the address segments.  The returned slice is not backed by the same array as this section.
func (section *MACAddressSection) GetSegments() (res []*MACAddressSegment) {
	res = make([]*MACAddressSegment, section.GetSegmentCount())
	section.CopySegments(res)
	return
}

func (section *MACAddressSection) GetLower() *MACAddressSection {
	return section.getLower().ToMACAddressSection()
}

func (section *MACAddressSection) GetUpper() *MACAddressSection {
	return section.getUpper().ToMACAddressSection()
}

func (section *MACAddressSection) Uint64Value() uint64 {
	return section.getLongValue(true)
}

func (section *MACAddressSection) UpperUint64Value() uint64 {
	return section.getLongValue(false)
}

func (section *MACAddressSection) getLongValue(lower bool) (result uint64) {
	segCount := section.GetSegmentCount()
	if segCount == 0 {
		return
	}
	seg := section.GetSegment(0)
	if lower {
		result = uint64(seg.GetSegmentValue())
	} else {
		result = uint64(seg.GetUpperSegmentValue())
	}
	bitsPerSegment := section.GetBitsPerSegment()
	for i := 1; i < segCount; i++ {
		result = (result << bitsPerSegment)
		seg = section.GetSegment(i)
		if lower {
			result |= uint64(seg.GetSegmentValue())
		} else {
			result |= uint64(seg.GetUpperSegmentValue())
		}
	}
	return
}

func (section *MACAddressSection) ToPrefixBlock() *MACAddressSection {
	return section.toPrefixBlock().ToMACAddressSection()
}

func (section *MACAddressSection) ToPrefixBlockLen(prefLen BitCount) *MACAddressSection {
	return section.toPrefixBlockLen(prefLen).ToMACAddressSection()
}

func (section *MACAddressSection) ToBlock(segmentIndex int, lower, upper SegInt) *MACAddressSection {
	return section.toBlock(segmentIndex, lower, upper).ToMACAddressSection()
}

func (section *MACAddressSection) Iterator() MACSectionIterator {
	return macSectionIterator{section.sectionIterator(nil)}
}

func (section *MACAddressSection) PrefixIterator() MACSectionIterator {
	return macSectionIterator{section.prefixIterator(false)}
}

func (section *MACAddressSection) PrefixBlockIterator() MACSectionIterator {
	return macSectionIterator{section.prefixIterator(true)}
}

func (section *MACAddressSection) IncrementBoundary(increment int64) *MACAddressSection {
	return section.incrementBoundary(increment).ToMACAddressSection()

}

func getMacMaxValueLong(segmentCount int) uint64 {
	return macMaxValues[segmentCount]
}

var macMaxValues = []uint64{
	0,
	MACMaxValuePerSegment,
	0xffff,
	0xffffff,
	0xffffffff,
	0xffffffffff,
	0xffffffffffff,
	0xffffffffffffff,
	0xffffffffffffffff}

func (section *MACAddressSection) Increment(incrementVal int64) *MACAddressSection {
	if incrementVal == 0 && !section.IsMultiple() {
		return section
	}
	segCount := section.GetSegmentCount()
	lowerValue := section.Uint64Value()
	upperValue := section.UpperUint64Value()
	count := section.GetCount()
	countMinus1 := count.Sub(count, bigOneConst()).Uint64()
	isOverflow := checkOverflow(incrementVal, lowerValue, upperValue, countMinus1, getMacMaxValueLong(segCount))
	if isOverflow {
		return nil
	}
	return increment(
		section.ToAddressSection(),
		incrementVal,
		DefaultMACNetwork.GetMACAddressCreator(),
		countMinus1,
		section.Uint64Value(),
		section.UpperUint64Value(),
		section.addressSectionInternal.getLower,
		section.addressSectionInternal.getUpper,
		section.GetPrefixLength()).ToMACAddressSection()
	//			}
	//			BigInteger lowerValue = getValue();
	//			BigInteger upperValue = getUpperValue();
	//			BigInteger count = getCount();
	//			BigInteger bigIncrement = BigInteger.valueOf(increment);
	//			checkOverflow(increment, bigIncrement, lowerValue, upperValue, count, () -> getMaxValue(getSegmentCount()));
	//			Integer prefixLength = getNetwork().getPrefixConfiguration().allPrefixedAddressesAreSubnets() ? null : getPrefixLength();
	//			MACAddressSection result = fastIncrement(
	//					this,
	//					increment,
	//					getAddressCreator(),
	//					this::getLower,
	//					this::getUpper,
	//					prefixLength);
	//			if(result != null) {
	//				return result;
	//			}
	//			return increment(
	//					this,
	//					increment,
	//					bigIncrement,
	//					getAddressCreator(),
	//					this::getLower,
	//					this::getUpper,
	//					getNetwork().getPrefixConfiguration().allPrefixedAddressesAreSubnets() ? null : getPrefixLength());
	//
	//*/
	//return nil
}

var (
	canonicalWildcards = new(WildcardsBuilder).SetRangeSeparator(MacDashedSegmentRangeSeparatorStr).SetWildcard(SegmentWildcardStr).ToWildcards()

	//macHexParams         = NewMACStringOptionsBuilder().SetHasSeparator(false).SetExpandedSegments(true).ToOptions()
	//macHexPrefixedParams = NewMACStringOptionsBuilder().SetHasSeparator(false).SetExpandedSegments(true).SetAddressLabel(HexPrefix).ToOptions()
	macNormalizedParams  = NewMACStringOptionsBuilder().SetExpandedSegments(true).ToOptions()
	macCanonicalParams   = NewMACStringOptionsBuilder().SetSeparator(MACDashSegmentSeparator).SetExpandedSegments(true).SetWildcards(canonicalWildcards).ToOptions()
	macCompressedParams  = NewMACStringOptionsBuilder().ToOptions()
	dottedParams         = NewMACStringOptionsBuilder().SetSeparator(MacDottedSegmentSeparator).SetExpandedSegments(true).ToOptions()
	spaceDelimitedParams = NewMACStringOptionsBuilder().SetSeparator(MacSpaceSegmentSeparator).SetExpandedSegments(true).ToOptions()
)

// ToCanonicalString produces a canonical string.
//
//If this section has a prefix length, it will be included in the string.
func (section *MACAddressSection) ToCanonicalString() string {
	return cacheStr(&section.getStringCache().canonicalString,
		func() string {
			return section.toNormalizedOptsString(macCanonicalParams)
		})
}

func (section *MACAddressSection) ToNormalizedString() string {
	cch := section.getStringCache()
	strp := &cch.normalizedMACString
	return cacheStr(strp,
		func() string {
			return section.toNormalizedOptsString(macNormalizedParams)
		})
}

func (section *MACAddressSection) ToCompressedString() string {
	return cacheStr(&section.getStringCache().compressedMACString,
		func() string {
			return section.toNormalizedOptsString(macCompressedParams)
		})
}

// ToDottedString produces the dotted hexadecimal format aaaa.bbbb.cccc
func (section *MACAddressSection) ToDottedString() (string, IncompatibleAddressError) {
	return cacheStrErr(&section.getStringCache().dottedString,
		func() (string, IncompatibleAddressError) {
			dottedGrouping, err := section.GetDottedGrouping()
			if err != nil {
				return "", err
			}
			//getStringCache().dottedString = result = toNormalizedString(MACStringCache.dottedParams, dottedGrouping);
			//return section.toNormalizedOptsString(dottedParams)
			return toNormalizedString(dottedParams, dottedGrouping), nil

			//return ""
		})
}

func (section *MACAddressSection) GetDottedGrouping() (AddressDivisionSeries, IncompatibleAddressError) {
	start := section.addressSegmentIndex
	segmentCount := section.GetSegmentCount()
	var newSegs []*AddressDivision
	newSegmentBitCount := section.GetBitsPerSegment() << 1
	var segIndex, newSegIndex int
	if (start & 1) == 0 {
		newSegmentCount := (segmentCount + 1) >> 1
		newSegs = make([]*AddressDivision, newSegmentCount)
		//newSegIndex = segIndex = 0;
	} else {
		newSegmentCount := (segmentCount >> 1) + 1
		newSegs = make([]*AddressDivision, newSegmentCount)
		segment := section.GetSegment(0)
		vals := &bitsDivisionVals{
			value:      segment.getDivisionValue(),
			upperValue: segment.getUpperDivisionValue(),
			bitCount:   newSegmentBitCount,
			radix:      MACDefaultTextualRadix,
			//joinedCount: joinCount,
			//prefixLen:   nil,
		}
		newSegs[0] = createAddressDivision(vals)

		//newSegs[0] = new AddressBitsDivision(segment.getSegmentValue(),
		//	segment.getUpperSegmentValue(),
		//	newSegmentBitCount, MACDefaultTextualRadix);
		newSegIndex = 1
		segIndex = 1
	}
	bitsPerSeg := section.GetBitsPerSegment()
	for segIndex+1 < segmentCount {
		segment1 := section.GetSegment(segIndex)
		segIndex++
		segment2 := section.GetSegment(segIndex)
		segIndex++
		if segment1.isMultiple() && !segment2.IsFullRange() {
			return nil, &incompatibleAddressError{addressError{key: "ipaddress.error.invalid.joined.ranges"}}
			//throw new IncompatibleAddressError(segment1, segIndex - 2, segment2, segIndex - 1, "ipaddress.error.invalid.joined.ranges");
		}
		vals := &bitsDivisionVals{
			value:      DivInt((segment1.GetSegmentValue() << bitsPerSeg) | segment2.GetSegmentValue()),
			upperValue: DivInt((segment1.GetUpperSegmentValue() << bitsPerSeg) | segment2.GetUpperSegmentValue()),
			bitCount:   newSegmentBitCount,
			radix:      MACDefaultTextualRadix,
			//joinedCount: joinCount,
			//prefixLen:   nil,
		}
		newSegs[newSegIndex] = createAddressDivision(vals)
		newSegIndex++
		//AddressDivision newSeg = new AddressBitsDivision(
		//		(segment1.GetSegmentValue() << getBitsPerSegment()) | segment2.GetSegmentValue(),
		//		(segment1.GetUpperSegmentValue() << getBitsPerSegment()) | segment2.GetUpperSegmentValue(),
		//		newSegmentBitCount,
		//		MACDefaultTextualRadix);
		//newSegs[newSegIndex++] = newSeg;
	}
	if segIndex < segmentCount {
		segment := section.GetSegment(segIndex)
		vals := &bitsDivisionVals{
			value:      DivInt(segment.GetSegmentValue() << bitsPerSeg),
			upperValue: DivInt(segment.GetUpperSegmentValue() << bitsPerSeg),
			bitCount:   newSegmentBitCount,
			radix:      MACDefaultTextualRadix,
			//joinedCount: joinCount,
			//prefixLen:   nil,
		}
		newSegs[newSegIndex] = createAddressDivision(vals)
		//			newSegs[newSegIndex] = new AddressBitsDivision(
		//					segment.getSegmentValue() << bitsPerSeg,
		//					segment.getUpperSegmentValue() << bitsPerSeg,
		//					newSegmentBitCount,
		//MACDefaultTextualRadix);
	}
	grouping := createInitializedGrouping(newSegs, section.GetPrefixLength(), zeroType, start)
	return grouping, nil
	//AddressDivisionGrouping dottedGrouping;
	//if(cachedPrefixLength == null) {
	//	dottedGrouping = new AddressDivisionGrouping(newSegs);
	//} else {
	//	Integer prefLength = cachedPrefixLength;
	//	dottedGrouping = new AddressDivisionGrouping(newSegs) {{
	//		cachedPrefixLength = prefLength;
	//	}};
	//}
	//return dottedGrouping;
}

// ToSpaceDelimitedString produces a string delimited by spaces: aa bb cc dd ee ff
func (section *MACAddressSection) ToSpaceDelimitedString() string {
	return cacheStr(&section.getStringCache().spaceDelimitedString,
		func() string {
			return section.toNormalizedOptsString(spaceDelimitedParams)
		})
}

func (section *MACAddressSection) ToDashedString() string {
	return section.ToCanonicalString()
}

func (section *MACAddressSection) ToColonDelimitedString() string {
	return section.ToNormalizedString()
}

//AddressBitsDivision

//TODO make public?  the derive and deriveNew all have prefix length - also, making these public can be awkward, exposing internals of divisions
// So I think instead you need a NewBitsDivisionVals or something that returns *AddressDivision
// divisionValues is anon field right now, so if that becomes public, cannot be anon anymore
type bitsDivisionVals struct {
	value, upperValue DivInt
	bitCount          BitCount
	radix             int
	cache             divCache
}

func (div bitsDivisionVals) getBitCount() BitCount {
	return div.bitCount
}

func (div bitsDivisionVals) getByteCount() int {
	return int((div.getBitCount() + 3) >> 3)
}

func (div bitsDivisionVals) getValue() *BigDivInt {
	return big.NewInt(int64(div.value))
}

func (div bitsDivisionVals) getUpperValue() *BigDivInt {
	return big.NewInt(int64(div.upperValue))
}

func (div bitsDivisionVals) includesZero() bool {
	return div.getDivisionValue() == 0
}

func (div bitsDivisionVals) includesMax() bool {
	return div.getUpperDivisionValue() == ^(^DivInt(0) << div.getBitCount())
}

func (div bitsDivisionVals) isMultiple() bool {
	return div.getDivisionValue() != div.getUpperDivisionValue()
}

func (div bitsDivisionVals) getCount() *big.Int {
	return big.NewInt(int64((div.getUpperDivisionValue() - div.getDivisionValue()) + 1))
}

func (div bitsDivisionVals) calcBytesInternal() (bytes, upperBytes []byte) {
	return calcBytesInternal(div.getByteCount(), div.getDivisionValue(), div.getUpperDivisionValue())
}

func (div bitsDivisionVals) getCache() *divCache {
	return &div.cache
}

func (div bitsDivisionVals) getAddrType() addrType {
	return zeroType // macType means convertible to MAC segment, which this is not
}

func (div bitsDivisionVals) getDivisionPrefixLength() PrefixLen {
	return nil
}

func (div bitsDivisionVals) getDivisionValue() DivInt {
	return div.value
}

func (div bitsDivisionVals) getUpperDivisionValue() DivInt {
	return div.upperValue
}

func (div bitsDivisionVals) deriveNew(val, upperVal DivInt, prefLen PrefixLen) divisionValues {
	return &bitsDivisionVals{
		value:      val,
		upperValue: upperVal,
		bitCount:   div.bitCount,
		radix:      div.radix,
	}
}

func (div bitsDivisionVals) getSegmentValue() SegInt {
	panic("implement me")
}

func (div bitsDivisionVals) getUpperSegmentValue() SegInt {
	panic("implement me")
}

func (div bitsDivisionVals) deriveNewMultiSeg(val, upperVal SegInt, prefLen PrefixLen) divisionValues {
	return &bitsDivisionVals{
		value:      DivInt(val),
		upperValue: DivInt(upperVal),
		bitCount:   div.bitCount,
		radix:      div.radix,
	}
}

func (div bitsDivisionVals) deriveNewSeg(val SegInt, prefLen PrefixLen) divisionValues {
	return &bitsDivisionVals{
		value:      DivInt(val),
		upperValue: DivInt(val),
		bitCount:   div.bitCount,
		radix:      div.radix,
	}
}

var _ divisionValues = &bitsDivisionVals{}
