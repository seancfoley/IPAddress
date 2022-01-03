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

package ipaddr

import (
	"math/big"
	"math/bits"
	"strings"
	"sync/atomic"
	"unsafe"

	"github.com/seancfoley/ipaddress/ipaddress-go/ipaddr/addrerr"
)

type ipAddressSegmentInternal struct {
	addressSegmentInternal
}

func (seg *ipAddressSegmentInternal) isPrefixed() bool {
	return seg.GetSegmentPrefixLen() != nil
}

func (seg *ipAddressSegmentInternal) IsPrefixBlock() bool {
	return seg.isPrefixBlock()
}

func (seg *ipAddressSegmentInternal) IsSinglePrefixBlock() bool {
	cache := seg.getCache()
	if cache == nil {
		if prefLen := seg.GetSegmentPrefixLen(); prefLen != nil {
			return seg.isSinglePrefixBlock(seg.getDivisionValue(), seg.getUpperDivisionValue(), prefLen.bitCount())
		}
		return false
	}
	res := cache.isSinglePrefBlock
	if res == nil {
		var result bool
		if prefLen := seg.GetSegmentPrefixLen(); prefLen != nil {
			result = seg.isSinglePrefixBlock(seg.getDivisionValue(), seg.getUpperDivisionValue(), prefLen.bitCount())
		}
		if result {
			res = &trueVal
		} else {
			res = &falseVal
		}
		dataLoc := (*unsafe.Pointer)(unsafe.Pointer(&cache.isSinglePrefBlock))
		atomic.StorePointer(dataLoc, unsafe.Pointer(res))
	}
	return *res
}

func (seg *ipAddressSegmentInternal) withoutPrefixLen() *IPAddressSegment {
	if seg.isPrefixed() {
		vals := seg.deriveNewMultiSeg(seg.GetSegmentValue(), seg.GetUpperSegmentValue(), nil)
		return createAddressDivision(vals).ToIP()
	}
	return seg.toIPAddressSegment()
}

func (seg *ipAddressSegmentInternal) GetPrefixValueCount() SegIntCount {
	prefixLength := seg.GetSegmentPrefixLen()
	if prefixLength == nil {
		return seg.GetValueCount()
	}
	return getPrefixValueCount(seg.toAddressSegment(), prefixLength.bitCount())
}

func (seg *ipAddressSegmentInternal) GetSegmentPrefixLen() PrefixLen {
	return seg.getDivisionPrefixLength()
}

func (seg *ipAddressSegmentInternal) MatchesWithPrefixMask(value SegInt, networkBits BitCount) bool {
	mask := seg.GetSegmentNetworkMask(networkBits)
	matchingValue := value & mask
	return matchingValue == (seg.GetSegmentValue()&mask) && matchingValue == (seg.GetUpperSegmentValue()&mask)
}

func (seg *ipAddressSegmentInternal) checkForPrefixMask() (networkMaskLen, hostMaskLen PrefixLen) {
	val := seg.GetSegmentValue()
	if val == 0 {
		networkMaskLen, hostMaskLen = cacheBitCount(0), cacheBitCount(seg.GetBitCount())
	} else {
		maxVal := seg.GetMaxValue()
		if val == maxVal {
			networkMaskLen, hostMaskLen = cacheBitCount(seg.GetBitCount()), cacheBitCount(0)
		} else {
			var shifted SegInt
			trailingOnes := seg.GetTrailingBitCount(true)
			if trailingOnes == 0 {
				// can only be 11110000 and not 00000000
				trailingZeros := seg.GetTrailingBitCount(false)
				shifted = (^val & maxVal) >> uint(trailingZeros)
				if shifted == 0 {
					networkMaskLen = cacheBitCount(seg.GetBitCount() - trailingZeros)
				}
			} else {
				// can only be 00001111 and not 11111111
				shifted = val >> uint(trailingOnes)
				if shifted == 0 {
					hostMaskLen = cacheBitCount(seg.GetBitCount() - trailingOnes)
				}
			}
		}
	}
	return
}

// GetBlockMaskPrefixLen returns the prefix length if this address section is equivalent to the mask for a CIDR prefix block.
// Otherwise, it returns null.
// A CIDR network mask is an address with all 1s in the network section and then all 0s in the host section.
// A CIDR host mask is an address with all 0s in the network section and then all 1s in the host section.
// The prefix length is the length of the network section.
//
// Also, keep in mind that the prefix length returned by this method is not equivalent to the prefix length of this object,
// indicating the network and host section of this address.
// The prefix length returned here indicates the whether the value of this address can be used as a mask for the network and host
// section of any other address.  Therefore the two values can be different values, or one can be null while the other is not.
//
// This method applies only to the lower value of the range if this section represents multiple values.
func (seg *ipAddressSegmentInternal) GetBlockMaskPrefixLen(network bool) PrefixLen {
	hostLength := seg.GetTrailingBitCount(!network)
	var shifted SegInt
	val := seg.GetSegmentValue()
	if network {
		maxVal := seg.GetMaxValue()
		shifted = (^val & maxVal) >> uint(hostLength)
	} else {
		shifted = val >> uint(hostLength)
	}
	if shifted == 0 {
		return cacheBitCount(seg.GetBitCount() - hostLength)
	}
	return nil
}

// GetTrailingBitCount returns the number of consecutive trailing one or zero bits.
// If ones is true, returns the number of consecutive trailing zero bits.
// Otherwise, returns the number of consecutive trailing one bits.
//
// This method applies only to the lower value of the range if this segment represents multiple values.
func (seg *ipAddressSegmentInternal) GetTrailingBitCount(ones bool) BitCount {
	val := seg.GetSegmentValue()
	if ones {
		// trailing ones
		return BitCount(bits.TrailingZeros32(uint32(^val)))
	}
	//trailing zeros
	bitCount := uint(seg.GetBitCount())
	return BitCount(bits.TrailingZeros32(uint32(val | (1 << bitCount))))
}

//	GetLeadingBitCount returns the number of consecutive leading one or zero bits.
// If ones is true, returns the number of consecutive leading one bits.
// Otherwise, returns the number of consecutive leading zero bits.
//
// This method applies only to the lower value of the range if this segment represents multiple values.
func (seg *ipAddressSegmentInternal) GetLeadingBitCount(ones bool) BitCount {
	extraLeading := 32 - seg.GetBitCount()
	val := seg.GetSegmentValue()
	if ones {
		//leading ones
		return BitCount(bits.LeadingZeros32(uint32(^val&seg.GetMaxValue()))) - extraLeading
	}
	// leading zeros
	return BitCount(bits.LeadingZeros32(uint32(val))) - extraLeading
}

func (seg *ipAddressSegmentInternal) getUpperStringMasked(radix int, uppercase bool, appendable *strings.Builder) {
	if seg.isPrefixed() {
		upperValue := seg.GetUpperSegmentValue()
		mask := seg.GetSegmentNetworkMask(seg.GetSegmentPrefixLen().bitCount())
		upperValue &= mask
		toUnsignedStringCased(DivInt(upperValue), radix, 0, uppercase, appendable)
	} else {
		seg.getUpperString(radix, uppercase, appendable)
	}
}

func (seg *ipAddressSegmentInternal) getStringAsLower() string {
	if seg.divisionValues != nil {
		if cache := seg.getCache(); cache != nil {
			return cacheStr(&cache.cachedString, seg.getDefaultLowerString)
		}
	}
	return seg.getDefaultLowerString()
}

func (seg *ipAddressSegmentInternal) getString() string {
	stringer := func() string {
		if !seg.isMultiple() || seg.IsSinglePrefixBlock() { //covers the case of !isMult, ie single addresses, when there is no prefix or the prefix is the bit count
			return seg.getDefaultLowerString()
		} else if seg.IsFullRange() {
			return seg.getDefaultSegmentWildcardString()
		}
		upperValue := seg.getUpperSegmentValue()
		if seg.IsPrefixBlock() {
			upperValue &= seg.GetSegmentNetworkMask(seg.getDivisionPrefixLength().bitCount())
		}
		return seg.getDefaultRangeStringVals(seg.getDivisionValue(), DivInt(upperValue), seg.getDefaultTextualRadix())
	}
	if seg.divisionValues != nil {
		if cache := seg.getCache(); cache != nil {
			return cacheStr(&cache.cachedString, stringer)
		}
	}
	return stringer()
}

func (seg *ipAddressSegmentInternal) getWildcardString() string {
	stringer := func() string {
		if !seg.isPrefixed() || !seg.isMultiple() {
			return seg.getString()
		} else if seg.IsFullRange() {
			return seg.getDefaultSegmentWildcardString()
		}
		return seg.getDefaultRangeString()
	}
	if seg.divisionValues != nil {
		if cache := seg.getCache(); cache != nil {
			return cacheStr(&cache.cachedWildcardString, stringer)
		}
	}
	return stringer()
}

func (seg *ipAddressSegmentInternal) setStandardString(
	addressStr string,
	isStandardString bool,
	lowerStringStartIndex,
	lowerStringEndIndex int,
	originalLowerValue SegInt) {
	if cache := seg.getCache(); cache != nil {
		if cache.cachedString == nil && isStandardString && originalLowerValue == seg.getSegmentValue() {
			str := addressStr[lowerStringStartIndex:lowerStringEndIndex]
			cacheStrPtr(&cache.cachedString, &str)
		}
	}
}

func (seg *ipAddressSegmentInternal) setWildcardString(
	addressStr string,
	isStandardString bool,
	lowerStringStartIndex,
	lowerStringEndIndex int,
	lowerValue SegInt) {
	if cache := seg.getCache(); cache != nil {
		if cache.cachedWildcardString == nil && isStandardString && lowerValue == seg.getSegmentValue() && lowerValue == seg.getUpperSegmentValue() {
			str := addressStr[lowerStringStartIndex:lowerStringEndIndex]
			cacheStrPtr(&cache.cachedWildcardString, &str)
		}
	}
}

func (seg *ipAddressSegmentInternal) setRangeStandardString(
	addressStr string,
	isStandardString,
	isStandardRangeString bool,
	lowerStringStartIndex,
	lowerStringEndIndex,
	upperStringEndIndex int,
	rangeLower,
	rangeUpper SegInt) {
	if cache := seg.getCache(); cache != nil {
		if cache.cachedString == nil {
			if seg.IsSinglePrefixBlock() {
				if isStandardString && rangeLower == seg.getSegmentValue() {
					str := addressStr[lowerStringStartIndex:lowerStringEndIndex]
					cacheStrPtr(&cache.cachedString, &str)
				}
			} else if seg.IsFullRange() {
				cacheStrPtr(&cache.cachedString, &segmentWildcardStr)
			} else if isStandardRangeString && rangeLower == seg.getSegmentValue() {
				upper := seg.getUpperSegmentValue()
				if seg.isPrefixed() {
					upper &= seg.GetSegmentNetworkMask(seg.getDivisionPrefixLength().bitCount())
				}
				if rangeUpper == upper {
					str := addressStr[lowerStringStartIndex:upperStringEndIndex]
					cacheStrPtr(&cache.cachedString, &str)
				}
			}
		}
	}
}

func (seg *ipAddressSegmentInternal) setRangeWildcardString(
	addressStr string,
	isStandardRangeString bool,
	lowerStringStartIndex,
	upperStringEndIndex int,
	rangeLower,
	rangeUpper SegInt) {
	if cache := seg.getCache(); cache != nil {
		if cache.cachedWildcardString == nil {
			if seg.IsFullRange() {
				cacheStrPtr(&cache.cachedWildcardString, &segmentWildcardStr)
			} else if isStandardRangeString && rangeLower == seg.getSegmentValue() && rangeUpper == seg.getUpperSegmentValue() {
				str := addressStr[lowerStringStartIndex:upperStringEndIndex]
				cacheStrPtr(&cache.cachedWildcardString, &str)
			}
		}
	}
}

func (seg *ipAddressSegmentInternal) GetSegmentNetworkMask(networkBits BitCount) SegInt {
	bc := seg.GetBitCount()
	networkBits = checkBitCount(networkBits, bc)
	return seg.GetMaxValue() & (^SegInt(0) << uint(bc-networkBits))
}

func (seg *ipAddressSegmentInternal) GetSegmentHostMask(networkBits BitCount) SegInt {
	bc := seg.GetBitCount()
	networkBits = checkBitCount(networkBits, bc)
	return ^(^SegInt(0) << uint(bc-networkBits))
}

func (seg *ipAddressSegmentInternal) toIPAddressSegment() *IPAddressSegment {
	return (*IPAddressSegment)(unsafe.Pointer(seg))
}

//// only needed for godoc / pkgsite

func (seg *ipAddressSegmentInternal) GetBitCount() BitCount {
	return seg.addressSegmentInternal.GetBitCount()
}

func (seg *ipAddressSegmentInternal) GetByteCount() int {
	return seg.addressSegmentInternal.GetByteCount()
}

func (seg *ipAddressSegmentInternal) GetValue() *BigDivInt {
	return seg.addressSegmentInternal.GetValue()
}

func (seg *ipAddressSegmentInternal) GetUpperValue() *BigDivInt {
	return seg.addressSegmentInternal.GetUpperValue()
}

func (seg *ipAddressSegmentInternal) Bytes() []byte {
	return seg.addressSegmentInternal.Bytes()
}

func (seg *ipAddressSegmentInternal) UpperBytes() []byte {
	return seg.addressSegmentInternal.UpperBytes()
}

func (seg *ipAddressSegmentInternal) CopyBytes(bytes []byte) []byte {
	return seg.addressSegmentInternal.CopyBytes(bytes)
}

func (seg *ipAddressSegmentInternal) CopyUpperBytes(bytes []byte) []byte {
	return seg.addressSegmentInternal.CopyUpperBytes(bytes)
}

func (seg *ipAddressSegmentInternal) IsZero() bool {
	return seg.addressSegmentInternal.IsZero()
}

func (seg *ipAddressSegmentInternal) IncludesZero() bool {
	return seg.addressSegmentInternal.IncludesZero()
}

func (seg *ipAddressSegmentInternal) IsMax() bool {
	return seg.addressSegmentInternal.IsMax()
}

func (seg *ipAddressSegmentInternal) IncludesMax() bool {
	return seg.addressSegmentInternal.IncludesMax()
}

func (seg *ipAddressSegmentInternal) IsFullRange() bool {
	return seg.addressSegmentInternal.IsFullRange()
}

func (seg *ipAddressSegmentInternal) ContainsPrefixBlock(prefixLen BitCount) bool {
	return seg.addressSegmentInternal.ContainsPrefixBlock(prefixLen)
}

func (seg *ipAddressSegmentInternal) ContainsSinglePrefixBlock(prefixLen BitCount) bool {
	return seg.addressSegmentInternal.ContainsSinglePrefixBlock(prefixLen)
}

func (seg *ipAddressSegmentInternal) GetMinPrefixLenForBlock() BitCount {
	return seg.addressSegmentInternal.GetMinPrefixLenForBlock()
}

func (seg *ipAddressSegmentInternal) GetPrefixLenForSingleBlock() PrefixLen {
	return seg.addressSegmentInternal.GetPrefixLenForSingleBlock()
}

func (seg *ipAddressSegmentInternal) IsSinglePrefix(divisionPrefixLength BitCount) bool {
	return seg.addressSegmentInternal.IsSinglePrefix(divisionPrefixLength)
}

func (seg *ipAddressSegmentInternal) PrefixContains(other AddressSegmentType, prefixLength BitCount) bool {
	return seg.addressSegmentInternal.PrefixContains(other, prefixLength)
}

func (seg *ipAddressSegmentInternal) PrefixEqual(other AddressSegmentType, prefixLength BitCount) bool {
	return seg.addressSegmentInternal.PrefixEqual(other, prefixLength)
}

func (seg *ipAddressSegmentInternal) GetSegmentValue() SegInt {
	return seg.addressSegmentInternal.GetSegmentValue()
}

func (seg *ipAddressSegmentInternal) GetUpperSegmentValue() SegInt {
	return seg.addressSegmentInternal.GetUpperSegmentValue()
}

func (seg *ipAddressSegmentInternal) Matches(value SegInt) bool {
	return seg.addressSegmentInternal.Matches(value)
}

func (seg *ipAddressSegmentInternal) MatchesWithMask(value, mask SegInt) bool {
	return seg.addressSegmentInternal.MatchesWithMask(value, mask)
}

func (seg *ipAddressSegmentInternal) MatchesValsWithMask(lowerValue, upperValue, mask SegInt) bool {
	return seg.addressSegmentInternal.MatchesValsWithMask(lowerValue, upperValue, mask)
}

func (seg *ipAddressSegmentInternal) GetPrefixCountLen(segmentPrefixLength BitCount) *big.Int {
	return seg.addressSegmentInternal.GetPrefixCountLen(segmentPrefixLength)
}

func (seg *ipAddressSegmentInternal) GetPrefixValueCountLen(segmentPrefixLength BitCount) SegIntCount {
	return seg.addressSegmentInternal.GetPrefixValueCountLen(segmentPrefixLength)
}

func (seg *ipAddressSegmentInternal) GetValueCount() SegIntCount {
	return seg.addressSegmentInternal.GetValueCount()
}

func (seg *ipAddressSegmentInternal) GetMaxValue() SegInt {
	return seg.addressSegmentInternal.GetMaxValue()
}

func (seg *ipAddressSegmentInternal) TestBit(n BitCount) bool {
	return seg.addressSegmentInternal.TestBit(n)
}

func (seg *ipAddressSegmentInternal) IsOneBit(segmentBitIndex BitCount) bool {
	return seg.addressSegmentInternal.IsOneBit(segmentBitIndex)
}

func (seg *ipAddressSegmentInternal) ToNormalizedString() string {
	return seg.addressSegmentInternal.ToNormalizedString()
}

func (seg *ipAddressSegmentInternal) ToHexString(with0xPrefix bool) (string, addrerr.IncompatibleAddressError) {
	return seg.addressSegmentInternal.ToHexString(with0xPrefix)
}

func (seg *ipAddressSegmentInternal) ReverseBits(perByte bool) (res *AddressSegment, err addrerr.IncompatibleAddressError) {
	return seg.addressSegmentInternal.ReverseBits(perByte)
}

func (seg *ipAddressSegmentInternal) ReverseBytes() (res *AddressSegment, err addrerr.IncompatibleAddressError) {
	return seg.addressSegmentInternal.ReverseBytes()
}

//// end needed for godoc / pkgsite

type IPAddressSegment struct {
	ipAddressSegmentInternal
}

func (seg *IPAddressSegment) GetLower() *IPAddressSegment {
	return seg.getLower().ToIP()
}

func (seg *IPAddressSegment) GetUpper() *IPAddressSegment {
	return seg.getUpper().ToIP()
}

func (seg *IPAddressSegment) IsMultiple() bool {
	return seg != nil && seg.isMultiple()
}

func (seg *IPAddressSegment) GetCount() *big.Int {
	if seg == nil {
		return bigZero()
	}
	return seg.getCount()
}

func (seg *IPAddressSegment) Contains(other AddressSegmentType) bool {
	if seg == nil {
		return other == nil || other.ToSegmentBase() == nil
	}
	return seg.contains(other)
}

func (seg *IPAddressSegment) Equal(other AddressSegmentType) bool {
	if seg == nil {
		return other == nil || other.ToDiv() == nil
		//return seg.getAddrType() == zeroType && other.(StandardDivisionType).ToDiv() == nil
	}
	return seg.equal(other)
}

func (seg *IPAddressSegment) Compare(item AddressItem) int {
	return CountComparator.Compare(seg, item)
}

func (seg *IPAddressSegment) ContainsPrefixBlock(divisionPrefixLen BitCount) bool {
	return seg.containsPrefixBlock(divisionPrefixLen)
}

func (seg *IPAddressSegment) ToPrefixedNetworkSegment(segmentPrefixLength PrefixLen) *IPAddressSegment {
	return seg.toPrefixedNetworkDivision(segmentPrefixLength).ToIP()
}

func (seg *IPAddressSegment) ToNetworkSegment(segmentPrefixLength PrefixLen) *IPAddressSegment {
	return seg.toNetworkDivision(segmentPrefixLength, false).ToIP()
}

func (seg *IPAddressSegment) ToPrefixedHostSegment(segmentPrefixLength PrefixLen) *IPAddressSegment {
	return seg.toPrefixedHostDivision(segmentPrefixLength).ToIP()
}

func (seg *IPAddressSegment) ToHostSegment(segmentPrefixLength PrefixLen) *IPAddressSegment {
	return seg.toHostDivision(segmentPrefixLength, false).ToIP()
}

func (seg *IPAddressSegment) Iterator() IPSegmentIterator {
	if seg == nil {
		return ipSegmentIterator{nilSegIterator()}
	}
	return ipSegmentIterator{seg.iterator()}
}

func (seg *IPAddressSegment) PrefixBlockIterator() IPSegmentIterator {
	return ipSegmentIterator{seg.prefixBlockIterator()}
}

func (seg *IPAddressSegment) PrefixedBlockIterator(segmentPrefixLen BitCount) IPSegmentIterator {
	return ipSegmentIterator{seg.prefixedBlockIterator(segmentPrefixLen)}
}

func (seg *IPAddressSegment) PrefixIterator() IPSegmentIterator {
	return ipSegmentIterator{seg.prefixIterator()}
}

func (seg *IPAddressSegment) IsPrefixed() bool {
	return seg != nil && seg.isPrefixed()
}

func (seg *IPAddressSegment) WithoutPrefixLen() *IPAddressSegment {
	if !seg.IsPrefixed() {
		return seg
	}
	return seg.withoutPrefixLen()
}

func (seg *IPAddressSegment) IsIPv4() bool {
	return seg != nil && seg.matchesIPv4Segment()
}

func (seg *IPAddressSegment) IsIPv6() bool {
	return seg != nil && seg.matchesIPv6Segment()
}

func (seg *IPAddressSegment) ToSegmentBase() *AddressSegment {
	return (*AddressSegment)(unsafe.Pointer(seg))
}

func (seg *IPAddressSegment) ToDiv() *AddressDivision {
	return seg.ToSegmentBase().ToDiv()
}

func (seg *IPAddressSegment) ToIPv4() *IPv4AddressSegment {
	if seg.IsIPv4() {
		return (*IPv4AddressSegment)(seg)
	}
	return nil
}

func (seg *IPAddressSegment) ToIPv6() *IPv6AddressSegment {
	if seg.IsIPv6() {
		return (*IPv6AddressSegment)(seg)
	}
	return nil
}

func (seg *IPAddressSegment) GetString() string {
	if seg == nil {
		return nilString()
	}
	return seg.getString()
}

func (seg *IPAddressSegment) GetWildcardString() string {
	if seg == nil {
		return nilString()
	}
	return seg.getWildcardString()
}

func (seg *IPAddressSegment) String() string {
	if seg == nil {
		return nilString()
	}
	return seg.toString()
}
