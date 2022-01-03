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
	"fmt"
	"math/big"
	"sync/atomic"
	"unsafe"
)

type addressDivisionGroupingBase struct {
	// the non-cacheBitCountx elements are assigned at creation and are immutable
	divisions divArray // either standard or large

	prefixLength PrefixLen // must align with the divisions if they store prefix lengths
	isMult       bool

	// When a top-level section is created, it is assigned an address type, IPv4, IPv6, or MAC,
	// and determines if an *AddressDivisionGrouping can be converted back to a section of the original type.
	//
	// Type-specific functions in IPAddressSection and lower levels, such as functions returning strings,
	// can rely on this field.
	addrType addrType

	// assigned on creation only; for zero-value groupings it is never assigned, but in that case it is not needed since there is nothing to cache
	cache *valueCache
}

// TODO LATER for large will need to add methods in java AddressItem (porting those same methods in AddressItem using BigINteger to use big.int should do it):
// isSinglePrefixBlock, isPrefixBlock, containsPrefixBlock(int), containsSinglePrefixBlock(int), GetMinPrefixLenForBlock() bitcount, GetPrefixLenForSingleBlock() prefixlen

func (grouping *addressDivisionGroupingBase) getAddrType() addrType {
	return grouping.addrType
}

// hasNoDivisions() returns whether this grouping is the zero grouping,
// which is what you get when contructing a grouping or section with no divisions
func (grouping *addressDivisionGroupingBase) hasNoDivisions() bool {
	divisions := grouping.divisions
	return divisions == nil || divisions.getDivisionCount() == 0
}

// GetBitCount returns the total number of bits across all divisions
func (grouping *addressDivisionGroupingBase) GetBitCount() (res BitCount) {
	for i := 0; i < grouping.GetDivisionCount(); i++ {
		res += grouping.getDivision(i).GetBitCount()
	}
	return
}

// GetBitCount returns the total number of bytes across all divisions (rounded up)
func (grouping *addressDivisionGroupingBase) GetByteCount() int {
	return (int(grouping.GetBitCount()) + 7) >> 3
}

// getDivision returns the division or panics if the index is negative or it is too large
func (grouping *addressDivisionGroupingBase) getDivision(index int) *addressDivisionBase {
	return grouping.divisions.getDivision(index)
}

// GetGenericDivision returns the division as an DivisionType,
// allowing all division types and aggregated division types to be represented by a single type,
// useful for comparisons and other common uses.
func (grouping *addressDivisionGroupingBase) GetGenericDivision(index int) DivisionType {
	return grouping.divisions.getGenericDivision(index)
}

func (grouping *addressDivisionGroupingBase) GetDivisionCount() int {
	divisions := grouping.divisions
	if divisions != nil {
		return divisions.getDivisionCount()
	}
	return 0
}

func (grouping *addressDivisionGroupingBase) IsZero() bool {
	divCount := grouping.GetDivisionCount()
	for i := 0; i < divCount; i++ {
		if !grouping.getDivision(i).IsZero() {
			return false
		}
	}
	return true
}

func (grouping *addressDivisionGroupingBase) IncludesZero() bool {
	divCount := grouping.GetDivisionCount()
	for i := 0; i < divCount; i++ {
		if !grouping.getDivision(i).IncludesZero() {
			return false
		}
	}
	return true
}

func (grouping *addressDivisionGroupingBase) IsMax() bool {
	divCount := grouping.GetDivisionCount()
	for i := 0; i < divCount; i++ {
		if !grouping.getDivision(i).IsMax() {
			return false
		}
	}
	return true
}

func (grouping *addressDivisionGroupingBase) IncludesMax() bool {
	divCount := grouping.GetDivisionCount()
	for i := 0; i < divCount; i++ {
		if !grouping.getDivision(i).IncludesMax() {
			return false
		}
	}
	return true
}

func (grouping *addressDivisionGroupingBase) IsFullRange() bool {
	divCount := grouping.GetDivisionCount()
	for i := 0; i < divCount; i++ {
		if !grouping.getDivision(i).IsFullRange() {
			return false
		}
	}
	return true
}

// GetSequentialBlockIndex gets the minimal segment index for which all following segments are full-range blocks.
// The segment at this index is not a full-range block unless all segments are full-range.
// The segment at this index and all following segments form a sequential range.
// For the full series to be sequential, the preceding segments must be single-valued.
func (grouping *addressDivisionGroupingBase) GetSequentialBlockIndex() int {
	divCount := grouping.GetDivisionCount()
	if divCount > 0 {
		for divCount--; divCount > 0 && grouping.getDivision(divCount).IsFullRange(); divCount-- {
		}
	}
	return divCount
}

func (grouping *addressDivisionGroupingBase) GetSequentialBlockCount() *big.Int {
	sequentialSegCount := grouping.GetSequentialBlockIndex()
	prefixLen := BitCount(0)
	for i := 0; i < sequentialSegCount; i++ {
		prefixLen += grouping.getDivision(i).GetBitCount()
	}
	return grouping.GetPrefixCountLen(prefixLen) // 0-1.0-1.*.* gives 1 as seq block index, and then you count only previous segments
}

func (grouping *addressDivisionGroupingBase) getCountBig() *big.Int {
	res := bigOne()
	count := grouping.GetDivisionCount()
	if count > 0 {
		for i := 0; i < count; i++ {
			div := grouping.getDivision(i)
			if div.isMultiple() {
				res.Mul(res, div.getCount())
			}
		}
	}
	return res
}

func (grouping *addressDivisionGroupingBase) getPrefixCountBig() *big.Int {
	prefixLen := grouping.prefixLength
	if prefixLen == nil {
		return grouping.getCountBig()
	}
	return grouping.getPrefixCountLenBig(prefixLen.bitCount())
}

func (grouping *addressDivisionGroupingBase) getPrefixCountLenBig(prefixLen BitCount) *big.Int {
	if prefixLen <= 0 {
		return bigOne()
	} else if prefixLen >= grouping.GetBitCount() {
		return grouping.getCountBig()
	}
	res := bigOne()
	if grouping.isMultiple() {
		divisionCount := grouping.GetDivisionCount()
		divPrefixLength := prefixLen
		for i := 0; i < divisionCount; i++ {
			div := grouping.getDivision(i)
			divBitCount := div.getBitCount()
			if div.isMultiple() {
				var divCount *big.Int
				if divPrefixLength < divBitCount {
					divCount = div.GetPrefixCountLen(divPrefixLength)
				} else {
					divCount = div.getCount()
				}
				res.Mul(res, divCount)
			}
			if divPrefixLength <= divBitCount {
				break
			}
			divPrefixLength -= divBitCount
		}
	}
	return res
}

func (grouping *addressDivisionGroupingBase) getBlockCountBig(segmentCount int) *big.Int {
	if segmentCount <= 0 {
		return bigOne()
	}
	divCount := grouping.GetDivisionCount()
	if segmentCount >= divCount {
		return grouping.getCountBig()
	}
	res := bigOne()
	if grouping.isMultiple() {
		for i := 0; i < divCount; i++ {
			division := grouping.getDivision(i)
			if division.isMultiple() {
				res.Mul(res, division.getCount())
			}
		}
	}
	return res
}

func (grouping *addressDivisionGroupingBase) getCount() *big.Int {
	return grouping.cacheCount(grouping.getCountBig)
}

func (grouping *addressDivisionGroupingBase) GetPrefixCount() *big.Int {
	return grouping.cachePrefixCount(grouping.getPrefixCountBig)
}

func (grouping *addressDivisionGroupingBase) GetPrefixCountLen(prefixLen BitCount) *big.Int {
	return grouping.calcCount(func() *big.Int { return grouping.getPrefixCountLenBig(prefixLen) })
}

// GetBlockCount returns the count of values in the initial (higher) count of divisions.
func (grouping *addressDivisionGroupingBase) GetBlockCount(divisionCount int) *big.Int {
	return grouping.calcCount(func() *big.Int { return grouping.getBlockCountBig(divisionCount) })
}

func (grouping *addressDivisionGroupingBase) cacheCount(counter func() *big.Int) *big.Int {
	cache := grouping.cache // isMult checks prior to this ensures cacheBitCountx no nil here
	if cache == nil {
		return grouping.calcCount(counter)
	}
	count := cache.cachedCount
	if count == nil {
		count = grouping.calcCount(counter)
		dataLoc := (*unsafe.Pointer)(unsafe.Pointer(&cache.cachedCount))
		atomic.StorePointer(dataLoc, unsafe.Pointer(count))
	}
	return new(big.Int).Set(count)
}

func (grouping *addressDivisionGroupingBase) calcCount(counter func() *big.Int) *big.Int {
	if grouping != nil && !grouping.isMultiple() {
		return bigOne()
	}
	return counter()
}

func (grouping *addressDivisionGroupingBase) cachePrefixCount(counter func() *big.Int) *big.Int {
	cache := grouping.cache // isMult checks prior to this ensures cache not nil here
	if cache == nil {
		return grouping.calcPrefixCount(counter)
	}
	count := cache.cachedPrefixCount
	if count == nil {
		count = grouping.calcPrefixCount(counter)
		dataLoc := (*unsafe.Pointer)(unsafe.Pointer(&cache.cachedPrefixCount))
		atomic.StorePointer(dataLoc, unsafe.Pointer(count))
	}
	return new(big.Int).Set(count)
}

func (grouping *addressDivisionGroupingBase) calcPrefixCount(counter func() *big.Int) *big.Int {
	if !grouping.isMultiple() {
		return bigOne()
	}
	prefixLen := grouping.prefixLength
	if prefixLen == nil || prefixLen.bitCount() >= grouping.GetBitCount() {
		return grouping.getCount()
	}
	return counter()
}

func (grouping *addressDivisionGroupingBase) getCachedBytes(calcBytes func() (bytes, upperBytes []byte)) (bytes, upperBytes []byte) {
	cache := grouping.cache
	if cache == nil {
		return emptyBytes, emptyBytes
	}
	cached := cache.bytesCache
	if cached == nil {
		bytes, upperBytes = calcBytes()
		cached = &bytesCache{
			lowerBytes: bytes,
			upperBytes: upperBytes,
		}
		dataLoc := (*unsafe.Pointer)(unsafe.Pointer(&cache.bytesCache))
		atomic.StorePointer(dataLoc, unsafe.Pointer(cached))
	}
	bytes = cached.lowerBytes
	upperBytes = cached.upperBytes
	return
}

// isMultiple returns whether this address or grouping represents more than one address or grouping.
// Such addresses include CIDR/IP addresses (eg 1.2.3.4/11) or wildcard addresses (eg 1.2.*.4) or range addresses (eg 1.2.3-4.5)
func (grouping *addressDivisionGroupingBase) isMultiple() bool {
	return grouping.isMult
}

type mixedCache struct {
	defaultMixedAddressSection *IPv6v4MixedAddressGrouping
	embeddedIPv4Section        *IPv4AddressSection
	embeddedIPv6Section        *EmbeddedIPv6AddressSection
}

type valueCache struct {
	cachedCount, cachedPrefixCount *big.Int

	cachedMaskLens *maskLenSetting

	bytesCache *bytesCache

	intsCache *intsCache

	zeroVals *zeroRangeCache

	stringCache stringCache

	sectionCache *groupingCache

	mixed *mixedCache

	minPrefix PrefixLen

	equivalentPrefix *PrefixLen

	isSinglePrefixBlock *bool
}

type ipStringCache struct {
	normalizedWildcardString,
	fullString,
	sqlWildcardString,

	reverseDNSString,

	segmentedBinaryString *string
}

type ipv4StringCache struct {
	inetAtonOctalString,
	inetAtonHexString *string
}

type ipv6StringCache struct {
	normalizedIPv6String,
	compressedIPv6String,
	mixedString,
	compressedWildcardString,
	canonicalWildcardString,
	networkPrefixLengthString,
	base85String *string
}

type macStringCache struct {
	normalizedMACString,
	compressedMACString,
	dottedString,
	spaceDelimitedString *string
}

type stringCache struct {
	canonicalString *string

	octalString, octalStringPrefixed,
	binaryString, binaryStringPrefixed,
	hexString, hexStringPrefixed *string

	*ipv6StringCache

	*ipv4StringCache

	*ipStringCache

	*macStringCache
}

var zeroStringCache = stringCache{
	ipv6StringCache: &ipv6StringCache{},
	ipv4StringCache: &ipv4StringCache{},
	ipStringCache:   &ipStringCache{},
	macStringCache:  &macStringCache{},
}

type groupingCache struct {
	lower, upper *AddressSection
}

type zeroRangeCache struct {
	zeroSegments, zeroRangeSegments RangeList
}

type intsCache struct {
	cachedLowerVal, cachedUpperVal uint32
}

type maskLenSetting struct {
	networkMaskLen, hostMaskLen PrefixLen
}

type divArray interface {
	getDivision(index int) *addressDivisionBase

	getGenericDivision(index int) DivisionType

	getDivisionCount() int

	fmt.Stringer
}

var zeroDivs = make([]*AddressDivision, 0)
var zeroStandardDivArray = standardDivArray{zeroDivs}

type standardDivArray struct {
	divisions []*AddressDivision
}

func (grouping standardDivArray) getDivisionCount() int {
	return len(grouping.divisions)
}

func (grouping standardDivArray) getDivision(index int) *addressDivisionBase {
	return (*addressDivisionBase)(unsafe.Pointer(grouping.divisions[index]))
}

func (grouping standardDivArray) getGenericDivision(index int) DivisionType {
	return grouping.divisions[index]
}

func (grouping standardDivArray) copyDivisions(divs []*AddressDivision) (count int) {
	return copy(divs, grouping.divisions)
}

func (grouping standardDivArray) copySubDivisions(start, end int, divs []*AddressDivision) (count int) {
	return copy(divs, grouping.divisions[start:end])
}

func (grouping standardDivArray) getSubDivisions(index, endIndex int) (divs []*AddressDivision) {
	return grouping.divisions[index:endIndex]
}

func (grouping standardDivArray) getDivisions() (divs []*AddressDivision) {
	return grouping.divisions
}

func (grouping standardDivArray) init() standardDivArray {
	if grouping.divisions == nil {
		return zeroStandardDivArray
	}
	return grouping
}

func (grouping standardDivArray) String() string {
	return fmt.Sprintf("%v", grouping.init().divisions)
}
