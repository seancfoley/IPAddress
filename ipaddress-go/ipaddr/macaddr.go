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
	"net"
	"sync/atomic"
	"unsafe"

	"github.com/seancfoley/ipaddress/ipaddress-go/ipaddr/addrerr"
	"github.com/seancfoley/ipaddress/ipaddress-go/ipaddr/addrstr"
)

const (
	MACBitsPerSegment           = 8
	MACBytesPerSegment          = 1
	MACDefaultTextualRadix      = 16
	MACMaxValuePerSegment       = 0xff
	MACMaxValuePerDottedSegment = 0xffff

	MediaAccessControlSegmentCount         = 6
	MediaAccessControlDottedSegmentCount   = 3
	MediaAccessControlDotted64SegmentCount = 4
	ExtendedUniqueIdentifier48SegmentCount = MediaAccessControlSegmentCount
	ExtendedUniqueIdentifier64SegmentCount = 8

	MACOrganizationalUniqueIdentifierSegmentCount = 3

	MACSegmentMaxChars = 2

	MACDashSegmentSeparator   = '-'
	MACColonSegmentSeparator  = ':'
	MacSpaceSegmentSeparator  = ' '
	MacDottedSegmentSeparator = '.'

	MacDashedSegmentRangeSeparator    = '|'
	MacDashedSegmentRangeSeparatorStr = "|"

	macBitsToSegmentBitshift = 3
)

func newMACAddress(section *MACAddressSection) *MACAddress {
	return createAddress(section.ToSectionBase(), NoZone).ToMAC()
}

func NewMACAddress(section *MACAddressSection) (*MACAddress, addrerr.AddressValueError) {
	segCount := section.GetSegmentCount()
	if segCount != MediaAccessControlSegmentCount && segCount != ExtendedUniqueIdentifier64SegmentCount {
		return nil, &addressValueError{
			addressError: addressError{key: "ipaddress.error.invalid.size"},
			val:          segCount,
		}
	}
	return createAddress(section.ToSectionBase(), NoZone).ToMAC(), nil
}

func NewMACAddressFromBytes(bytes net.HardwareAddr) (*MACAddress, addrerr.AddressValueError) {
	section, err := createMACSectionFromBytes(bytes)
	if err != nil {
		return nil, err
	}
	segCount := section.GetSegmentCount()
	if segCount != MediaAccessControlSegmentCount && segCount != ExtendedUniqueIdentifier64SegmentCount {
		return nil, &addressValueError{
			addressError: addressError{key: "ipaddress.error.invalid.size"},
			val:          segCount,
		}
	}
	return createAddress(section.ToSectionBase(), NoZone).ToMAC(), nil
}

func NewMACAddressFromUint64Ext(val uint64, isExtended bool) *MACAddress {
	section := NewMACSectionFromUint64(val, getMacSegCount(isExtended))
	return createAddress(section.ToSectionBase(), NoZone).ToMAC()
}

func NewMACAddressFromSegments(segments []*MACAddressSegment) (*MACAddress, addrerr.AddressValueError) {
	segsLen := len(segments)
	if segsLen != MediaAccessControlSegmentCount && segsLen != ExtendedUniqueIdentifier64SegmentCount {
		return nil, &addressValueError{val: segsLen, addressError: addressError{key: "ipaddress.error.mac.invalid.segment.count"}}
	}
	section := NewMACSection(segments)
	return createAddress(section.ToSectionBase(), NoZone).ToMAC(), nil
}

func NewMACAddressFromVals(vals MACSegmentValueProvider) (addr *MACAddress) {
	return NewMACAddressFromValsExt(vals, false)
}

func NewMACAddressFromValsExt(vals MACSegmentValueProvider, isExtended bool) (addr *MACAddress) {
	section := NewMACSectionFromVals(vals, getMacSegCount(isExtended))
	addr = newMACAddress(section)
	return
}

func NewMACAddressFromRange(vals, upperVals MACSegmentValueProvider) (addr *MACAddress) {
	return NewMACAddressFromRangeExt(vals, upperVals, false)
}

func NewMACAddressFromRangeExt(vals, upperVals MACSegmentValueProvider, isExtended bool) (addr *MACAddress) {
	section := NewMACSectionFromRange(vals, upperVals, getMacSegCount(isExtended))
	addr = newMACAddress(section)
	return
}

func createMACSectionFromBytes(bytes []byte) (*MACAddressSection, addrerr.AddressValueError) {
	var segCount int
	length := len(bytes)
	//We round down the bytes to 6 bytes if we can.  Otherwise, we round up.
	if length < ExtendedUniqueIdentifier64SegmentCount {
		segCount = MediaAccessControlSegmentCount
		if length > MediaAccessControlSegmentCount {
			for i := 0; ; i++ {
				if bytes[i] != 0 {
					segCount = ExtendedUniqueIdentifier64SegmentCount
					break
				}
				length--
				if length <= MediaAccessControlSegmentCount {
					break
				}
			}
		}
	} else {
		segCount = ExtendedUniqueIdentifier64SegmentCount
	}
	return NewMACSectionFromBytes(bytes, segCount)
}

func getMacSegCount(isExtended bool) (segmentCount int) {
	if isExtended {
		segmentCount = ExtendedUniqueIdentifier64SegmentCount
	} else {
		segmentCount = MediaAccessControlSegmentCount
	}
	return
}

var zeroMAC = createMACZero()

func createMACZero() *MACAddress {
	segs := []*MACAddressSegment{zeroMACSeg, zeroMACSeg, zeroMACSeg, zeroMACSeg, zeroMACSeg, zeroMACSeg}
	section := NewMACSection(segs)
	return newMACAddress(section)
}

type MACAddress struct {
	addressInternal
}

func (addr *MACAddress) init() *MACAddress {
	if addr.section == nil {
		return zeroMAC
	}
	return addr
}

func (addr *MACAddress) GetCount() *big.Int {
	if addr == nil {
		return bigZero()
	}
	return addr.getCount()
}

func (addr *MACAddress) IsMultiple() bool {
	return addr != nil && addr.isMultiple()
}

func (addr *MACAddress) IsPrefixed() bool {
	return addr != nil && addr.isPrefixed()
}

func (addr *MACAddress) IsFullRange() bool {
	return addr.GetSection().IsFullRange()
}

func (addr *MACAddress) GetBitCount() BitCount {
	return addr.init().addressInternal.GetBitCount()
}

func (addr *MACAddress) GetByteCount() int {
	return addr.init().addressInternal.GetByteCount()
}

func (addr *MACAddress) GetBitsPerSegment() BitCount {
	return MACBitsPerSegment
}

func (addr *MACAddress) GetBytesPerSegment() int {
	return MACBytesPerSegment
}

func (addr *MACAddress) checkIdentity(section *MACAddressSection) *MACAddress {
	if section == nil {
		return nil
	}
	sec := section.ToSectionBase()
	if sec == addr.section {
		return addr
	}
	return newMACAddress(section)
}

func (addr *MACAddress) GetValue() *big.Int {
	return addr.init().section.GetValue()
}

func (addr *MACAddress) GetUpperValue() *big.Int {
	return addr.init().section.GetUpperValue()
}

func (addr *MACAddress) GetLower() *Address {
	return addr.init().getLower()
}

func (addr *MACAddress) GetUpper() *Address {
	return addr.init().getUpper()
}

func (addr *MACAddress) Uint64Value() uint64 {
	return addr.GetSection().Uint64Value()
}

func (addr *MACAddress) UpperUint64Value() uint64 {
	return addr.GetSection().UpperUint64Value()
}

func (addr *MACAddress) GetHardwareAddr() net.HardwareAddr {
	return addr.Bytes()
}

func (addr *MACAddress) CopyHardwareAddr(bytes net.HardwareAddr) net.HardwareAddr {
	return addr.CopyBytes(bytes)
}

func (addr *MACAddress) GetUpperHardwareAddr() net.HardwareAddr {
	return addr.UpperBytes()
}

func (addr *MACAddress) CopyUpperHardwareAddr(bytes net.HardwareAddr) net.HardwareAddr {
	return addr.CopyUpperBytes(bytes)
}

func (addr *MACAddress) Bytes() []byte {
	return addr.init().section.Bytes()
}

func (addr *MACAddress) UpperBytes() []byte {
	return addr.init().section.UpperBytes()
}

func (addr *MACAddress) CopyBytes(bytes []byte) []byte {
	return addr.init().section.CopyBytes(bytes)
}

func (addr *MACAddress) CopyUpperBytes(bytes []byte) []byte {
	return addr.init().section.CopyUpperBytes(bytes)
}

func (addr *MACAddress) GetSection() *MACAddressSection {
	return addr.init().section.ToMAC()
}

// GetTrailingSection gets the subsection from the series starting from the given index
// The first segment is at index 0.
func (addr *MACAddress) GetTrailingSection(index int) *MACAddressSection {
	return addr.GetSection().GetTrailingSection(index)
}

// GetSubSection gets the subsection from the series starting from the given index and ending just before the give endIndex.
// The first segment is at index 0.
func (addr *MACAddress) GetSubSection(index, endIndex int) *MACAddressSection {
	return addr.GetSection().GetSubSection(index, endIndex)
}

// CopySubSegments copies the existing segments from the given start index until but not including the segment at the given end index,
// into the given slice, as much as can be fit into the slice, returning the number of segments copied
func (addr *MACAddress) CopySubSegments(start, end int, segs []*MACAddressSegment) (count int) {
	return addr.GetSection().CopySubSegments(start, end, segs)
}

// CopySubSegments copies the existing segments from the given start index until but not including the segment at the given end index,
// into the given slice, as much as can be fit into the slice, returning the number of segments copied
func (addr *MACAddress) CopySegments(segs []*MACAddressSegment) (count int) {
	return addr.GetSection().CopySegments(segs)
}

// GetSegments returns a slice with the address segments.  The returned slice is not backed by the same array as this address.
func (addr *MACAddress) GetSegments() []*MACAddressSegment {
	return addr.GetSection().GetSegments()
}

// GetSegment returns the segment at the given index
func (addr *MACAddress) GetSegment(index int) *MACAddressSegment {
	return addr.init().getSegment(index).ToMAC()
}

// GetSegmentCount returns the segment/division count
func (addr *MACAddress) GetSegmentCount() int {
	return addr.GetDivisionCount()
}

// GetGenericDivision returns the segment at the given index as an DivisionType
func (addr *MACAddress) GetGenericDivision(index int) DivisionType {
	return addr.init().getDivision(index)
}

// GetGenericSegment returns the segment at the given index as an AddressSegmentType
func (addr *MACAddress) GetGenericSegment(index int) AddressSegmentType {
	return addr.init().getSegment(index)
}

// TestBit computes (this & (1 << n)) != 0), using the lower value of this segment.
func (addr *MACAddress) TestBit(n BitCount) bool {
	return addr.init().testBit(n)
}

// IsOneBit returns true if the bit in the lower value of this segment at the given index is 1, where index 0 is the most significant bit.
func (addr *MACAddress) IsOneBit(bitIndex BitCount) bool {
	return addr.init().isOneBit(bitIndex)
}

func (addr *MACAddress) IsMax() bool {
	return addr.init().section.IsMax()
}

func (addr *MACAddress) IncludesMax() bool {
	return addr.init().section.IncludesMax()
}

// GetDivision returns the segment count, implementing the interface AddressDivisionSeries
func (addr *MACAddress) GetDivisionCount() int {
	return addr.init().getDivisionCount()
}

func (addr *MACAddress) ToPrefixBlock() *MACAddress {
	return addr.init().toPrefixBlock().ToMAC()
}

func (addr *MACAddress) ToBlock(segmentIndex int, lower, upper SegInt) *MACAddress {
	return addr.init().toBlock(segmentIndex, lower, upper).ToMAC()
}

func (addr *MACAddress) WithoutPrefixLen() *MACAddress {
	if !addr.IsPrefixed() {
		return addr
	}
	return addr.init().withoutPrefixLen().ToMAC()
}

func (addr *MACAddress) SetPrefixLen(prefixLen BitCount) *MACAddress {
	return addr.init().setPrefixLen(prefixLen).ToMAC()
}

func (addr *MACAddress) SetPrefixLenZeroed(prefixLen BitCount) (*MACAddress, addrerr.IncompatibleAddressError) {
	res, err := addr.init().setPrefixLenZeroed(prefixLen)
	return res.ToMAC(), err
}

func (addr *MACAddress) AdjustPrefixLen(prefixLen BitCount) *MACAddress {
	return addr.init().adjustPrefixLen(prefixLen).ToMAC()
}

func (addr *MACAddress) AdjustPrefixLenZeroed(prefixLen BitCount) (*MACAddress, addrerr.IncompatibleAddressError) {
	res, err := addr.init().adjustPrefixLenZeroed(prefixLen)
	return res.ToMAC(), err
}

func (addr *MACAddress) AssignPrefixForSingleBlock() *MACAddress {
	return addr.init().assignPrefixForSingleBlock().ToMAC()
}

func (addr *MACAddress) AssignMinPrefixForBlock() *MACAddress {
	return addr.init().assignMinPrefixForBlock().ToMAC()
}

func (addr *MACAddress) ContainsPrefixBlock(prefixLen BitCount) bool {
	return addr.init().addressInternal.ContainsPrefixBlock(prefixLen)
}

func (addr *MACAddress) ContainsSinglePrefixBlock(prefixLen BitCount) bool {
	return addr.init().addressInternal.ContainsSinglePrefixBlock(prefixLen)
}

func (addr *MACAddress) GetMinPrefixLenForBlock() BitCount {
	return addr.init().addressInternal.GetMinPrefixLenForBlock()
}

func (addr *MACAddress) GetPrefixLenForSingleBlock() PrefixLen {
	return addr.init().addressInternal.GetPrefixLenForSingleBlock()
}

func (addr *MACAddress) Compare(item AddressItem) int {
	return CountComparator.Compare(addr, item)
}

func (addr *MACAddress) PrefixEqual(other AddressType) bool {
	return addr.init().prefixEquals(other)
}

func (addr *MACAddress) PrefixContains(other AddressType) bool {
	return addr.init().prefixContains(other)
}

func (addr *MACAddress) Contains(other AddressType) bool {
	if addr == nil {
		return other == nil || other.ToAddressBase() == nil
	}
	// note: we don't use the same optimization as in IPv4/6 because we do need to check segment count with MAC
	return addr.init().contains(other)
}

func (addr *MACAddress) Equal(other AddressType) bool {
	if addr == nil {
		return other == nil || other.ToAddressBase() == nil
	}
	// note: we don't use the same optimization as in IPv4/6 because we do need to check segment count with MAC
	return addr.init().equals(other)
}

// CompareSize returns whether this subnet has more elements than the other, returning -1 if this subnet has less, 1 if more, and 0 if both have the same count of individual addresses
func (addr *MACAddress) CompareSize(other AddressType) int { // this is here to take advantage of the CompareSize in IPAddressSection
	if addr == nil {
		if other != nil && other.ToAddressBase() != nil {
			// we have size 0, other has size >= 1
			return -1
		}
		return 0
	}
	return addr.init().compareSize(other)
}

func (addr *MACAddress) GetMaxSegmentValue() SegInt {
	return addr.init().getMaxSegmentValue()
}

// Multicast MAC addresses have the least significant bit of the first octet set to 1.
func (addr *MACAddress) IsMulticast() bool {
	return addr.GetSegment(0).MatchesWithMask(1, 0x1)
}

func (addr *MACAddress) IsUnicast() bool {
	return !addr.IsMulticast()
}

// Universal MAC addresses have second the least significant bit of the first octet set to 0.
func (addr *MACAddress) IsUniversal() bool {
	return !addr.IsLocal()
}

// Local MAC addresses have the second least significant bit of the first octet set to 1.
func (addr *MACAddress) IsLocal() bool {
	return addr.GetSegment(0).MatchesWithMask(2, 0x2)
}

func (addr *MACAddress) Iterator() MACAddressIterator {
	if addr == nil {
		return macAddressIterator{nilAddrIterator()}
	}
	return macAddressIterator{addr.init().addrIterator(nil)}
}

func (addr *MACAddress) PrefixIterator() MACAddressIterator {
	return macAddressIterator{addr.init().prefixIterator(false)}
}

func (addr *MACAddress) PrefixBlockIterator() MACAddressIterator {
	return macAddressIterator{addr.init().prefixIterator(true)}
}

func (addr *MACAddress) BlockIterator(segmentCount int) MACAddressIterator {
	return macAddressIterator{addr.init().blockIterator(segmentCount)}
}

func (addr *MACAddress) SequentialBlockIterator() MACAddressIterator {
	return macAddressIterator{addr.init().sequentialBlockIterator()}
}

func (addr *MACAddress) GetSequentialBlockIndex() int {
	return addr.init().getSequentialBlockIndex()
}

func (addr *MACAddress) GetSequentialBlockCount() *big.Int {
	return addr.init().getSequentialBlockCount()
}

func (addr *MACAddress) IncrementBoundary(increment int64) *MACAddress {
	return addr.init().incrementBoundary(increment).ToMAC()
}

func (addr *MACAddress) Increment(increment int64) *MACAddress {
	return addr.init().increment(increment).ToMAC()
}

func (addr *MACAddress) ReverseBytes() *MACAddress {
	return addr.checkIdentity(addr.GetSection().ReverseBytes())
}

func (addr *MACAddress) ReverseBits(perByte bool) (*MACAddress, addrerr.IncompatibleAddressError) {
	res, err := addr.GetSection().ReverseBits(perByte)
	if err != nil {
		return nil, err
	}
	return addr.checkIdentity(res), nil
}

func (addr *MACAddress) ReverseSegments() *MACAddress {
	return addr.checkIdentity(addr.GetSection().ReverseSegments())
}

// ReplaceLen replaces segments starting from startIndex and ending before endIndex with the same number of segments starting at replacementStartIndex from the replacement section
func (addr *MACAddress) ReplaceLen(startIndex, endIndex int, replacement *MACAddress, replacementIndex int) *MACAddress {
	startIndex, endIndex, replacementIndex =
		adjust1To1Indices(startIndex, endIndex, addr.GetSegmentCount(), replacementIndex, replacement.GetSegmentCount())
	if startIndex == endIndex {
		return addr
	}
	count := endIndex - startIndex
	return addr.checkIdentity(addr.GetSection().ReplaceLen(startIndex, endIndex, replacement.GetSection(), replacementIndex, replacementIndex+count))
}

// Replace replaces segments starting from startIndex with segments from the replacement section
func (addr *MACAddress) Replace(startIndex int, replacement *MACAddressSection) *MACAddress {
	startIndex, endIndex, replacementIndex :=
		adjust1To1Indices(startIndex, startIndex+replacement.GetSegmentCount(), addr.GetSegmentCount(), 0, replacement.GetSegmentCount())
	count := endIndex - startIndex
	return addr.checkIdentity(addr.GetSection().ReplaceLen(startIndex, endIndex, replacement, replacementIndex, replacementIndex+count))
}

func (addr *MACAddress) GetOUISection() *MACAddressSection {
	return addr.GetSubSection(0, MACOrganizationalUniqueIdentifierSegmentCount)
}

func (addr *MACAddress) GetODISection() *MACAddressSection {
	return addr.GetTrailingSection(MACOrganizationalUniqueIdentifierSegmentCount)
}

// ToOUIPrefixBlock returns a section in which the range of values match the full block for the OUI (organizationally unique identifier) bytes
func (addr *MACAddress) ToOUIPrefixBlock() *MACAddress {
	segmentCount := addr.GetSegmentCount()
	currentPref := addr.getPrefixLen()
	newPref := BitCount(MACOrganizationalUniqueIdentifierSegmentCount) << 3 //ouiSegmentCount * MACAddress.BITS_PER_SEGMENT
	createNew := currentPref == nil || currentPref.bitCount() > newPref
	if !createNew {
		newPref = currentPref.bitCount()
		for i := MACOrganizationalUniqueIdentifierSegmentCount; i < segmentCount; i++ {
			segment := addr.GetSegment(i)
			if !segment.IsFullRange() {
				createNew = true
				break
			}
		}
	}
	if !createNew {
		return addr
	}
	segmentIndex := MACOrganizationalUniqueIdentifierSegmentCount
	newSegs := createSegmentArray(segmentCount)
	addr.GetSection().copySubDivisions(0, segmentIndex, newSegs)
	allRangeSegment := allRangeMACSeg.ToDiv()
	for i := segmentIndex; i < segmentCount; i++ {
		newSegs[i] = allRangeSegment
	}
	newSect := createSectionMultiple(newSegs, cacheBitCount(newPref), addr.getAddrType(), true).ToMAC()
	return newMACAddress(newSect)
}

var IPv6LinkLocalPrefix = createLinkLocalPrefix()

func createLinkLocalPrefix() *IPv6AddressSection {
	zeroSeg := zeroIPv6Seg.ToDiv()
	segs := []*AddressDivision{
		NewIPv6Segment(0xfe80).ToDiv(),
		zeroSeg,
		zeroSeg,
		zeroSeg,
	}
	return newIPv6Section(segs)
}

// ToLinkLocalIPv6 converts to a link-local Ipv6 address.  Any MAC prefix length is ignored.  Other elements of this address section are incorporated into the conversion.
// This will provide the latter 4 segments of an IPv6 address, to be paired with the link-local IPv6 prefix of 4 segments.
func (addr *MACAddress) ToLinkLocalIPv6() (*IPv6Address, addrerr.IncompatibleAddressError) {
	sect, err := addr.ToEUI64IPv6()
	if err != nil {
		return nil, err
	}
	return newIPv6Address(IPv6LinkLocalPrefix.Append(sect)), nil
}

// ToEUI64IPv6 converts to an Ipv6 address section.  Any MAC prefix length is ignored.  Other elements of this address section are incorporated into the conversion.
// This will provide the latter 4 segments of an IPv6 address, to be paired with an IPv6 prefix of 4 segments.
func (addr *MACAddress) ToEUI64IPv6() (*IPv6AddressSection, addrerr.IncompatibleAddressError) {
	return NewIPv6SectionFromMAC(addr.init())
}

// IsEUI64 returns whether this section is consistent with an IPv6 EUI64Size section,
// which means it came from an extended 8 byte address,
// and the corresponding segments in the middle match 0xff and 0xff/fe for MAC/not-MAC
func (addr *MACAddress) IsEUI64(asMAC bool) bool {
	if addr.GetSegmentCount() == ExtendedUniqueIdentifier64SegmentCount { //getSegmentCount() == EXTENDED_UNIQUE_IDENTIFIER_64_SEGMENT_COUNT
		section := addr.GetSection()
		seg3 := section.GetSegment(3)
		seg4 := section.GetSegment(4)
		if seg3.matches(0xff) {
			if asMAC {
				return seg4.matches(0xff)
			}
			return seg4.matches(0xfe)
		}
	}
	return false
}

// ToEUI64 converts to IPv6 EUI-64 section
//
// http://standards.ieee.org/develop/regauth/tut/eui64.pdf
//
// If asMAC if true, this address is considered MAC and the EUI-64 is extended using ff-ff, otherwise this address is considered EUI-48 and extended using ff-fe
// Note that IPv6 treats MAC as EUI-48 and extends MAC to IPv6 addresses using ff-fe
func (addr *MACAddress) ToEUI64(asMAC bool) (*MACAddress, addrerr.IncompatibleAddressError) {
	section := addr.GetSection()
	if addr.GetSegmentCount() == ExtendedUniqueIdentifier48SegmentCount {
		segs := createSegmentArray(ExtendedUniqueIdentifier64SegmentCount)
		section.copySubDivisions(0, 3, segs)
		segs[3] = ffMACSeg.ToDiv()
		if asMAC {
			segs[4] = ffMACSeg.ToDiv()
		} else {
			segs[4] = feMACSeg.ToDiv()
		}
		section.copySubDivisions(3, 6, segs[5:])
		prefixLen := addr.getPrefixLen()
		if prefixLen != nil {
			if prefixLen.bitCount() >= 24 {
				prefixLen = cacheBitCount(prefixLen.bitCount() + (MACBitsPerSegment << 1)) //two segments
			}
		}
		newSect := createInitializedSection(segs, prefixLen, addr.getAddrType()).ToMAC()
		return newMACAddress(newSect), nil
	}
	seg3 := section.GetSegment(3)
	seg4 := section.GetSegment(4)
	if seg3.matches(0xff) {
		if asMAC {
			if seg4.matches(0xff) {
				return addr, nil
			}
		} else {
			if seg4.matches(0xfe) {
				return addr, nil
			}
		}
	}
	return nil, &incompatibleAddressError{addressError{key: "ipaddress.mac.error.not.eui.convertible"}}
}

func (addr *MACAddress) String() string {
	if addr == nil {
		return nilString()
	}
	return addr.init().addressInternal.toString()
}

func (addr MACAddress) Format(state fmt.State, verb rune) {
	addr.init().format(state, verb)
}

func (addr *MACAddress) GetSegmentStrings() []string {
	if addr == nil {
		return nil
	}
	return addr.init().getSegmentStrings()
}

func (addr *MACAddress) ToCanonicalString() string {
	if addr == nil {
		return nilString()
	}
	return addr.init().toCanonicalString()
}

func (addr *MACAddress) ToNormalizedString() string {
	if addr == nil {
		return nilString()
	}
	return addr.init().toNormalizedString()
}

func (addr *MACAddress) ToCompressedString() string {
	if addr == nil {
		return nilString()
	}
	return addr.init().toCompressedString()
}

func (addr *MACAddress) ToHexString(with0xPrefix bool) (string, addrerr.IncompatibleAddressError) {
	if addr == nil {
		return nilString(), nil
	}
	return addr.init().toHexString(with0xPrefix)
}

func (addr *MACAddress) ToOctalString(with0Prefix bool) (string, addrerr.IncompatibleAddressError) {
	if addr == nil {
		return nilString(), nil
	}
	return addr.init().toOctalString(with0Prefix)
}

func (addr *MACAddress) ToBinaryString(with0bPrefix bool) (string, addrerr.IncompatibleAddressError) {
	if addr == nil {
		return nilString(), nil
	}
	return addr.init().toBinaryString(with0bPrefix)
}

func (addr *MACAddress) GetDottedAddress() (*AddressDivisionGrouping, addrerr.IncompatibleAddressError) {
	return addr.init().GetSection().GetDottedGrouping()
}

// ToDottedString produces the dotted hexadecimal format aaaa.bbbb.cccc
func (addr *MACAddress) ToDottedString() (string, addrerr.IncompatibleAddressError) {
	if addr == nil {
		return nilString(), nil
	}
	return addr.init().GetSection().ToDottedString()
}

// ToSpaceDelimitedString produces a string delimited by spaces: aa bb cc dd ee ff
func (addr *MACAddress) ToSpaceDelimitedString() string {
	if addr == nil {
		return nilString()
	}
	return addr.init().GetSection().ToSpaceDelimitedString()
}

func (addr *MACAddress) ToDashedString() string {
	if addr == nil {
		return nilString()
	}
	return addr.init().GetSection().ToDashedString()
}

func (addr *MACAddress) ToColonDelimitedString() string {
	if addr == nil {
		return nilString()
	}
	return addr.init().GetSection().ToColonDelimitedString()
}

func (addr *MACAddress) ToCustomString(stringOptions addrstr.StringOptions) string {
	if addr == nil {
		return nilString()
	}
	return addr.init().GetSection().toCustomString(stringOptions)
}

func (addr *MACAddress) ToAddressString() *MACAddressString {
	addr = addr.init()
	cache := addr.cache
	if cache == nil {
		return newMACAddressStringFromAddr(addr.toCanonicalString(), addr)
	}
	res := addr.cache.identifierStr
	if res == nil {
		str := newMACAddressStringFromAddr(addr.toCanonicalString(), addr)
		res = &IdentifierStr{str}
		dataLoc := (*unsafe.Pointer)(unsafe.Pointer(&addr.cache.identifierStr))
		atomic.StorePointer(dataLoc, unsafe.Pointer(res))
	}
	hostIdStr := res.idStr
	return hostIdStr.(*MACAddressString)
}

func (addr *MACAddress) ToAddressBase() *Address {
	if addr != nil {
		addr = addr.init()
	}
	return (*Address)(addr)
}

func (addr *MACAddress) Wrap() WrappedAddress {
	return WrapAddress(addr.ToAddressBase())
}
