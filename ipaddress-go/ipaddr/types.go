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
	"math"
	"math/big"
	"strconv"
)

type boolSetting struct {
	isSet, val bool
}

var (
	falseVal = false
	trueVal  = true
)

// A PrefixLen indicates the length of the prefix for an address, section, division grouping, segment, or division.
// The zero value, which is nil, indicates that there is no prefix length.
type PrefixLen = *PrefixBitCount

// A PrefixBitCount is the count of bits in a non-nil PrefixLen.
type PrefixBitCount uint8

// A BitCount represents a count of bits in an address, section, grouping, segment, or division.
// Using signed integers allows for easier arithmetic, avoiding bugs.
// However, all methods adjust bit counts to match address size,
// so negative bit counts or bit counts larger than address size are meaningless.
type BitCount = int // using signed integers allows for easier arithmetic

const maxBitCountInternal, minBitCountInternal = math.MaxUint8, 0

// Len() returns the length of the prefix.  If the receiver is nil, representing the absence of a prefix length, returns 0.
// It will also return 0 if the receiver is a prefix with length of 0.  To distinguish the two, compare the receiver with nil.
func (p *PrefixBitCount) Len() BitCount {
	if p == nil {
		return 0
	}
	return p.bitCount()
}

func (p *PrefixBitCount) IsNil() bool {
	return p == nil
}

func (p *PrefixBitCount) bitCount() BitCount {
	return BitCount(*p)
}

func (p *PrefixBitCount) copy() PrefixLen {
	if p == nil {
		return nil
	}
	res := *p
	return &res
}

// Equal compares two PrefixLen values for equality.  This method is intended for the PrefixLen type.  BitCount values should be compared with == operator.
func (p *PrefixBitCount) Equal(other PrefixLen) bool {
	if p == nil {
		return other == nil
	}
	return other != nil && p.bitCount() == other.bitCount()
}

// Matches compares a PrefixLen value with a bit count
func (p *PrefixBitCount) Matches(other BitCount) bool {
	return p != nil && p.bitCount() == other
}

// Compare compares PrefixLen values, returning -1, 0, or 1 if the receiver is less than, equal to, or greater than the argument.
// This method is intended for the PrefixLen type.  BitCount values should be compared with ==, >, <, >= and <= operators.
func (p *PrefixBitCount) Compare(other PrefixLen) int {
	if p == nil {
		if other == nil {
			return 0
		}
		return 1
	} else if other == nil {
		return -1
	}
	return p.bitCount() - other.bitCount()
}

func (p *PrefixBitCount) String() string {
	if p == nil {
		return nilString()
	}
	return strconv.Itoa(p.bitCount())
}

var cachedPrefixBitCounts, cachedPrefixLens = initPrefLens()

func initPrefLens() ([]PrefixBitCount, []PrefixLen) {
	cachedPrefBitcounts := make([]PrefixBitCount, maxBitCountInternal)
	cachedPrefLens := make([]PrefixLen, maxBitCountInternal)
	for i := 0; i <= IPv6BitCount; i++ {
		cachedPrefBitcounts[i] = PrefixBitCount(i)
		cachedPrefLens[i] = &cachedPrefBitcounts[i]
	}
	return cachedPrefBitcounts, cachedPrefLens
}

func cacheBitCount(i BitCount) PrefixLen {
	if i < minBitCountInternal {
		i = minBitCountInternal
	}
	if i < len(cachedPrefixBitCounts) {
		return &cachedPrefixBitCounts[i]
	}
	if i > maxBitCountInternal {
		i = maxBitCountInternal
	}
	res := PrefixBitCount(i)
	return &res
}

func cachePrefix(i BitCount) *PrefixLen {
	if i < minBitCountInternal {
		i = minBitCountInternal
	}
	if i < len(cachedPrefixLens) {
		return &cachedPrefixLens[i]
	}
	if i > maxBitCountInternal {
		i = maxBitCountInternal
	}
	val := PrefixBitCount(i)
	res := &val
	return &res
}

func cachePrefixLen(external PrefixLen) PrefixLen {
	if external == nil {
		return nil
	}
	return cacheBitCount(external.bitCount())
}

var p PrefixLen

func cacheNilPrefix() *PrefixLen {
	return &p
}

const maxPortNumInternal, minPortNumInternal = math.MaxUint16, 0

// Port represents the port of a UDP or TCP address.  A nil value indicates no port.
type Port = *PortNum

type PortInt = int // using signed integers allows for easier arithmetic

// A PortNum is the port number for a non-nil Port
type PortNum uint16

func (p *PortNum) portNum() PortInt {
	return PortInt(*p)
}

func (p *PortNum) copy() Port {
	if p == nil {
		return nil
	}
	res := *p
	return &res
}

func (p *PortNum) Num() PortInt {
	if p == nil {
		return 0
	}
	//return PortInt(p.port)
	return PortInt(*p)
}

// Equal compares two Port values for equality.
func (p *PortNum) Equal(other Port) bool {
	if p == nil {
		return other == nil
	}
	return other != nil && p.portNum() == other.portNum()
}

// Matches compares a Port value with a port number
func (p *PortNum) Matches(other PortInt) bool {
	return p != nil && p.portNum() == other
}

// Compare compares PrefixLen values, returning -1, 0, or 1 if the receiver is less than, equal to, or greater than the argument.
func (p *PortNum) Compare(other Port) int {
	if p == nil {
		if other == nil {
			return 0
		}
		return -1
	} else if other == nil {
		return 1
	}
	return p.portNum() - other.portNum()
}

func (p *PortNum) String() string {
	if p == nil {
		return nilString()
	}
	return strconv.Itoa(p.portNum())
}

func cachePorts(i PortInt) Port {
	if i < minPortNumInternal {
		i = minPortNumInternal
	} else if i > maxPortNumInternal {
		i = maxPortNumInternal
	}
	res := PortNum(i)
	return &res
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

func checkPrefLen(prefixLength PrefixLen, max BitCount) PrefixLen {
	if prefixLength != nil {
		prefLen := prefixLength.bitCount()
		if prefLen > max {
			return cacheBitCount(max)
		} else if prefLen < 0 {
			return cacheBitCount(0)
		}
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
