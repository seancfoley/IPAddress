//
// Copyright 2020-2021 Sean C Foley
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

//func GetPrefixLen(i int) PrefixLen {
//	return cacheBits(i)
//}

//// Equal compares two PrefixLen values for equality.  This method is intended for the PrefixLen type.  BitCount values should be compared with == operator.
//func (p *BitCount) Equal(other *BitCount) bool {
//	if p == nil {
//		return other == nil
//	}
//	return other != nil && *p == *other
//}
//
//// Matches compares a PrefixLen value with a bit count
//func (p *BitCount) Matches(other BitCount) bool {
//	return p != nil && *p == other
//}
//
//// Compare compares PrefixLen values, returning -1, 0, or 1 if the receiver is less than, equal to, or greater than the argument.
//// This method is intended for the PrefixLen type.  BitCount values should be compared with ==, >, <, >= amd <= operators.
//func (p *BitCount) Compare(other *BitCount) int {
//	if p == nil {
//		if other == nil {
//			return 0
//		}
//		return 1
//	} else if other == nil {
//		return -1
//	}
//	return int(*p) - int(*other)
//}
//
//func (p *BitCount) String() string {
//	if p == nil {
//		return nilString()
//	}
//	return strconv.Itoa(int(*p))
//}

// A BitCount represents a count of bits in an address, section, grouping, segment, or division.
// Using signed integers allows for easier arithmetic and decrement bugs.
// Using a signed int (rather than int16 or int8) provides for cleaner code, but all methods adjust bit counts to match address size,
// so negative bit counts or bit counts larger than address size are meaningless.
//type BitCount = int
//
//type bitCount = int16 // using signed integers allows for easier arithmetic and decrement bugs

// A PrefixLen indicates the numnber of bits in the prefix of an address, address section, or address segment.
// The zero value is the absence of a prefix, in which case isNil() returns true.
//type PrefixLen struct {
//	isSet    bool
//	bitCount bitCount
//}

/*
This solution is the best for several reasons:
1. We can represent the absence of prefix length with nil
2. Prefix lengths are immutable thanks to the private member
3. BitCounts, being equivalent to int, can take int args
4. bitCount saves space in our data structures
This solves all our requirements, and is the only solution to do so, specifically #1.
*/

// PrefixLen indicates the length of the prefix for an address, section, division grouping, segment, or division.
// The zero value, which is nil, indicates that there is no prefix length.
type PrefixLen = *PrefixBitCount

type PrefixBitCount uint8

// is it possible to change PrefixBitCount?  To make PrefixLen easier to construct?
//maybe switch to: type PrefixBitCount uint8
//Because it seems to me, the alias is not required
//And you do not seem to use bitCount anywhere

type BitCount = int // using signed integers allows for easier arithmetic
//type bitCount = uint8

const maxBitCountInternal, minBitCountInternal = math.MaxUint8, 0

//type PrefixBitCount struct {
//	bCount bitCount
//}

/*
p1 := ipaddr.ToPrefixLen(1)
p2 := ipaddr.ToPrefixLen(2)
*p1 = *p2

So then we might try to make PrefixBitCount private, but then when we do the godocs, the methods do not appear for PrefixLen
And making it private does not work anyway.
Yeesh.
You have two options as far as I can tell:
1. copy to your own internal PrefixLen on function calls.  Returns a copy on calls to get the prefix len.
2. Use interfaces.  So PrefixLen becomes an interface.  PrefixBitCount becomes private.  You can still store a ptr to a struct in the data structs.
	But you must check that pointer for nil when accessing, and return nil for the interface.
I do not think I like interface for this, since there really is no method, it is a value.

I  think i may need to return to a BitCount pointer, and when we store to the field, we get our own pointer to store.
And then when we return the prefix len, we need to make a copy.
We can still use the bitCount() method to dereference.
// - ensure you always assign the internal copy to addressDivisionGroupingBase
// - when obtaining the prefix internally, use a getPrefixLength that does not copy it
// - the external methods must use a copy
// - same for divisions/segments
// Seems as though nothing needed for MAC
*/

// Len() returns the length of the prefix.  If the receiver is nil, representing the absence of a prefix length, returns 0.
// It will also return 0 if the receiver is a prefix with length is 0.
func (p *PrefixBitCount) Len() BitCount {
	if p == nil {
		return 0
	}
	return p.bitCount()
}

func (p *PrefixBitCount) IsNil() bool {
	return p == nil
}

//func (p *PrefixBitCount) Len() (len BitCount, exists bool) {
//	if p == nil {
//		return 0, false
//	}
//	return p.bitCount(), true
//}

// before calling this, check for nil
//func (p *PrefixBitCount) bitCount() BitCount {
//	return BitCount(p.bCount)
//}
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
//func (p *PrefixBitCount) Equal(other *BitCount) bool {
//	if p == nil {
//		return other == nil
//	}
//	return other != nil && p.bitCount() == *other
//}
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

//xxxx we should make it an interface so we can use nil xxxx
//NOT SURE
//NAH
//BUT WHY ARE WE NOT USING a pointer to a struct?  Was that on my list?  That makes more sense I think
//xxxxx

//func (p PrefixLen) IsNil() bool {
//	return p.isSet
//}

//// Equal compares two PrefixLen values for equality.  This method is intended for the PrefixLen type.  BitCount values should be compared with == operator.
//func (p PrefixLen) Equal(other PrefixLen) bool {
//	return p.isSet == other.isSet && p.bitCount == other.bitCount
//}
//
//// Matches compares a PrefixLen value with a bit count
//func (p PrefixLen) Matches(other BitCount) bool {
//	return p.isSet && p.Len() == other
//}
//
//// Compare compares PrefixLen values, returning -1, 0, or 1 if the receiver is less than, equal to, or greater than the argument.
//// This method is intended for the PrefixLen type.  BitCount values should be compared with ==, >, <, >= amd <= operators.
//func (p PrefixLen) Compare(other PrefixLen) int {
//	if p.isSet {
//		if other.isSet {
//			return 0
//		}
//		return -1
//	} else if other.isSet {
//		return 1
//	}
//	return int(p.bitCount - other.bitCount)
//}
//
//func (p PrefixLen) String() string {
//	if !p.isSet {
//		return nilString()
//	}
//	return strconv.Itoa(p.Len())
//}

//type PrefixLen = *BitCount

var cachedPrefixBitCounts, cachedPrefixLens = initPrefLens()

//var cachedPrefixLens = initPrefLens()

//var minusOne BitCount = -1
//var noPrefix PrefixLen = &minusOne

func initPrefLens() ([]PrefixBitCount, []PrefixLen) {
	cachedPrefBitcounts := make([]PrefixBitCount, maxBitCountInternal)
	cachedPrefLens := make([]PrefixLen, maxBitCountInternal)
	for i := 0; i <= IPv6BitCount; i++ {
		//cachedPrefBitcounts[i] = PrefixBitCount{i}
		cachedPrefBitcounts[i] = PrefixBitCount(i)
		cachedPrefLens[i] = &cachedPrefBitcounts[i]
	}
	return cachedPrefBitcounts, cachedPrefLens
}

// ToPrefixLen creates a prefix length.  A prefix length can only range from 0 to 255,
// although in practice it really only makes sense to have a prefix length that is no larger than the item (such as an address) with the prefix.
// If bit count argument is negative, the resulting prefix length will be zero.
// If bit count argument is larger than 255, the resulting prefix length will be 255.
//func ToPrefixLen(i BitCount) PrefixLen {
//	if i < minBitCountInternal {
//		i = minBitCountInternal
//	}
//	if i <= IPv6BitCount {
//		return &cachedPrefixBitCounts[i]
//	}
//	if i > maxBitCountInternal {
//		i = maxBitCountInternal
//	}
//	//return &PrefixBitCount{bitCount(i)}
//	res := PrefixBitCount(i)
//	return &res
//}

func cacheBitCount(i BitCount) PrefixLen {
	//return ToPrefixLen(i)
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

//func initPrefLens() []PrefixLen {
//	cachedPrefLens := make([]PrefixLen, IPv6BitCount+1)
//	for i := bitCount(0); i <= IPv6BitCount; i++ {
//		cachedPrefLens[i] = PrefixLen{
//			isSet:    true,
//			bitCount: i,
//		}
//		//bc := i
//		//cachedPrefLens[i] = &bc
//	}
//	return cachedPrefLens
//}
//
//func NilPrefix() PrefixLen {
//	return PrefixLen{}
//}

//func cacheBitCount(i BitCount) PrefixLen {
//	if i >= 0 && i < BitCount(len(cachedPrefixLens)) {
//		result := cachedPrefixLens[i]
//		return result
//	}
//	return PrefixLen{
//		isSet:    true,
//		bitCount: bitCount(i),
//	}
//	//bc := i
//	//return &bc
//}
//
//func cachePrefix(i BitCount) *PrefixLen {
//	if i >= 0 && i < BitCount(len(cachedPrefixLens)) {
//		return &cachedPrefixLens[i]
//	}
//	res := cacheBitCount(i)
//	return &res
//}

var p PrefixLen

func cacheNilPrefix() *PrefixLen {
	return &p
}

const maxPortNumInternal, minPortNumInternal = math.MaxUint16, 0

// Port represents the port of a UDP or TCP address.  It ca
type Port = *PortNum

type PortInt = int // using signed integers allows for easier arithmetic

type PortNum uint16

func (p *PortNum) portNum() PortInt {
	//return PortInt(p.port)
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
	//return ToPort(i)
	if i < minPortNumInternal {
		i = minPortNumInternal
	} else if i > maxPortNumInternal {
		i = maxPortNumInternal
	}
	res := PortNum(i)
	return &res
}

//// ToPort creates a port for use with a HostName.  A prefix length can only range from 0 to 65535.
//// If the port number argument is negative, the resulting Port will be zero.
//// If the port number argument is larger than 65535, the resulting Port will be 65535.
//func ToPort(i PortInt) Port {
//	if i < minPortNumInternal {
//		i = minPortNumInternal
//	} else if i > maxPortNumInternal {
//		i = maxPortNumInternal
//	}
//	return &PortNum{portNum(i)}
//}

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

//func checkPrefLen(prefixLength PrefixLen, max BitCount) PrefixLen {
//	if prefixLength.isSet {
//		prefLen := prefixLength.Len()
//		if prefLen > max {
//			return cacheBitCount(max)
//		} else if prefLen < 0 {
//			return cacheBits(0)
//		}
//	}
//	return prefixLength
//
//}

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
