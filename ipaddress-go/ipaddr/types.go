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

func GetPrefixLen(i int) PrefixLen {
	return cacheBits(i)
}

func cacheBits(i int) PrefixLen {
	return cacheBitCount(BitCount(i))
}

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
//type bitCountInternal = int16 // using signed integers allows for easier arithmetic and decrement bugs

// A PrefixLen indicates the numnber of bits in the prefix of an address, address section, or address segment.
// The zero value is the absence of a prefix, in which case isNil() returns true.
//type PrefixLen struct {
//	isSet    bool
//	bitCount bitCountInternal
//}

/*
This solution is the best for several reasons:
1. We can represent the absence of prefix length with nil
2. Prefix lengths are immutable thanks to the private member
3. BitCounts, being equivalent to int, can take int args
4. bitCountInternal saves space in our data structures
This solves all our requirements, and is the only solution to do so, specifically #1.
*/

// PrefixLen indicates the length of the prefix for an address, section, division grouping, segment, or division.
// The zero value, which is nil, indicates that there is no prefix length.
type PrefixLen = *PrefixBitCount

type BitCount = int

func ToPrefixLen(i BitCount) PrefixLen {
	if i < 0 {
		i = 0
	}
	if i <= IPv6BitCount {
		return &PrefixBitCount{bitCountInternal(i)} //TODO use cache
	}
	if i > math.MaxInt16 {
		i = math.MaxInt16
	}
	return &PrefixBitCount{bitCountInternal(i)}
}

func ToString(i BitCount) string {
	return strconv.Itoa(i)
}

type bitCountInternal = int16

type PrefixBitCount struct {
	bCount bitCountInternal
}

// Len() returns the length of the prefix.  If the receiver is nil, representing the absence of a prefix length, returns 0.
// It will also return 0 if the receiver is a prefix with length is 0.
func (p *PrefixBitCount) Len() BitCount {
	if p == nil {
		return 0
	}
	return p.bitCount()
}

//func (p *PrefixBitCount) Len() (len BitCount, exists bool) {
//	if p == nil {
//		return 0, false
//	}
//	return p.bitCount(), true
//}

// before calling this, check for nil
func (p *PrefixBitCount) bitCount() BitCount {
	return BitCount(p.bCount)
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
// This method is intended for the PrefixLen type.  BitCount values should be compared with ==, >, <, >= amd <= operators.
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

var cachedPrefixLens = initPrefLens()

//var minusOne BitCount = -1
//var noPrefix PrefixLen = &minusOne

func initPrefLens() []PrefixLen {
	cachedPrefLens := make([]PrefixLen, IPv6BitCount+1)
	for i := bitCountInternal(0); i <= bitCountInternal(IPv6BitCount); i++ {
		cachedPrefLens[i] = &PrefixBitCount{i}
	}
	return cachedPrefLens
}

//func initPrefLens() []PrefixLen {
//	cachedPrefLens := make([]PrefixLen, IPv6BitCount+1)
//	for i := bitCountInternal(0); i <= IPv6BitCount; i++ {
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

func cacheBitCount(i BitCount) PrefixLen {
	if i >= 0 && i < BitCount(len(cachedPrefixLens)) {
		result := cachedPrefixLens[i]
		return result
	}
	return &PrefixBitCount{bitCountInternal(i)}
}

func cachePrefix(i BitCount) *PrefixLen { //TODO use cache: in the new world, we will have an array of prefix structs and this will return the address, while cacheBitCount will return a copy
	res := cacheBitCount(i)
	return &res
}

//func cacheBitCount(i BitCount) PrefixLen {
//	if i >= 0 && i < BitCount(len(cachedPrefixLens)) {
//		result := cachedPrefixLens[i]
//		return result
//	}
//	return PrefixLen{
//		isSet:    true,
//		bitCount: bitCountInternal(i),
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

func cacheNilPrefix() *PrefixLen {
	var p PrefixLen
	return &p
}

//TODO Port has the same problems as PrefixLen and needs the same conversion
type Port = *PortNum // using signed integers allows for easier arithmetic and decrement bugs
type PortNum uint16

// Equal compares two PrefixLen values for equality.  This method is intended for the PrefixLen type.  BitCount values should be compared with == operator.
func (p *PortNum) Equal(other *PortNum) bool {
	if p == nil {
		return other == nil
	}
	return other != nil && *p == *other
}

func (p *PortNum) String() string {
	if p == nil {
		return nilString()
	}
	return strconv.Itoa(int(*p))
}

func cachePorts(i PortNum) Port {
	return Port(&i)
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
			return cacheBits(0)
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
