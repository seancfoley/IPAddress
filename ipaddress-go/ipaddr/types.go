package ipaddr

import (
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

type BitCount int16 // using signed integers allows for easier arithmetic and decrement bugs

func GetPrefixLen(i int) PrefixLen {
	return cacheBits(i)
}

func cacheBits(i int) PrefixLen {
	return cacheBitCount(BitCount(i))
}

// Equals compares two PrefixLen values for equality.  This method is intended for the PrefixLen type.  BitCount values should be compared with == operator.
func (p *BitCount) Equals(other *BitCount) bool {
	if p == nil {
		return other == nil
	} else if other == nil {
		return false
	}
	return *p == *other
}

// Matches compares a PrefixLen value with a bit count
func (p *BitCount) Matches(other BitCount) bool {
	return p != nil && *p == other
}

// Exceeds is true if PrefixLen is a value that is larger than the supplied bit count
func (p *BitCount) Exceeds(other BitCount) bool {
	return p != nil && *p > other
}

// Within is true if PrefixLen is a value that is smaller than or equal to the supplied bit count
func (p *BitCount) Within(other BitCount) bool {
	return p != nil && *p <= other
}

// Compare compares PrefixLen values, returning -1, 0, or 1 if the receiver is less than, equal to, or greater than the argument.
// This method is intended for the PrefixLen type.  BitCount values should be compared with ==, >, <, >= amd <= operators.
func (p *BitCount) Compare(other *BitCount) int {
	if p == nil {
		if other == nil {
			return 0
		}
		return 1
	} else if other == nil {
		return -1
	}
	return int(*p) - int(*other)
}

func (p *BitCount) String() string {
	if p == nil {
		return "<nil>"
	}
	return strconv.Itoa(int(*p))
}

func PrefixEquals(one, two PrefixLen) bool { //TODO replace calls to this with the above
	if one == nil {
		return two == nil
	}
	return two != nil && *one == *two
}

type PrefixLen = *BitCount

var cachedPrefixLens = initPrefLens()
var minusOne BitCount = -1
var noPrefix PrefixLen = &minusOne

func initPrefLens() []PrefixLen {
	cachedPrefLens := make([]PrefixLen, IPv6BitCount+1)
	for i := BitCount(0); i <= IPv6BitCount; i++ {
		bc := i
		cachedPrefLens[i] = &bc
	}
	return cachedPrefLens
}

func cacheBitCount(i BitCount) PrefixLen {
	if i >= 0 && i < BitCount(len(cachedPrefixLens)) {
		result := cachedPrefixLens[i]
		return result
	}
	bc := i
	return &bc
}

type Port *PortNum // using signed integers allows for easier arithmetic and decrement bugs
type PortNum int

func PortEquals(one, two Port) bool {
	if one == nil {
		return two == nil
	}
	return two != nil && *one == *two
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
		prefLen := *prefixLength
		if prefLen > max {
			return cacheBitCount(max)
		} else if prefLen < 0 {
			return cacheBits(0)
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
