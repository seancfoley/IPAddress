package ipaddr

import (
	"math/big"
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

//func (p PrefixLen) Equals(other PrefixLen) bool { this does not work either, cannot have pointer receiver...
//	if p == nil {
//		return other == nil
//	} else if other == nil {
//		return false
//	}
//	return *p == *other
//}

func (p *BitCount) Equals(other *BitCount) bool {
	if p == nil {
		return other == nil
	} else if other == nil {
		return false
	}
	return *p == *other
}

func PrefixEquals(one, two PrefixLen) bool { //TODO replace calls to this with the above
	if one == nil {
		return two == nil
	}
	return two != nil && *one == *two
}

type PrefixLen = *BitCount

var cachedPrefixLens = initPrefLens()

func cacheBitCount(i BitCount) PrefixLen {
	if i >= 0 && i < BitCount(len(cachedPrefixLens)) {
		result := cachedPrefixLens[i]
		return result
	}
	bc := BitCount(i)
	return &bc
}

func initPrefLens() []PrefixLen {
	cachedPrefLens := make([]PrefixLen, IPv6BitCount+1)
	for i := BitCount(0); i <= IPv6BitCount; i++ {
		bc := i
		cachedPrefLens[i] = &bc
	}
	return cachedPrefLens
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
