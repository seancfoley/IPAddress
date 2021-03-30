package ipaddr

import "math/big"

type BitCount int16 // using signed integers allows for easier arithmetic and decrement bugs

func cacheBits(i int) PrefixLen {
	return cacheBitCount(BitCount(i))
}

//func (p *BitCount) Equals(other *BitCount) bool { this just don't work, I tried...
//	if p == nil {
//		return other == nil
//	} else if other == nil {
//		return false
//	}
//	return *p == *other
//}

func PrefixEquals(one, two PrefixLen) bool {
	if one == nil {
		return two == nil
	}
	return two != nil && *one == *two
}

type PrefixLen *BitCount //TODO ensure you check for negative prefix lens everywhere

func cacheBitCount(i BitCount) PrefixLen {
	//TODO caching
	bits := i
	return PrefixLen(&bits)
}

type Port *int // using signed integers allows for easier arithmetic and decrement bugs

func PortEquals(one, two Port) bool {
	if one == nil {
		return two == nil
	}
	return two != nil && *one == *two
}

func cachePorts(i int) Port {
	//TODO caching
	return Port(&i)
}

//type Service string

// Allows for 3 different boolean values: not set, set to true, set to false (Similar to Boolean in Java which is null, true, false)
//type boolSetting struct {
//	value, isSet bool
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
