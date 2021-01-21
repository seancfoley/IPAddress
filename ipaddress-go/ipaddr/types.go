package ipaddr

import "math/big"

type BitCount int16 // using signed integers allows for easier arithmetic and decrement bugs

//func (p *BitCount) Equals(other *BitCount) bool {
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
	} else if two == nil {
		return false
	}
	return *one == *two
}

type PrefixLen *BitCount

type Port *int // using signed integers allows for easier arithmetic and decrement bugs

type Service string

// Allows for 3 different boolean values: not set, set to true, set to false (Similar to Boolean in Java which is null, true, false)
type boolSetting struct {
	value, isSet bool
}

func bigOne() *big.Int {
	return big.NewInt(1)
}

func bigZero() *big.Int {
	return new(big.Int)
}
