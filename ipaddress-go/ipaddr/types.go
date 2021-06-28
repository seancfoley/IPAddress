package ipaddr

import "math/big"

type BitCount int16 // using signed integers allows for easier arithmetic and decrement bugs

func cacheBits(i int) PrefixLen {
	return cacheBitCount(BitCount(i))
}

//func (p *BitCount) Equals(other *BitCount) bool { this just doesn't work, I tried...
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

type PrefixLen *BitCount //TODO ensure you check for negative prefix lens everywhere (I think I do that for the most part)

var cachedPrefixLens = initPrefLens()

func cacheBitCount(i BitCount) PrefixLen {
	return cache(i)
}

func initPrefLens() []PrefixLen {
	cachedPrefLens := make([]PrefixLen, IPv6BitCount+1)
	for i := 0; i <= IPv6BitCount; i++ {
		bc := BitCount(i)
		cachedPrefLens[i] = &bc
	}
	return cachedPrefLens
}

func cache(i BitCount) PrefixLen {
	if i >= 0 && i < BitCount(len(cachedPrefixLens)) {
		result := cachedPrefixLens[i]
		return result
	}
	bc := BitCount(i)
	return &bc
}

type Port *int // using signed integers allows for easier arithmetic and decrement bugs

func PortEquals(one, two Port) bool {
	if one == nil {
		return two == nil
	}
	return two != nil && *one == *two
}

func cachePorts(i int) Port {
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
