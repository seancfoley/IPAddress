package ipaddr

import (
	"strconv"
	"strings"
)

const (
	DIGITS = "0123456789abcdefghijklmnopqrstuvwxyz"

	EXTENDED_DIGITS = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-';<=>?@^_`{|}~"

	UPPERCASE_DIGITS = EXTENDED_DIGITS

	DOUBLE_DIGITS_DEC = "00010203040506070809" +
		"10111213141516171819" +
		"20212223242526272829" +
		"30313233343536373839" +
		"40414243444546474849" +
		"50515253545556575859" +
		"60616263646566676869" +
		"70717273747576777879" +
		"80818283848586878889" +
		"90919293949596979899"
)

func toUnsignedString(value uint64, radix int, appendable *strings.Builder) *strings.Builder {
	return toUnsignedStringCased(value, radix, 0, false, appendable)
}

func toUnsignedStringCased(value uint64, radix, choppedDigits int, uppercase bool, appendable *strings.Builder) *strings.Builder {
	if value > 0xffff || choppedDigits != 0 || !toUnsignedStringFast(uint16(value), radix, uppercase, appendable) {
		toUnsignedStringSlow(value, radix, choppedDigits, uppercase, appendable)
	}
	return appendable
}

func toUnsignedStringFast(value uint16, radix int, uppercase bool, appendable *strings.Builder) bool {
	if value <= 1 { //for values larger than 1, result can be different with different radix (radix is 2 and up)
		if value == 0 {
			appendable.WriteByte('0')
		} else {
			appendable.WriteByte('1')
		}
		return true
	}
	//var quotient, remainder uint //we iterate on //value == quotient * radix + remainder
	if radix == 10 {
		// we know value <= 0xffff (ie 16 bits or less)
		if value < 10 {
			appendable.WriteByte(DIGITS[value])
			return true
		} else if value < 100 {
			dig := DOUBLE_DIGITS_DEC
			digIndex := value << 1
			appendable.WriteByte(dig[digIndex])
			appendable.WriteByte(dig[digIndex+1])
			return true
		} else if value < 200 {
			dig := DOUBLE_DIGITS_DEC
			digIndex := (value - 100) << 1
			appendable.WriteByte('1')
			appendable.WriteByte(dig[digIndex])
			appendable.WriteByte(dig[digIndex+1])
			return true
		} else if value < 300 {
			dig := DOUBLE_DIGITS_DEC
			digIndex := (value - 200) << 1
			appendable.WriteByte('2')
			appendable.WriteByte(dig[digIndex])
			appendable.WriteByte(dig[digIndex+1])
			return true
		}
		dig := DIGITS
		uval := uint(value)
		var res [5]byte
		i := 5
		for uval != 0 { //value == quotient * 10 + remainder
			i--
			quotient := (uval * 0xcccd) >> 19                       // floor of n/10 is floor of ((0xcccd * n / 2^16) / 2^3)
			remainder := uval - ((quotient << 3) + (quotient << 1)) //multiplication by 2 added to multiplication by 2^3 is multiplication by 2 + 8 = 10
			res[i] = dig[remainder]
			uval = quotient
		}
		appendable.Write(res[i:])
		return true
	} else if radix == 16 {
		if value < 0x10 {
			dig := getDigits(uppercase, radix)
			appendable.WriteByte(dig[value])
			return true
		} else if value == 0xffff {
			if uppercase {
				appendable.WriteString("FFFF")
			} else {
				appendable.WriteString("ffff")
			}
			return true
		}
		dig := getDigits(uppercase, radix)

		//var res [4]byte
		//i := 4
		//for { //value2 == quotient * 16 + remainder
		//	i--
		//	remainder := value & 15
		//	value >>= 4
		//	res[i] = dig[remainder]
		//	if value == 0 {
		//		break
		//	}
		//}
		//appendable.Write(res[i:])

		shift := 12
		for shift > 0 {
			index := (value >> shift) & 15
			if index != 0 { // index 0 is digit "0"
				appendable.WriteByte(dig[index])
				for shift > 0 {
					appendable.WriteByte(dig[(value>>shift)&15])
					shift -= 4
				}
				break
			}
			shift -= 4
		}
		appendable.WriteByte(dig[value&15])
		return true
	} else if radix == 8 {
		dig := DIGITS
		if value < 010 {
			appendable.WriteByte(dig[value])
			return true

		}
		shift := 15
		for shift > 0 {
			index := (value >> shift) & 7
			if index != 0 { // index 0 is digit "0"
				appendable.WriteByte(dig[index])
				for shift > 0 {
					appendable.WriteByte(dig[(value>>shift)&7])
					shift -= 3
				}
				break
			}
			shift -= 3
		}
		appendable.WriteByte(dig[value&7])
		return true
	} else if radix == 2 {
		//note that we already know value != 0 and that value <= 0xffff
		var digitIndex int
		if (value >> 8) == 0 {
			if value == 0xff {
				appendable.WriteString("11111111")
				return true
			} else if (value >> 4) == 0 {
				digitIndex = 4
			} else {
				digitIndex = 8
			}
		} else {
			if value == 0xffff {
				appendable.WriteString("1111111111111111")
				return true
			} else if (value >> 4) == 0 {
				digitIndex = 12
			} else {
				digitIndex = 16
			}
		}
		for digitIndex--; digitIndex > 0; digitIndex-- {
			digit := (value >> digitIndex) & 1
			if digit == 1 {
				appendable.WriteByte('1')
				for digitIndex--; digitIndex > 0; digitIndex-- {
					digit = (value >> digitIndex) & 1
					if digit == 0 {
						appendable.WriteByte('0')
					} else {
						appendable.WriteByte('1')
					}
				}
				break
			}
		}
		if (value & 1) == 0 {
			appendable.WriteByte('0')
		} else {
			appendable.WriteByte('1')
		}
		return true
	}
	return false
}

func toUnsignedStringSlow(
	value uint64,
	radix,
	choppedDigits int,
	uppercase bool,
	appendable *strings.Builder) {
	var str string
	if radix <= 36 { // strconv.FormatUint doesn't work with larger radix
		str = strconv.FormatUint(value, radix)
		if choppedDigits > 0 {
			str = str[:len(str)-choppedDigits]
		}
		if uppercase && radix > 10 {
			strlen := len(str)
			diff := uint8('a' - 'A')
			for i := 0; i < strlen; i++ {
				c := str[i]
				if c > '9' {
					c -= diff
				}
				appendable.WriteByte(c)
			}
		} else {
			appendable.WriteString(str)
		}
		return
	}
	var bytes [13]byte
	index := 13
	dig := EXTENDED_DIGITS
	rad64 := uint64(radix)
	for value >= rad64 {
		val := value
		value /= rad64
		if choppedDigits > 0 {
			choppedDigits--
			continue
		}
		index--
		remainder := val - (value * rad64)
		bytes[index] = dig[remainder]
	}
	if choppedDigits == 0 {
		appendable.WriteByte(dig[value])
	}
	appendable.Write(bytes[index:])
}

func getDigits(uppercase bool, radix int) string {
	if uppercase || radix > 36 {
		return UPPERCASE_DIGITS
	}
	return DIGITS
}
