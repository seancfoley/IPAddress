package ipaddr

import (
	"fmt"
	"strconv"
	"strings"
	"sync/atomic"
	"unsafe"
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
		i := 4
		for { //value == quotient * 10 + remainder
			quotient := (uval * 0xcccd) >> 19                       // floor of n/10 is floor of ((0xcccd * n / 2^16) / 2^3)
			remainder := uval - ((quotient << 3) + (quotient << 1)) //multiplication by 2 added to multiplication by 2^3 is multiplication by 2 + 8 = 10
			res[i] = dig[remainder]
			uval = quotient
			if uval == 0 {
				break
			}
			i--
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
		shift := uint(12)
		for {
			index := (value >> shift) & 15
			if index != 0 { // index 0 is digit "0", no need to write leading zeros
				appendable.WriteByte(dig[index])
				shift -= 4
				for shift > 0 {
					appendable.WriteByte(dig[(value>>shift)&15])
					shift -= 4
				}
				break
			}
			shift -= 4
			if shift == 0 {
				break
			}
		}
		appendable.WriteByte(dig[value&15])
		return true
	} else if radix == 8 {
		dig := DIGITS
		if value < 010 {
			appendable.WriteByte(dig[value])
			return true

		}
		shift := uint(15)
		for {
			index := (value >> shift) & 7
			if index != 0 { // index 0 is digit "0"
				appendable.WriteByte(dig[index])
				shift -= 3
				for shift > 0 {
					appendable.WriteByte(dig[(value>>shift)&7])
					shift -= 3
				}
				break
			}
			shift -= 3
			if shift == 0 {
				break
			}
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

func toUnsignedStringLength(value uint64, radix int) int {
	if value <= 0xffff {
		if result := toUnsignedStringLengthFast(uint16(value), radix); result >= 0 {
			return result
		}
	}
	return toUnsignedStringLengthSlow(value, radix)

}

const maxUint = ^uint(0)

func toUnsignedStringLengthSlow(value uint64, radix int) int {
	count := 1
	useInts := value <= uint64(maxUint)
	var value2 uint = uint(radix)
	if useInts {
		value2 = uint(value)
	}
	uradix := uint(radix)
	for value2 >= uradix {
		if useInts {
			value2 /= uradix
		} else {
			value /= uint64(radix)
			if value <= uint64(maxUint) {
				useInts = true
				value2 = uint(value)
			}
		}
		count++
	}
	return count
}

func toUnsignedStringLengthFast(value uint16, radix int) int {
	if value <= 1 { //for values larger than 1, result can be different with different radix (radix is 2 and up)
		return 1
	}
	if radix == 10 {
		//this needs value <= 0xffff (ie 16 bits or less) which is a prereq to calling this method
		if value < 10 {
			return 1
		} else if value < 100 {
			return 2
		} else if value < 1000 {
			return 3
		} else if value < 10000 {
			return 4
		}
		return 5
	}
	if radix == 16 {
		//this needs value <= 0xffff (ie 16 bits or less)
		if value < 0x10 {
			return 1
		} else if value < 0x100 {
			return 2
		} else if value < 0x1000 {
			return 3
		}
		return 4
	}
	if radix == 8 {
		//this needs value <= 0xffff (ie 16 bits or less)
		if value < 010 {
			return 1
		} else if value < 0100 {
			return 2
		} else if value < 01000 {
			return 3
		} else if value < 010000 {
			return 4
		} else if value < 0100000 {
			return 5
		}
		return 6
	}
	if radix == 2 {
		//count the number of digits
		//note that we already know value != 0 and that value <= 0xffff
		//and we use both of those facts
		digitCount := 15
		val := value
		if val>>8 == 0 {
			digitCount -= 8
		} else {
			val >>= 8
		}
		if val>>4 == 0 {
			digitCount -= 4
		} else {
			val >>= 4
		}
		if val>>2 == 0 {
			digitCount -= 2
		} else {
			val >>= 2
		}
		//at this point, if (val & 2) != 0 we have undercounted the digit count by 1
		if (val & 2) != 0 {
			digitCount++
		}
		return digitCount
	}
	return -1
}

func toDefaultString(val uint64, radix int) string {
	//0 and 1 are common segment values, and additionally they are the same regardless of radix (even binary)
	//so we have a fast path for them
	if val == 0 {
		return "0"
	} else if val == 1 {
		return "1"
	}
	var len int
	var quotient, remainder, value uint //we iterate on //value == quotient * radix + remainder
	if radix == 10 {
		if val < 10 {
			return DIGITS[val : val+1]
		} else if val < 100 {
			dig := DOUBLE_DIGITS_DEC
			value = uint(val)
			digIndex := value << 1
			var builder strings.Builder
			builder.Grow(2)
			builder.WriteByte(dig[digIndex])
			builder.WriteByte(dig[digIndex+1])
			return builder.String()
		} else if val < 200 {
			dig := DOUBLE_DIGITS_DEC
			value = uint(val)
			digIndex := (value - 100) << 1
			var builder strings.Builder
			builder.WriteByte('1')
			builder.WriteByte(dig[digIndex])
			builder.WriteByte(dig[digIndex+1])
			return builder.String()
		} else if val < 300 {
			dig := DOUBLE_DIGITS_DEC
			value = uint(val)
			digIndex := (value - 200) << 1
			var builder strings.Builder
			builder.WriteByte('2')
			builder.WriteByte(dig[digIndex])
			builder.WriteByte(dig[digIndex+1])
			return builder.String()
		} else if val < 1000 {
			len = 3
			value = uint(val)
		} else {
			return strconv.FormatUint(val, 10)
		}
		chars := make([]byte, len)
		dig := DIGITS
		for value != 0 {
			len--
			//value == quotient * 10 + remainder
			quotient = (value * 0xcccd) >> 19                       //floor of n/10 is floor of ((0xcccd * n / (2 ^ 16)) / (2 ^ 3))
			remainder = value - ((quotient << 3) + (quotient << 1)) //multiplication by 2 added to multiplication by 2 ^ 3 is multiplication by 2 + 8 = 10
			chars[len] = dig[remainder]
			value = quotient
		}
		return string(chars)
	} else if radix == 16 {
		if val < 0x10 {
			return DIGITS[val : val+1]
		}
		var builder strings.Builder
		if val < 0x100 {
			len = 2
			value = uint(val)
		} else if val < 0x1000 {
			len = 3
			value = uint(val)
		} else if val < 0x10000 {
			if val == 0xffff {
				return "ffff"
			}
			value = uint(val)
			len = 4
		} else {
			return strconv.FormatUint(val, 16)
		}
		dig := DIGITS
		builder.Grow(len)
		shift := uint(12)
		for {
			index := (value >> shift) & 15
			if index != 0 { // index 0 is digit "0", so no need to write a leading zero
				builder.WriteByte(dig[index])
				shift -= 4
				for shift > 0 {
					builder.WriteByte(dig[(value>>shift)&15])
					shift -= 4
				}
				break
			}
			shift -= 4
			if shift == 0 {
				break
			}
		}
		builder.WriteByte(dig[value&15])
		return builder.String()
	}
	return strconv.FormatUint(val, radix)
}

func getDefaultRangeStringVals(strProvider divStringProvider, val1, val2 uint64, radix int) string {
	var len1, len2 int      // we iterate on //value == quotient * radix + remainder
	var value1, value2 uint // we iterate on //value == quotient * radix + remainder
	if radix == 10 {
		if val2 < 10 {
			len2 = 1
		} else if val2 < 100 {
			len2 = 2
		} else if val2 < 1000 {
			len2 = 3
		} else {
			return buildDefaultRangeString(strProvider, radix)
		}
		value2 = uint(val2)
		if val1 < 10 {
			len1 = 1
		} else if val1 < 100 {
			len1 = 2
		} else if val1 < 1000 {
			len1 = 3
		} else {
			return buildDefaultRangeString(strProvider, radix)
		}
		value1 = uint(val1)

		charsStr := strings.Builder{}
		charsStr.Grow(len1 + len2 + 1)

		dig := DIGITS
		doubleDig := DOUBLE_DIGITS_DEC

		var quotient, remainder uint

		var chars []byte

		if val1 < 10 {
			charsStr.WriteByte(dig[value1])
		} else if val1 < 100 {
			digIndex := value1 << 1
			charsStr.WriteByte(doubleDig[digIndex])
			charsStr.WriteByte(doubleDig[digIndex+1])
		} else if val1 < 200 {
			charsStr.WriteByte('1')
			digIndex := (value1 - 100) << 1
			charsStr.WriteByte(doubleDig[digIndex])
			charsStr.WriteByte(doubleDig[digIndex+1])
		} else if val1 < 300 {
			charsStr.WriteByte('2')
			digIndex := (value1 - 200) << 1
			charsStr.WriteByte(doubleDig[digIndex])
			charsStr.WriteByte(doubleDig[digIndex+1])
		} else {
			chars = make([]byte, len2) // note that len2 >= len1
			origLen1 := len1
			for {
				//value == quotient * 10 + remainder
				quotient = (value1 * 0xcccd) >> 19                       //floor of n/10 is floor of ((0xcccd * n / (2 ^ 16)) / (2 ^ 3))
				remainder = value1 - ((quotient << 3) + (quotient << 1)) //multiplication by 2 added to multiplication by 2 ^ 3 is multiplication by 2 + 8 = 10
				len1--
				chars[len1] = dig[remainder]
				value1 = quotient
				if value1 == 0 {
					break
				}
			}
			charsStr.Write(chars[:origLen1])
		}
		charsStr.WriteByte(RangeSeparator)
		if val2 < 10 {
			charsStr.WriteByte(dig[value2])
		} else if val2 < 100 {
			digIndex := value2 << 1
			charsStr.WriteByte(doubleDig[digIndex])
			charsStr.WriteByte(doubleDig[digIndex+1])
		} else if val2 < 200 {
			charsStr.WriteByte('1')
			digIndex := (value2 - 100) << 1
			charsStr.WriteByte(doubleDig[digIndex])
			charsStr.WriteByte(doubleDig[digIndex+1])
		} else if val2 < 300 {
			charsStr.WriteByte('2')
			digIndex := (value2 - 200) << 1
			charsStr.WriteByte(doubleDig[digIndex])
			charsStr.WriteByte(doubleDig[digIndex+1])
		} else {
			origLen2 := len2
			if chars == nil {
				chars = make([]byte, len2)
			}
			for {
				quotient = (value2 * 0xcccd) >> 19
				remainder = value2 - ((quotient << 3) + (quotient << 1))
				len2--
				chars[len2] = dig[remainder]
				value2 = quotient
				if value2 == 0 {
					break
				}
			}
			charsStr.Write(chars[:origLen2])
		}
		return charsStr.String()
	} else if radix == 16 {
		if val2 < 0x10 {
			len2 = 1
		} else if val2 < 0x100 {
			len2 = 2
		} else if val2 < 0x1000 {
			len2 = 3
		} else if val2 < 0x10000 {
			len2 = 4
		} else {
			return buildDefaultRangeString(strProvider, radix)
		}
		if val1 < 0x10 {
			len1 = 1
		} else if val1 < 0x100 {
			len1 = 2
		} else if val1 < 0x1000 {
			len1 = 3
		} else if val1 < 0x10000 {
			len1 = 4
		} else {
			return buildDefaultRangeString(strProvider, radix)
		}
		value1 = uint(val1)
		charsStr := strings.Builder{}
		charsStr.Grow(len1 + len2 + 1)
		dig := DIGITS
		if val1 < 0x10 {
			charsStr.WriteByte(dig[value1])
		} else {
			shift := uint(12)
			for {
				index := (value1 >> shift) & 15
				if index != 0 { // index 0 is digit "0"
					charsStr.WriteByte(dig[index])
					shift -= 4
					for shift > 0 {
						charsStr.WriteByte(dig[(value1>>shift)&15])
						shift -= 4
					}
					break
				}
				shift -= 4
				if shift == 0 {
					break
				}
			}
		}
		charsStr.WriteByte(RangeSeparator)
		value2 = uint(val2)
		if val2 < 0x10 {
			charsStr.WriteByte(dig[value2])
		} else {
			shift := uint(12)
			for {
				index := (value2 >> shift) & 15
				if index != 0 { // index 0 is digit "0"
					charsStr.WriteByte(dig[index])
					shift -= 4
					for shift > 0 {
						charsStr.WriteByte(dig[(value2>>shift)&15])
						shift -= 4
					}
					break
				}
				shift -= 4
				if shift == 0 {
					break
				}
			}
		}
		return charsStr.String()
	}
	return buildDefaultRangeString(strProvider, radix)
}

func buildDefaultRangeString(strProvider divStringProvider, radix int) string {
	builder := strings.Builder{}
	builder.Grow(20)
	getRangeString(strProvider, RangeSeparatorStr, 0, 0, "", radix, false, false, &builder)
	return builder.String()
}

func getRangeString(
	strProvider divStringProvider,
	rangeSeparator string,
	lowerLeadingZerosCount,
	upperLeadingZerosCount int,
	stringPrefix string,
	radix int,
	uppercase,
	maskUpper bool,
	appendable *strings.Builder) int {

	prefLen := len(stringPrefix)
	hasStringPrefix := prefLen > 0
	if appendable == nil {
		count := lowerLeadingZerosCount + upperLeadingZerosCount +
			strProvider.getLowerStringLength(radix) + strProvider.getUpperStringLength(radix) + len(rangeSeparator)
		if hasStringPrefix {
			count += prefLen << 1
		}
		return count
	} else {
		if hasStringPrefix {
			appendable.WriteString(stringPrefix)
		}
		if lowerLeadingZerosCount > 0 {
			getLeadingZeros(lowerLeadingZerosCount, appendable)
		}
		strProvider.getLowerString(radix, uppercase, appendable)
		appendable.WriteString(rangeSeparator)
		if hasStringPrefix {
			appendable.WriteString(stringPrefix)
		}
		if upperLeadingZerosCount > 0 {
			getLeadingZeros(upperLeadingZerosCount, appendable)
		}
		if maskUpper {
			strProvider.getUpperStringMasked(radix, uppercase, appendable)
		} else {
			strProvider.getUpperString(radix, uppercase, appendable)
		}
	}
	return 0
}

func getDigits(uppercase bool, radix int) string {
	if uppercase || radix > 36 {
		return UPPERCASE_DIGITS
	}
	return DIGITS
}

func toSplitUnsignedString(
	value uint64,
	radix,
	choppedDigits int,
	uppercase bool,
	splitDigitSeparator byte,
	reverseSplitDigits bool,
	stringPrefix string,
	appendable *strings.Builder) {

	if reverseSplitDigits {
		appendDigits(value, radix, choppedDigits, uppercase, splitDigitSeparator, stringPrefix, appendable)
	} else {
		// for ::1 this produces
		// 1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa
		// each seg is 4 digits like 1.0.0.0 for the last seg
		var tmpBuilder strings.Builder
		appendDigits(value, radix, choppedDigits, uppercase, splitDigitSeparator, stringPrefix, &tmpBuilder)
		stringPrefixLen := len(stringPrefix)
		str := tmpBuilder.String()
		back := tmpBuilder.Len() - 1
		for {
			appendable.WriteString(stringPrefix)
			appendable.WriteByte(str[back])
			back -= stringPrefixLen // skip the prefix, if any
			back -= 2               // 1 for the separator, 1 for the byte
			if back < 0 {
				break
			}
			appendable.WriteByte(splitDigitSeparator)
		}
	}
}

func toUnsignedSplitRangeString(
	lower,
	upper uint64,
	rangeSeparator,
	wildcard string,
	radix int,
	uppercase bool,
	splitDigitSeparator byte,
	reverseSplitDigits bool,
	stringPrefix string,
	appendable *strings.Builder) (err IncompatibleAddressException) {
	//A split can be invalid.  Consider xxx.456-789.
	//The number 691, which is in the range 456-789, is not in the range 4-7.5-8.6-9
	//In such cases we throw IncompatibleAddressException
	//To avoid such cases, we must have lower digits covering the full range, for example 400-799 in which lower digits are both 0-9 ranges.
	//If we have 401-799 then 500 will not be included when splitting.
	//If we have 400-798 then 599 will not be included when splitting.
	//If we have 410-799 then 500 will not be included when splitting.
	//If we have 400-789 then 599 will not be included when splitting.
	if reverseSplitDigits {
		err = appendRangeDigits(lower, upper, rangeSeparator, wildcard, radix, uppercase, splitDigitSeparator, reverseSplitDigits, stringPrefix, appendable)
	} else {
		var tmpBuilder strings.Builder
		err = appendRangeDigits(lower, upper, rangeSeparator, wildcard, radix, uppercase, splitDigitSeparator, reverseSplitDigits, stringPrefix, &tmpBuilder)
		if err == nil {
			str := tmpBuilder.String()
			for back := tmpBuilder.Len() - 1; back >= 0; back-- {
				appendable.WriteByte(str[back])
			}
		}
	}
	return
}

func toUnsignedSplitRangeStringLength(
	lower,
	upper uint64,
	rangeSeparator,
	wildcard string,
	leadingZerosCount,
	radix int,
	uppercase bool,
	splitDigitSeparator byte,
	reverseSplitDigits bool,
	stringPrefix string) int {

	digitsLength := -1 //we will count one too many split digit separators in here
	stringPrefixLength := len(stringPrefix)
	radix64 := uint64(radix)
	for {
		upperDigit := int(upper % radix64)
		lowerDigit := int(lower % radix64)
		isFull := (lowerDigit == 0) && (upperDigit == radix-1)
		if isFull {
			digitsLength += len(wildcard) + 1
		} else {
			//if not full range, they must not be the same either, otherwise they would be illegal for split range.
			//this is because we know whenever entering the loop that upper != lower, and we know this also means the least significant digits must differ.
			digitsLength += (stringPrefixLength << 1) + 4 /* 1 for each digit, 1 for range separator, 1 for split digit separator */
		}
		upper /= radix64
		lower /= radix64
		if upper == lower {
			break
		}
	}
	remaining := 0
	if upper != 0 {
		remaining = toUnsignedStringLength(upper, radix)
	}
	remaining += leadingZerosCount
	if remaining > 0 {
		digitsLength += remaining * (stringPrefixLength + 2 /* one for each splitDigitSeparator, 1 for each digit */)
	}
	return digitsLength
}

func appendDigits(
	value uint64,
	radix int,
	choppedDigits int,
	uppercase bool,
	splitDigitSeparator byte,
	stringPrefix string,
	appendable *strings.Builder) {

	useInts := value <= uint64(maxUint)
	var value2 uint = uint(radix)
	if useInts {
		value2 = uint(value)
	}
	uradix := uint(radix)
	rad64 := uint64(radix)
	dig := DIGITS
	if uppercase {
		dig = UPPERCASE_DIGITS
	}
	var index uint
	prefLen := len(stringPrefix)
	for value2 >= uradix {
		if useInts {
			val := value2
			value2 /= uradix
			if choppedDigits > 0 {
				choppedDigits--
				continue
			}
			index = val % uradix
		} else {
			val := value
			value /= rad64
			if value <= uint64(maxUint) {
				useInts = true
				value2 = uint(value)
			}
			if choppedDigits > 0 {
				choppedDigits--
				continue
			}
			index = uint(val % rad64)
		}
		if prefLen > 0 {
			appendable.WriteString(stringPrefix)
		}
		appendable.WriteByte(dig[index])
		appendable.WriteByte(splitDigitSeparator)
	}
	if choppedDigits == 0 {
		if prefLen > 0 {
			appendable.WriteString(stringPrefix)
		}
		appendable.WriteByte(dig[value2])
	}
}

func appendRangeDigits(
	lower,
	upper uint64,
	rangeSeparator,
	wildcard string,
	radix int,
	uppercase bool,
	splitDigitSeparator byte,
	reverseSplitDigits bool,
	stringPrefix string,
	appendable *strings.Builder) IncompatibleAddressException {

	dig := DIGITS
	if uppercase {
		dig = UPPERCASE_DIGITS
	}
	previousWasFullRange := true
	useInts := upper <= uint64(maxUint)
	var lowerInt uint = uint(radix)
	upperInt := lowerInt
	if useInts {
		upperInt = uint(upper)
		lowerInt = uint(lower)
	}
	uradix := uint(radix)
	rad64 := uint64(radix)
	prefLen := len(stringPrefix)
	for {
		var upperDigit, lowerDigit uint
		if useInts {
			ud := upperInt
			upperDigit = upperInt % uradix
			upperInt /= uradix
			if ud == lowerInt {
				lowerInt = upperInt
				lowerDigit = upperDigit
			} else {
				lowerDigit = lowerInt % uradix
				lowerInt /= uradix
			}
		} else {
			ud := upper
			upperDigit = uint(upper % rad64)
			upper /= rad64
			if ud == lower {
				lower = upper
				lowerDigit = upperDigit
			} else {
				lowerDigit = uint(lower % rad64)
				lower /= rad64
			}
			if upper <= uint64(maxUint) {
				useInts = true
				upperInt = uint(upper)
				lowerInt = uint(lower)
			}
		}
		if lowerDigit == upperDigit {
			previousWasFullRange = false
			if reverseSplitDigits {
				if prefLen > 0 {
					appendable.WriteString(stringPrefix)
				}
				appendable.WriteByte(dig[lowerDigit])
			} else {
				//in this case, whatever we do here will be completely reversed following this method call
				appendable.WriteByte(dig[lowerDigit])
				for k := prefLen - 1; k >= 0; k-- {
					appendable.WriteByte(stringPrefix[k])
				}
			}
		} else {
			if !previousWasFullRange {
				return &incompatibleAddressException{str: fmt.Sprintf("%d-%d", lower, upper), key: "ipaddress.error.splitMismatch"}
			}
			previousWasFullRange = (lowerDigit == 0) && (upperDigit == uradix-1)
			if previousWasFullRange && len(wildcard) > 0 {
				if reverseSplitDigits {
					appendable.WriteString(wildcard)
				} else {
					//in this case, whatever we do here will be completely reversed following this method call
					for k := len(wildcard) - 1; k >= 0; k-- {
						appendable.WriteByte(wildcard[k])
					}
				}
			} else {
				if reverseSplitDigits {
					if prefLen > 0 {
						appendable.WriteString(stringPrefix)
					}
					appendable.WriteByte(dig[lowerDigit])
					appendable.WriteString(rangeSeparator)
					appendable.WriteByte(dig[upperDigit])
				} else {
					//in this case, whatever we do here will be completely reversed following this method call
					appendable.WriteByte(dig[upperDigit])
					appendable.WriteString(rangeSeparator)
					appendable.WriteByte(dig[lowerDigit])
					for k := prefLen - 1; k >= 0; k-- {
						appendable.WriteByte(stringPrefix[k])
					}
				}
			}
		}
		if upperInt == 0 {
			break
		}
		appendable.WriteByte(splitDigitSeparator)
	}
	return nil
}

var maxDigitMap = createMap()

func createMap() *map[uint64]int {
	res := make(map[uint64]int)
	return &res
}

func getMaxDigitCount(radix int, bitCount BitCount, maxValue uint64) int {
	rad64 := uint64(radix)
	key := (rad64 << 32) | uint64(bitCount)
	theMap := *maxDigitMap
	if digs, ok := theMap[key]; ok {
		return digs
	}
	digs := getDigitCount(maxValue, radix)
	newMaxDigitMap := make(map[uint64]int)
	for k, val := range theMap {
		newMaxDigitMap[k] = val
	}
	newMaxDigitMap[key] = digs
	dataLoc := (*unsafe.Pointer)(unsafe.Pointer(&maxDigitMap))
	atomic.StorePointer(dataLoc, unsafe.Pointer(&newMaxDigitMap))
	return digs
}

func getDigitCount(value uint64, radix int) int {
	result := 1
	if radix == 16 {
		for {
			value >>= 4
			if value == 0 {
				break
			}
			result++
		}
	} else {
		if radix == 10 {
			if value < 10 {
				return 1
			} else if value < 100 {
				return 2
			} else if value < 1000 {
				return 3
			}
			value /= 1000
			result = 3 //we start with 3 in the loop below
		} else if radix == 8 {
			for {
				value >>= 3
				if value == 0 {
					break
				}
				result++
			}
			return result
		}
		rad64 := uint64(radix)
		for {
			value /= rad64
			if value == 0 {
				break
			}
			result++
		}
	}
	return result
}
