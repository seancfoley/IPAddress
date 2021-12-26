package ipaddr

import "math/big"

// BigDivInt is an unsigned integer type for unlimited size division values.
type BigDivInt = big.Int

//TODO LATER reinstate LargeDivisionValues
//// LargeDivisionValues represents divisions with unlimited length
//type LargeDivisionValues interface {
//	divisionValuesBase
//
//	GetValue() *BigDivInt
//
//	GetUpperValue() *BigDivInt
//}
//
//// IPAddressDivisionValues represents divisions with unlimited length and a stored prefix length
//type IPAddressLargeDivisionValues interface {
//	LargeDivisionValues
//
//	GetDivisionPrefixLength() *PrefixLen
//}
