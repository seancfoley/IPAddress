package ipaddr

import (
	"math/big"
	"unsafe"
)

// TODO we must be careful that any methods we grab from Java addressDivisionBase are put in the right place and done the right way.
// Most are string-related and byte-related.
// The byte ones we can probably ignore, we do not (and cannot really) use the same wrapper pattern xxx() calling xxxImpl() as in Java.

// addressDivisionBase is a base for both standard and large divisions.
// Standard divisions are divisions up to 64 bits of length, large are divisions of any length.
// With standard divisions, you can use GetValue/GetUpperValue and use DivInt integers for the values.
// For large divisions, you must use big.Int instances.

type addressDivisionBase struct {
	divisionValues
}

func (div *addressDivisionBase) getDivisionPrefixLength() PrefixLen {
	vals := div.divisionValues
	if vals == nil {
		return nil
	}
	return vals.getDivisionPrefixLength()
}

func (div *addressDivisionBase) GetBitCount() BitCount {
	vals := div.divisionValues
	if vals == nil {
		return 0
	}
	return vals.GetBitCount()
}

func (div *addressDivisionBase) GetByteCount() int {
	vals := div.divisionValues
	if vals == nil {
		return 0
	}
	return vals.GetByteCount()
}

func (div *addressDivisionBase) GetValue() *big.Int {
	vals := div.divisionValues
	if vals == nil {
		return bigZero()
	}
	return vals.getValue()
}

func (div *addressDivisionBase) GetUpperValue() *big.Int {
	vals := div.divisionValues
	if vals == nil {
		return bigZero()
	}
	return vals.getUpperValue()
}

func (div *addressDivisionBase) GetCount() *big.Int {
	if !div.IsMultiple() {
		return bigOne()
	}
	return div.getCount()
}

func (div *addressDivisionBase) IsZero() bool {
	return !div.IsMultiple() && div.includesZero()
}

// Returns whether this item includes the value of zero within its range
func (div *addressDivisionBase) IncludesZero() bool {
	vals := div.divisionValues
	if vals == nil {
		return true
	}
	return vals.includesZero()
}

// Returns whether this item matches the maximum possible value for the address type or version
func (div *addressDivisionBase) IsMax() bool {
	return !div.IsMultiple() && div.includesMax()
}

// Returns whether this item includes the maximum possible value for the address type or version within its range
func (div *addressDivisionBase) IncludesMax() bool {
	vals := div.divisionValues
	if vals == nil {
		return false
	}
	return vals.includesMax()
}

// whether this address item represents all possible values attainable by an address item of this type
func (div *addressDivisionBase) IsFullRange() bool {
	return div.includesZero() && div.includesMax()
}

func (div *addressDivisionBase) IsMultiple() bool {
	vals := div.divisionValues
	if vals == nil {
		return false
	}
	return vals.isMultiple()
}

func (div *addressDivisionBase) toAddressDivision() *AddressDivision {
	return (*AddressDivision)(unsafe.Pointer(div))
}
