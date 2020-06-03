package ipaddrold

import (
	//"fmt"
	"math/big"
	"reflect"
)

/*
then call:
Use
https://golang.org/pkg/go/parser/#ParseDir
like in this example:
https://golang.org/pkg/go/ast/#example_Print
and then call
https://golang.org/pkg/go/doc/#New
*/

//TODO I guess json is the equivalent of serialization for go

//TODO godoc cheat sheet
//https://godoc.org/github.com/fluhus/godoc-tricks#Links

// SegInt is an unsigned integer type for holding generic segment values, which are unsigned byte for MAC or IPv4 and two unsigned bytes for IPv6.
type SegInt = uint16

// DivInt is an unsigned integer type for division values, aliased to the largest unsigned primitive type to allow for the largest possible division values.
type DivInt = uint64

// BigDivInt is an unsigned integer type for unlimited size division values.
type BigDivInt = big.Int

type largeDivisionValues interface {
	GetValue() *BigDivInt

	GetUpperValue() *BigDivInt
}

type divisionValues interface {
	largeDivisionValues

	// GetDivisionValue gets the lower value for the division
	GetDivisionValue() DivInt

	GetUpperDivisionValue() DivInt

	GetBitCount() int

	GetByteCount() int

	getDivisionPrefixLength() *PrefixLen
}

type addressDivisionValues struct {
	divisionValue, upperDivisionValue DivInt
	bitCount                          int
}

func (d *addressDivisionValues) GetDivisionValue() DivInt {
	return d.divisionValue
}

func (d *addressDivisionValues) GetUpperDivisionValue() DivInt {
	return d.upperDivisionValue
}

func (d *addressDivisionValues) GetValue() *BigDivInt {
	result := &BigDivInt{}
	return result.SetUint64(d.divisionValue)
}

func (d *addressDivisionValues) GetUpperValue() *BigDivInt {
	result := &BigDivInt{}
	return result.SetUint64(d.upperDivisionValue)
}

func (d *addressDivisionValues) GetBitCount() int {
	return d.bitCount
}

func (d *addressDivisionValues) GetByteCount() int {
	return (d.bitCount + 7) >> 3
}

func (d *addressDivisionValues) getDivisionPrefixLength() *PrefixLen {
	return nil
}

// Keeping the internal structs like addressDivisionInternal allow us to prevent users from mixing and matching their own public structs inside others,
// while at the same time inheriting methods from embedded types.
// Using non-ponters allows simple construction, so users can do this: IPAddressSegment{} and call any embedded methods on that instance as is,
// although in such cases you always have the zero value for that type.
// Users are expected to use ToIPv4(), ToIPv6(), ToIPSegment(), ToIPDivision(), and ToDivision() for conversion.

type addressDivisionInternal struct {
	// lower, upper, prefix
	divisionValues //one of ipv6SegmentValues, ipv4SegmentValues, addressDivisionValues (default), ipaddressDivisionValues (default with prefix)

	// cached for performance reasons - especially valuable since segments can be shared amongst different addresses as we do with the masks
	cachedWildcardString, cachedPrefixedString string

	// cached segment bytes
	lowerBytes, upperBytes []byte
}

func (d *addressDivisionInternal) getDivisionValue() DivInt {
	if d.divisionValues == nil {
		return DivInt(0)
	}
	return d.divisionValues.GetDivisionValue()
}

func (d *addressDivisionInternal) getUpperDivisionValue() DivInt {
	if d.divisionValues == nil {
		return DivInt(0)
	}
	return d.divisionValues.GetUpperDivisionValue()
}

func (d *addressDivisionInternal) GetValue() *BigDivInt {
	if d.divisionValues == nil {
		return &BigDivInt{}
	}
	return d.divisionValues.GetValue()
}

func (d *addressDivisionInternal) GetUpperValue() *BigDivInt {
	if d.divisionValues == nil {
		return &BigDivInt{}
	}
	return d.divisionValues.GetUpperValue()
}

// We assign default values whenever we return data about the values, so that we can remain consistent (ie we must never convert to some other type of address afterwards)
// We also assign default values so that we know to what values we can upcast, which is dependent on the values as well as the IP version returned by the values
func (d *addressDivisionInternal) assignDefaultValues() {
	if d.divisionValues == nil {
		byteType := reflect.TypeOf((*byte)(nil)).Elem()
		d.divisionValues = &addressDivisionValues{bitCount: int(byteType.Size())}
	}
}

func (d *addressDivisionInternal) GetBitCount() int {
	d.assignDefaultValues()
	return d.divisionValues.GetBitCount()
}

func (d *addressDivisionInternal) GetByteCount() int {
	d.assignDefaultValues()
	return d.divisionValues.GetByteCount()
}

// We must know what a division started as, in order to know if we can convert to that type again.
// This ensures that type bit counts and other identifying factors from divisionValues interface remain consistent.
// The one exception is that we always allow upcasting from AddressDivision to IPAddressDivision.
// So we must check divisionValues before upcasting.
// First we must ensure that divisionValues has been assigned, and assign it if not.

// ToIPDivision() converts this division to an IP division
func (d *addressDivisionInternal) toIPDivision() *IPAddressDivision {
	d.assignDefaultValues()
	switch d.divisionValues.(type) {
	//note that we always allow AddressDivision upcast to IPAddressDivision (with no prefix length)
	case *addressDivisionValues, *ipAddressDivisionValues, *ipv4SegmentValues, *ipv6SegmentValues:
		return &IPAddressDivision{ipAddressDivisionInternal{addressDivisionInternal: *d}}
	default:
		return nil
	}
}

// ToIPSegment() converts this division to an IP segment if it originated as an IPv4 segment, otherwise it returns nil
func (d *addressDivisionInternal) toIPSegment() *IPAddressSegment {
	d.assignDefaultValues()
	switch d.divisionValues.(type) {
	case *ipv4SegmentValues, *ipv6SegmentValues:
		return &IPAddressSegment{ipAddressSegmentInternal{ipAddressDivisionInternal{addressDivisionInternal: *d}}}
	default:
		return nil
	}
}

type AddressDivision struct {
	addressDivisionInternal
}

// GetDivisionValue gets the lower value for the division
func (d *AddressDivision) GetDivisionValue() DivInt {
	return d.getDivisionValue()
}

// GetUpperDivisionValue gets the upper value for the division
func (d *AddressDivision) GetUpperDivisionValue() DivInt {
	return d.getUpperDivisionValue()
}

// ToIPv4() converts this division to an IPv4 segment if it originated as an IPv4 segment, otherwise it returns nil
func (d *AddressDivision) ToIPv4() *IPv4AddressSegment {
	d.assignDefaultValues()
	if _, ok := d.divisionValues.(*ipv4SegmentValues); ok {
		return &IPv4AddressSegment{ipAddressSegmentInternal{ipAddressDivisionInternal{addressDivisionInternal: d.addressDivisionInternal}}}
	}
	return nil
}

// ToIPv6() converts this division to an IPv6 segment if it originated as an IPv6 segment, otherwise it returns nil
func (d *AddressDivision) ToIPv6() *IPv6AddressSegment {
	d.assignDefaultValues()
	if _, ok := d.divisionValues.(*ipv6SegmentValues); ok {
		return &IPv6AddressSegment{ipAddressSegmentInternal{ipAddressDivisionInternal{addressDivisionInternal: d.addressDivisionInternal}}}
	}
	return nil
}

//func (d *AddressDivision) ToDivision() *AddressDivision {
//	return d
//}

func (d *AddressDivision) ToIPDivision() *IPAddressDivision {
	return d.toIPDivision()
}

// ToIPSegment() converts this division to an IP segment if it originated as an IPv4 segment, otherwise it returns nil
func (d *AddressDivision) ToIPSegment() *IPAddressSegment {
	return d.toIPSegment()
}
