package ipaddr

type AddressItem interface {
	//CopyBytes(bytes []byte) []byte
	//CopyUpperBytes(bytes []byte) []byte
	GetByteCount() int
	GetBitCount() BitCount
}

type AddressComponentRange interface {
	AddressItem
}

type AddressComponent interface { //AddressSegment and above, AddressSegmentSeries and above
	AddressComponentRange
}

//
//
// divisions

type AddressStringDivision interface {
}

type IPAddressStringDivision interface {
	AddressStringDivision
}

// serves as "superclass" to all divisions
type AddressGenericDivision interface {
	AddressItem
	AddressStringDivision

	GetDivisionValue() DivInt
	GetUpperDivisionValue() DivInt
}

var _ AddressGenericDivision = &AddressDivision{}

// do not see the need for this, since I am doing away with IPAddressDivision
//type IPAddressGenericDivision interface { // IPAddressDivision, IPAddressLargeDivision
//	AddressGenericDivision
//	IPAddressStringDivision
//}

// euqivalent to AddressSegment on Java side, serves as "superclass" to all segments
type AddressGenericSegment interface {
	AddressItem
	AddressStringDivision

	GetSegmentValue() SegInt

	GetUpperSegmentValue() SegInt
}

var _, _, _, _ AddressGenericSegment = &AddressSegment{},
	&IPv6AddressSegment{},
	&MACAddressSegment{},
	&IPv4AddressSegment{}

//
//
// division series

type AddressStringDivisionSeries interface {
}

type IPAddressStringDivisionSeries interface {
	AddressStringDivisionSeries
}

// serves as "superclass" to all division groupings and addresses
type AddressDivisionSeries interface {
	AddressItem
	AddressStringDivisionSeries

	GetDivision(index int) *AddressDivision
}

type AddressSegmentSeries interface { // Address and above, AddressSection and above, IPAddressSegmentSeries
	AddressComponent
	//AddressDivisionSeries
}

type IPAddressSegmentSeries interface { // IPAddress and above, IPAddressSection and above
	AddressSegmentSeries
}

//
//
//
// addresses and address ranges

type IPAddressRange interface { //IPAddress and above, IPAddressSeqRange and above
	AddressComponentRange
}

//Logically AddressDivisionSeries would be implemened only by AddressDivisionGrouping
//AddressSegmentSeries by AddressSection and Address
//AddressGenericDivision by AddressDivision
//
// Also, in Go, you cannot have the same function appearing in two embedded interfaces, which is lame
// But I guess in the end, since the only thing that matters is the methods themselves, can work around it,
// the embedding is really only a convenience, you could literally list every method in every interface
// Still, it's a PITA
//
