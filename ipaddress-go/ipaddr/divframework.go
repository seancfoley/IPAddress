//
// Copyright 2020-2021 Sean C Foley
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package ipaddr

// DivisionType serves as a common interface to all divisions
type DivisionType interface {
	AddressItem

	getAddrType() addrType

	// getStringAsLower caches the string from getDefaultLowerString
	getStringAsLower() string

	// GetString produces a string that avoids wildcards when a prefix length is part of the string.  Equivalent to GetWildcardString when the prefix length is not part of the string.
	GetString() string

	// GetWildcardString produces a string that uses wildcards and avoids prefix length
	GetWildcardString() string

	// Determines if the division has a single prefix for the given prefix length.  You can call GetPrefixCountLen to get the count of prefixes.
	IsSinglePrefix(BitCount) bool

	// methods for string generation used by the string params and string writer
	divStringProvider
}

// Represents any standard address division, which is a division of size 64 bits or less.  All can be converted to/from AddressDivision
type StandardDivisionType interface {
	DivisionType

	ToDiv() *AddressDivision
}

var _ StandardDivisionType = &AddressDivision{}

// AddressSegment serves as a common interface to all segments
type AddressSegmentType interface {
	AddressComponent

	StandardDivisionType

	Equal(AddressSegmentType) bool
	Contains(AddressSegmentType) bool

	// GetSegmentValue returns the lower segment value as a SegInt, the same value as the DivInt value returned by getDivisionValue()
	GetSegmentValue() SegInt

	// GetUpperSegmentValue returns the upper segment value as a SegInt, the same value as the DivInt value returned by getUpperDivisionValue()
	GetUpperSegmentValue() SegInt

	ToSegmentBase() *AddressSegment
}

var _, _, _, _, _ AddressSegmentType = &AddressSegment{},
	&IPAddressSegment{},
	&IPv6AddressSegment{},
	&IPv4AddressSegment{},
	&MACAddressSegment{}
