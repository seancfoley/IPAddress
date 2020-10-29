package ipaddr

const (
	UPPER_ADJUSTMENT int = 8

	// these are for the flags
	// a standard string is a string showing only the lower value of a segment.
	// A standard range string shows both values, low to high, with the standard separator.
	KEY_WILDCARD                uint32 = 0x10000
	KEY_SINGLE_WILDCARD         uint32 = 0x20000
	KEY_STANDARD_STR            uint32 = 0x40000
	KEY_STANDARD_RANGE_STR      uint32 = 0x80000
	KEY_RANGE_WILDCARD          uint32 = 0x100000
	KEY_INFERRED_LOWER_BOUNDARY uint32 = 0x200000
	KEY_INFERRED_UPPER_BOUNDARY uint32 = 0x400000
	KEY_MERGED_MIXED            uint32 = 0x800000
	KEY_RADIX                   uint32 = 0x00ff
	KEY_BIT_SIZE                uint32 = 0xff00
	BIT_SIZE_SHIFT                     = 8

	// the flags, radix and bit size are stored in the same int, the radix takes the low byte,
	// the bit size the next byte, the remaining 16 bits are available for flags.
	KEY_LOWER_RADIX_INDEX int = 0
	KEY_BIT_SIZE_INDEX    int = KEY_LOWER_RADIX_INDEX
	FLAGS_INDEX           int = KEY_LOWER_RADIX_INDEX
	KEY_UPPER_RADIX_INDEX int = KEY_LOWER_RADIX_INDEX + UPPER_ADJUSTMENT

	// these are for the segment values - they must be even-numbered
	KEY_LOWER          int = 2
	KEY_EXTENDED_LOWER int = 4
	KEY_UPPER          int = KEY_LOWER + UPPER_ADJUSTMENT
	KEY_EXTENDED_UPPER int = KEY_EXTENDED_LOWER + UPPER_ADJUSTMENT

	// these are for the indices
	KEY_LOWER_STR_DIGITS_INDEX int = 1
	KEY_LOWER_STR_START_INDEX  int = 6
	KEY_LOWER_STR_END_INDEX    int = 7
	KEY_UPPER_STR_DIGITS_INDEX int = KEY_LOWER_STR_DIGITS_INDEX + UPPER_ADJUSTMENT
	KEY_UPPER_STR_START_INDEX  int = KEY_LOWER_STR_START_INDEX + UPPER_ADJUSTMENT
	KEY_UPPER_STR_END_INDEX    int = KEY_LOWER_STR_END_INDEX + UPPER_ADJUSTMENT
	SEGMENT_DATA_SIZE          int = 16
	SEGMENT_INDEX_SHIFT        int = 4
	IPV4_SEGMENT_DATA_SIZE     int = SEGMENT_DATA_SIZE * 4
	IPV6_SEGMENT_DATA_SIZE     int = SEGMENT_DATA_SIZE * 8
)

type AddressParseData struct {
	segmentData  []uint32
	segmentCount int

	anyWildcard, isEmpty, isAllVal, isSingleSegmentVal bool

	// these are indices into the original string used while parsing
	consecutiveSepIndex, consecutiveSepSegmentIndex, addressEndIndex int

	str string
}

func (parseData *AddressParseData) init(str string) {
	parseData.consecutiveSepIndex = -1
	parseData.consecutiveSepSegmentIndex = -1
	parseData.str = str
}

func (parseData *AddressParseData) getString() string {
	return parseData.str
}

func (parseData *AddressParseData) initSegmentData(segmentCapacity int) {
	dataSize := 0
	if segmentCapacity == 4 {
		dataSize = IPV4_SEGMENT_DATA_SIZE
	} else if segmentCapacity == 8 {
		dataSize = IPV6_SEGMENT_DATA_SIZE
	} else if segmentCapacity == 1 {
		dataSize = SEGMENT_DATA_SIZE // SEGMENT_DATA_SIZE * segmentCapacity
	} else {
		dataSize = segmentCapacity * SEGMENT_DATA_SIZE
	}
	parseData.segmentData = make([]uint32, dataSize)
}

func (parseData *AddressParseData) releaseSegmentData() {
	parseData.segmentData = nil
}

func (parseData *AddressParseData) getSegmentData() []uint32 {
	return parseData.segmentData
}

func (parseData *AddressParseData) incrementSegmentCount() {
	parseData.segmentCount++
}

func (parseData *AddressParseData) getSegmentCount() int {
	return parseData.segmentCount
}

func (parseData *AddressParseData) getConsecutiveSeparatorSegmentIndex() int {
	return parseData.consecutiveSepSegmentIndex
}

func (parseData *AddressParseData) setConsecutiveSeparatorSegmentIndex(val int) {
	parseData.consecutiveSepSegmentIndex = val
}

func (parseData *AddressParseData) getConsecutiveSeparatorIndex() int {
	return parseData.consecutiveSepIndex
}

func (parseData *AddressParseData) setConsecutiveSeparatorIndex(val int) {
	parseData.consecutiveSepIndex = val
}

func (parseData *AddressParseData) isProvidingEmpty() bool {
	return parseData.isEmpty
}

func (parseData *AddressParseData) setEmpty(val bool) {
	parseData.isEmpty = val
}

func (parseData *AddressParseData) isAll() bool {
	return parseData.isAllVal
}

func (parseData *AddressParseData) setAll() {
	parseData.isAllVal = true
}

func (parseData *AddressParseData) getAddressEndIndex() int {
	return parseData.addressEndIndex
}

func (parseData *AddressParseData) setAddressEndIndex(val int) {
	parseData.addressEndIndex = val
}

func (parseData *AddressParseData) isSingleSegment() bool {
	return parseData.isSingleSegmentVal
}

func (parseData *AddressParseData) setSingleSegment() {
	parseData.isSingleSegmentVal = true
}

func (parseData *AddressParseData) hasWildcard() bool {
	return parseData.anyWildcard
}

func (parseData *AddressParseData) setHasWildcard() {
	parseData.anyWildcard = true
}

func (parseData *AddressParseData) unsetFlag(segmentIndex int, flagIndicator uint32) {
	index := (segmentIndex << SEGMENT_INDEX_SHIFT) | FLAGS_INDEX
	segmentData := parseData.getSegmentData()
	segmentData[index] &= uint32(0xffff) ^ flagIndicator // segmentData[index] &= ~flagIndicator
}

func (parseData *AddressParseData) getFlag(segmentIndex int, flagIndicator uint32) bool {
	segmentData := parseData.getSegmentData()
	return (segmentData[(segmentIndex<<SEGMENT_INDEX_SHIFT)|FLAGS_INDEX] & flagIndicator) != 0
}

func (parseData *AddressParseData) hasEitherFlag(segmentIndex int, flagIndicator1, flagIndicator2 uint32) bool {
	return parseData.getFlag(segmentIndex, flagIndicator1|flagIndicator2)
}

func (parseData *AddressParseData) getRadix(segmentIndex, indexIndicator int) uint32 {
	segmentData := parseData.getSegmentData()
	radix := segmentData[(segmentIndex<<SEGMENT_INDEX_SHIFT)|indexIndicator] & KEY_RADIX
	if radix == 0 {
		return IPv6DefaultTextualRadix // 16 is the default, we only set the radix if not 16
	}
	return radix
}

func (parseData *AddressParseData) getBitLength(segmentIndex int) uint16 {
	segmentData := parseData.getSegmentData()
	bitLength := (segmentData[(segmentIndex<<SEGMENT_INDEX_SHIFT)|KEY_BIT_SIZE_INDEX] & KEY_BIT_SIZE) >> BIT_SIZE_SHIFT
	return uint16(bitLength)
}

func (parseData *AddressParseData) setBitLength(segmentIndex int, length uint16) {
	segmentData := parseData.getSegmentData()
	segmentData[(segmentIndex<<SEGMENT_INDEX_SHIFT)|KEY_BIT_SIZE_INDEX] |= ((uint32(length) << BIT_SIZE_SHIFT) & KEY_BIT_SIZE)
}

func (parseData *AddressParseData) setIndex(segmentIndex,
	indexIndicator0 int, value0 uint32,
	indexIndicator1 int, value1 uint32,
	indexIndicator2 int, value2 uint32,
	indexIndicator3 int, value3 uint32,
	indexIndicator4 int, value4 uint32,
	indexIndicator5 int, value5 uint32) {
	baseIndex := segmentIndex << SEGMENT_INDEX_SHIFT
	segmentData := parseData.getSegmentData()
	segmentData[baseIndex|indexIndicator0] = value0
	segmentData[baseIndex|indexIndicator1] = value1
	segmentData[baseIndex|indexIndicator2] = value2
	segmentData[baseIndex|indexIndicator3] = value3
	segmentData[baseIndex|indexIndicator4] = value4
	segmentData[baseIndex|indexIndicator5] = value5
}

func (parseData *AddressParseData) getIndex(segmentIndex, indexIndicator int) int {
	return getIndexFromData(segmentIndex, indexIndicator, parseData.getSegmentData())
}

func getIndexFromData(segmentIndex, indexIndicator int, segmentData []uint32) int {
	return int(segmentData[(segmentIndex<<SEGMENT_INDEX_SHIFT)|indexIndicator])
}

func (parseData *AddressParseData) set7IndexFlags(segmentIndex,
	indexIndicator0 int, value0 uint32,
	indexIndicator1 int, value1 uint32,
	indexIndicator2 int, value2 uint32,
	indexIndicator3 int, value3 uint32,
	indexIndicator4 int, value4 uint32,
	indexIndicator5 int, value5 uint32,
	indexIndicator6 int, value6 uint32) {
	baseIndex := segmentIndex << SEGMENT_INDEX_SHIFT
	segmentData := parseData.getSegmentData()
	segmentData[baseIndex|indexIndicator0] = value0
	segmentData[baseIndex|indexIndicator1] = value1
	segmentData[baseIndex|indexIndicator2] = value2
	segmentData[baseIndex|indexIndicator3] = value3
	segmentData[baseIndex|indexIndicator4] = value4
	segmentData[baseIndex|indexIndicator5] = value5
	segmentData[baseIndex|indexIndicator6] = value6
}

func (parseData *AddressParseData) set8IndexFlags(segmentIndex,
	indexIndicator0 int, value0 uint32,
	indexIndicator1 int, value1 uint32,
	indexIndicator2 int, value2 uint32,
	indexIndicator3 int, value3 uint32,
	indexIndicator4 int, value4 uint32,
	indexIndicator5 int, value5 uint32,
	indexIndicator6 int, value6 uint32,
	indexIndicator7 int, value7 uint32) {
	baseIndex := segmentIndex << SEGMENT_INDEX_SHIFT
	segmentData := parseData.getSegmentData()
	segmentData[baseIndex|indexIndicator0] = value0
	segmentData[baseIndex|indexIndicator1] = value1
	segmentData[baseIndex|indexIndicator2] = value2
	segmentData[baseIndex|indexIndicator3] = value3
	segmentData[baseIndex|indexIndicator4] = value4
	segmentData[baseIndex|indexIndicator5] = value5
	segmentData[baseIndex|indexIndicator6] = value6
	segmentData[baseIndex|indexIndicator7] = value7
}

func (parseData *AddressParseData) set8Index4ValuesFlags(segmentIndex,
	indexIndicator0 int, value0 uint32,
	indexIndicator1 int, value1 uint32,
	indexIndicator2 int, value2 uint32,
	indexIndicator3 int, value3 uint32,
	indexIndicator4 int, value4 uint32,
	indexIndicator5 int, value5 uint32,
	indexIndicator6 int, value6 uint32,
	indexIndicator7 int, value7 uint32,
	indexIndicator8 int, value8 uint64,
	indexIndicator9 int, value9 uint64,
	indexIndicator10 int, value10 uint64,
	indexIndicator11 int, value11 uint64) {
	baseIndex := segmentIndex << SEGMENT_INDEX_SHIFT
	segmentData := parseData.getSegmentData()
	setIndexValuesFlags(baseIndex, segmentData,
		indexIndicator0, value0,
		indexIndicator1, value1,
		indexIndicator2, value2,
		indexIndicator3, value3,
		indexIndicator4, value4,
		indexIndicator5, value5,
		indexIndicator6, value6,
		indexIndicator8, value8,
		indexIndicator9, value9)
	segmentData[baseIndex|indexIndicator7] = value7

	index := baseIndex | indexIndicator10
	segmentData[index] = uint32(value10 >> 32)
	segmentData[index|1] = uint32(value10 & 0xffffffff)

	index = baseIndex | indexIndicator11
	segmentData[index] = uint32(value11 >> 32)
	segmentData[index|1] = uint32(value11 & 0xffffffff)
}

func (parseData *AddressParseData) set7Index4ValuesFlags(segmentIndex,
	indexIndicator0 int, value0 uint32,
	indexIndicator1 int, value1 uint32,
	indexIndicator2 int, value2 uint32,
	indexIndicator3 int, value3 uint32,
	indexIndicator4 int, value4 uint32,
	indexIndicator5 int, value5 uint32,
	indexIndicator6 int, value6 uint32,
	indexIndicator7 int, value7 uint64,
	indexIndicator8 int, value8 uint64,
	indexIndicator9 int, value9 uint64,
	indexIndicator10 int, value10 uint64) {
	baseIndex := segmentIndex << SEGMENT_INDEX_SHIFT
	segmentData := parseData.getSegmentData()
	setIndexValuesFlags(baseIndex, segmentData,
		indexIndicator0, value0,
		indexIndicator1, value1,
		indexIndicator2, value2,
		indexIndicator3, value3,
		indexIndicator4, value4,
		indexIndicator5, value5,
		indexIndicator6, value6,
		indexIndicator7, value7,
		indexIndicator8, value8)

	index := baseIndex | indexIndicator9
	segmentData[index] = uint32(value9 >> 32)
	segmentData[index|1] = uint32(value9 & 0xffffffff)

	index = baseIndex | indexIndicator10
	segmentData[index] = uint32(value10 >> 32)
	segmentData[index|1] = uint32(value10 & 0xffffffff)
}

func (parseData *AddressParseData) set8Index2ValuesFlags(segmentIndex,
	indexIndicator0 int, value0 uint32,
	indexIndicator1 int, value1 uint32,
	indexIndicator2 int, value2 uint32,
	indexIndicator3 int, value3 uint32,
	indexIndicator4 int, value4 uint32,
	indexIndicator5 int, value5 uint32,
	indexIndicator6 int, value6 uint32,
	indexIndicator7 int, value7 uint32,
	indexIndicator8 int, value8 uint64,
	indexIndicator9 int, value9 uint64) {
	baseIndex := segmentIndex << SEGMENT_INDEX_SHIFT
	segmentData := parseData.getSegmentData()
	setIndexValuesFlags(baseIndex, segmentData,
		indexIndicator0, value0,
		indexIndicator1, value1,
		indexIndicator2, value2,
		indexIndicator3, value3,
		indexIndicator4, value4,
		indexIndicator5, value5,
		indexIndicator6, value6,
		indexIndicator8, value8,
		indexIndicator9, value9)
	segmentData[baseIndex|indexIndicator7] = value7
}

func (parseData *AddressParseData) set7Index2ValuesFlags(segmentIndex,
	indexIndicator0 int, value0 uint32,
	indexIndicator1 int, value1 uint32,
	indexIndicator2 int, value2 uint32,
	indexIndicator3 int, value3 uint32,
	indexIndicator4 int, value4 uint32,
	indexIndicator5 int, value5 uint32,
	indexIndicator6 int, value6 uint32,
	indexIndicator7 int, value7 uint64,
	indexIndicator8 int, value8 uint64) {
	baseIndex := segmentIndex << SEGMENT_INDEX_SHIFT
	segmentData := parseData.getSegmentData()
	setIndexValuesFlags(baseIndex, segmentData,
		indexIndicator0, value0,
		indexIndicator1, value1,
		indexIndicator2, value2,
		indexIndicator3, value3,
		indexIndicator4, value4,
		indexIndicator5, value5,
		indexIndicator6, value6,
		indexIndicator7, value7,
		indexIndicator8, value8)
}

func setIndexValuesFlags(
	baseIndex int,
	segmentData []uint32,
	indexIndicator0 int, value0 uint32,
	indexIndicator1 int, value1 uint32,
	indexIndicator2 int, value2 uint32,
	indexIndicator3 int, value3 uint32,
	indexIndicator4 int, value4 uint32,
	indexIndicator5 int, value5 uint32,
	indexIndicator6 int, value6 uint32,
	indexIndicator7 int, value7 uint64,
	indexIndicator8 int, value8 uint64) {
	segmentData[baseIndex|indexIndicator0] = value0
	segmentData[baseIndex|indexIndicator1] = value1
	segmentData[baseIndex|indexIndicator2] = value2
	segmentData[baseIndex|indexIndicator3] = value3
	segmentData[baseIndex|indexIndicator4] = value4
	segmentData[baseIndex|indexIndicator5] = value5
	segmentData[baseIndex|indexIndicator6] = value6

	index := baseIndex | indexIndicator7
	segmentData[index] = uint32(value7 >> 32)
	segmentData[index|1] = uint32(value7 & 0xffffffff)

	index = baseIndex | indexIndicator8
	segmentData[index] = uint32(value8 >> 32)
	segmentData[index|1] = uint32(value8 & 0xffffffff)
}

func (parseData *AddressParseData) setValue(segmentIndex,
	indexIndicator int, value uint64) {
	index := (segmentIndex << SEGMENT_INDEX_SHIFT) | indexIndicator
	upperValue := uint32(value >> 32)
	lowerValue := uint32(value & 0xffffffff)
	segmentData := parseData.getSegmentData()
	segmentData[index] = upperValue
	segmentData[index|1] = lowerValue
}

func (parseData *AddressParseData) getValue(segmentIndex, indexIndicator int) uint64 {
	return getValueFromData(segmentIndex, indexIndicator, parseData.getSegmentData())
}

func getValueFromData(segmentIndex, indexIndicator int, segmentData []uint32) uint64 {
	index := (segmentIndex << SEGMENT_INDEX_SHIFT) | indexIndicator
	upperValue := uint64(segmentData[index])
	lowerValue := 0xffffffff & uint64(segmentData[index|1])
	value := (upperValue << 32) | lowerValue
	return value
}

func (parseData *AddressParseData) isMergedMixed(segmentIndex int) bool {
	return parseData.getFlag(segmentIndex, KEY_MERGED_MIXED)
}

func (parseData *AddressParseData) isWildcard(segmentIndex int) bool {
	return parseData.getFlag(segmentIndex, KEY_WILDCARD)
}

func (parseData *AddressParseData) hasRange(segmentIndex int) bool {
	return parseData.hasEitherFlag(segmentIndex, KEY_SINGLE_WILDCARD, KEY_RANGE_WILDCARD)
}

func (parseData *AddressParseData) isInferredUpperBoundary(segmentIndex int) bool {
	return parseData.getFlag(segmentIndex, KEY_INFERRED_UPPER_BOUNDARY)
}

func NewIPAddressParseData(str string) *IPAddressParseData {
	return &IPAddressParseData{AddressParseData: AddressParseData{str: str}}
}

type IPAddressParseData struct {
	AddressParseData

	qualifier ParsedHostIdentifierStringQualifier

	qualifierIndex int

	hasPrefixSeparatorVal, isZonedVal bool

	ipVersion IPVersion

	is_inet_aton_joined_val             bool
	has_inet_aton_value_val             bool // either octal 01 or hex 0x1
	hasIPv4LeadingZerosVal, isBinaryVal bool
	isBase85, isBase85ZonedVal          bool

	mixedParsedAddress *ParsedIPAddress
}

func (parseData *IPAddressParseData) init(str string) {
	parseData.qualifierIndex = -1
	parseData.AddressParseData.init(str)
}

func (parseData *IPAddressParseData) getAddressParseData() *AddressParseData {
	return &parseData.AddressParseData
}

func (parseData *IPAddressParseData) getProviderIPVersion() IPVersion {
	return parseData.ipVersion
}

func (parseData *IPAddressParseData) setVersion(version IPVersion) {
	parseData.ipVersion = version
}

func (parseData *IPAddressParseData) isProvidingIPv6() bool {
	version := parseData.getProviderIPVersion()
	return version.isIPv6()
}

func (parseData *IPAddressParseData) isProvidingIPv4() bool {
	version := parseData.getProviderIPVersion()
	return version.isIPv4()
}

func (parseData *IPAddressParseData) is_inet_aton_joined() bool {
	return parseData.is_inet_aton_joined_val
}

func (parseData *IPAddressParseData) set_inet_aton_joined(val bool) {
	parseData.is_inet_aton_joined_val = val
}

func (parseData *IPAddressParseData) has_inet_aton_value() bool {
	return parseData.has_inet_aton_value_val
}

func (parseData *IPAddressParseData) set_has_inet_aton_value(val bool) {
	parseData.has_inet_aton_value_val = val
}

func (parseData *IPAddressParseData) hasIPv4LeadingZeros() bool {
	return parseData.hasIPv4LeadingZerosVal
}

func (parseData *IPAddressParseData) setHasIPv4LeadingZeros(val bool) {
	parseData.hasIPv4LeadingZerosVal = val
}

func (parseData *IPAddressParseData) hasBinaryDigits() bool {
	return parseData.isBinaryVal
}

func (parseData *IPAddressParseData) setHasBinaryDigits(val bool) {
	parseData.isBinaryVal = val
}

func (parseData *IPAddressParseData) getQualifier() *ParsedHostIdentifierStringQualifier {
	return &parseData.qualifier
}

func (parseData *IPAddressParseData) getQualifierIndex() int {
	return parseData.qualifierIndex
}

//func (parseData *IPAddressParseData) setQualifier(val *ParsedHostIdentifierStringQualifier) {
//	parseData.qualifier = val
//}

func (parseData *IPAddressParseData) clearQualifier() {
	parseData.qualifierIndex = -1
	parseData.isZonedVal = false
	parseData.isBase85ZonedVal = false
	parseData.hasPrefixSeparatorVal = false
	parseData.qualifier = ParsedHostIdentifierStringQualifier{}
}

func (parseData *IPAddressParseData) setQualifierIndex(index int) {
	parseData.qualifierIndex = index
}

func (parseData *IPAddressParseData) isZoned() bool {
	return parseData.isZonedVal
}

func (parseData *IPAddressParseData) setZoned(val bool) {
	parseData.isZonedVal = val
}

func (parseData *IPAddressParseData) hasPrefixSeparator() bool {
	return parseData.hasPrefixSeparatorVal
}

func (parseData *IPAddressParseData) setHasPrefixSeparator(val bool) {
	parseData.hasPrefixSeparatorVal = val
}

func (parseData *IPAddressParseData) isProvidingBase85IPv6() bool {
	return parseData.isBase85
}

func (parseData *IPAddressParseData) setBase85(val bool) {
	parseData.isBase85 = val
}

func (parseData *IPAddressParseData) isBase85Zoned() bool {
	return parseData.isBase85ZonedVal
}

func (parseData *IPAddressParseData) setBase85Zoned(val bool) {
	parseData.isBase85ZonedVal = val
}

func (parseData *IPAddressParseData) isCompressed() bool {
	return parseData.AddressParseData.getConsecutiveSeparatorIndex() >= 0
}

func (parseData *IPAddressParseData) segIsCompressed(index int, segmentData []uint32) bool {
	end := getIndexFromData(index, KEY_UPPER_STR_END_INDEX, segmentData)
	start := getIndexFromData(index, KEY_LOWER_STR_START_INDEX, segmentData)
	return start == end
}
func (parseData *IPAddressParseData) segmentIsCompressed(index int) bool {
	return parseData.segIsCompressed(index, parseData.AddressParseData.getSegmentData())
}

func (parseData *IPAddressParseData) isProvidingMixedIPv6() bool {
	return parseData.mixedParsedAddress != nil
}

func (parseData *IPAddressParseData) setMixedParsedAddress(val *ParsedIPAddress) {
	parseData.mixedParsedAddress = val
}

func NewMACAddressParseData(str string) *MACAddressParseData {
	return &MACAddressParseData{AddressParseData: AddressParseData{str: str}}
}

const (
	MACDashSegmentSeparator  = '-'
	MACColonSegmentSeparator = ':'
)

type MACFormat *byte

var (
	dash            byte      = MACDashSegmentSeparator
	colon           byte      = MACColonSegmentSeparator
	space           byte      = ' '
	dot             byte      = '.'
	DASHED          MACFormat = &dash
	COLON_DELIMITED MACFormat = &colon
	DOTTED          MACFormat = &dot
	SPACE_DELIMITED MACFormat = &space
	UNKNOWN_FORMAT  MACFormat
)

type MACAddressParseData struct {
	AddressParseData

	isDoubleSegmentVal, isExtendedVal bool

	format MACFormat
}

func (parseData *MACAddressParseData) init(str string) {
	parseData.AddressParseData.init(str)
}

func (parseData *MACAddressParseData) getAddressParseData() *AddressParseData {
	return &parseData.AddressParseData
}

func (parseData *MACAddressParseData) getFormat() MACFormat {
	return parseData.format
}

func (parseData *MACAddressParseData) setFormat(format MACFormat) {
	parseData.format = format
}

func (parseData *MACAddressParseData) isDoubleSegment() bool {
	return parseData.isExtendedVal
}

func (parseData *MACAddressParseData) setDoubleSegment(val bool) {
	parseData.isExtendedVal = val
}

func (parseData *MACAddressParseData) isExtended() bool {
	return parseData.isDoubleSegmentVal
}

func (parseData *MACAddressParseData) setExtended(val bool) {
	parseData.isDoubleSegmentVal = val
}
