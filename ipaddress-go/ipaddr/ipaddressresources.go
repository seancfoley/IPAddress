package ipaddr

var keyStrMap = map[string]int{
	`ipaddress.error.ipv4.invalid.decimal.digit`:               50,
	`ipaddress.host.error.invalid.service.hyphen.start`:        51,
	`ipaddress.error.ipv4.invalid.octal.digit`:                 103,
	`ipaddress.host.error.invalidService.no.letter`:            114,
	`ipaddress.host.error.invalidPort.no.digits`:               118,
	`ipaddress.error.empty.start.of.range`:                     122,
	`ipaddress.error.too.many.segments`:                        2,
	`ipaddress.error.ipv4.too.many.segments`:                   59,
	`ipaddress.error.address.is.ipv4`:                          84,
	`ipaddress.error.ipv4.segment.hex`:                         116,
	`ipaddress.error.null.segment`:                             135,
	`ipaddress.error.invalid.zone`:                             10,
	`ipaddress.error.all`:                                      40,
	`ipaddress.error.empty`:                                    94,
	`ipaddress.host.error.invalidService.too.long`:             106,
	`ipaddress.error.only.ipv6.square.brackets`:                14,
	`ipaddress.error.invalid.mask.extra.chars`:                 25,
	`ipaddress.error.segment.too.short.at.index`:               35,
	`ipaddress.error.ipv6.prefix.leading.zeros`:                48,
	`ipaddress.host.error.url`:                                 120,
	`ipaddress.error.zoneAndCIDRPrefix`:                        16,
	`ipaddress.error.single.segment`:                           32,
	`ipaddress.error.zero.not.allowed`:                         63,
	`ipaddress.error.ipv6.format`:                              71,
	`ipaddress.error.invalidRange`:                             89,
	`ipaddress.error.prefix.only`:                              101,
	`ipaddress.error.ipv4.prefix.leading.zeros`:                21,
	`ipaddress.error.invalid.character.combination`:            49,
	`ipaddress.host.error.invalid.mechanism`:                   129,
	`ipaddress.host.error.empty`:                               19,
	`ipaddress.error.invalid.mask.empty`:                       67,
	`ipaddress.error.invalid.character`:                        112,
	`ipaddress.error.invalid.mask.address.empty`:               132,
	`ipaddress.error.ip.format`:                                62,
	`ipaddress.error.special.ip`:                               69,
	`ipaddress.error.ipMismatch`:                               9,
	`ipaddress.error.url`:                                      83,
	`ipaddress.error.no.wildcard`:                              124,
	`ipaddress.error.address.not.block`:                        128,
	`ipaddress.error.only.zone`:                                45,
	`ipaddress.error.ipv6.invalid.byte.count`:                  66,
	`ipaddress.address.error`:                                  33,
	`ipaddress.host.error.invalid.type`:                        27,
	`ipaddress.error.ipv6.has.zone`:                            130,
	`ipaddress.host.error.invalid.service.hyphen.consecutive`:  133,
	`ipaddress.error.mismatched.bit.size`:                      136,
	`ipaddress.host.error.cidrprefixonly`:                      26,
	`ipaddress.error.invalid.character.combination.at.index`:   102,
	`ipaddress.error.mixedNetworks`:                            52,
	`ipaddress.host.error.invalid.length`:                      107,
	`ipaddress.mac.error.not.eui.convertible`:                  110,
	`ipaddress.error.empty.segment.at.index`:                   15,
	`ipaddress.host.error.host.resolve`:                        100,
	`ipaddress.error.ipv6.separator`:                           105,
	`ipaddress.error.maskMismatch`:                             80,
	`ipaddress.error.lower.above.range`:                        61,
	`ipaddress.host.error.ipaddress`:                           121,
	`ipaddress.error.no.mixed`:                                 123,
	`ipaddress.host.error.host.brackets`:                       55,
	`ipaddress.error.ipv4.segment.too.large`:                   75,
	`ipaddress.error.ipv4`:                                     57,
	`ipaddress.error.mac.invalid.segment.count`:                79,
	`ipaddress.error.version.mismatch`:                         96,
	`ipaddress.error.unavailable.numeric`:                      104,
	`ipaddress.error.separatePrefixFromAddress`:                39,
	`ipaddress.error.ipv4.format`:                              20,
	`ipaddress.error.address.lower.exceeds.upper`:              23,
	`ipaddress.error.zone`:                                     38,
	`ipaddress.error.too.few.segments.digit.count`:             41,
	`ipaddress.host.error.bracketed.conflicting.prefix.length`: 65,
	`ipaddress.error.prefixSize`:                               91,
	`ipaddress.error.back.digit.count`:                         6,
	`ipaddress.error.no.single.wildcard`:                       43,
	`ipaddress.error.invalid.character.at.index`:               111,
	`ipaddress.error.invalidCIDRPrefix`:                        11,
	`ipaddress.error.ipv4.too.few.segments`:                    7,
	`ipaddress.error.cannot.end.with.single.separator`:         53,
	`ipaddress.error.splitMismatch`:                            82,
	`ipaddress.error.segment.leading.zeros`:                    86,
	`ipaddress.error.single.wildcard.order`:                    87,
	`ipaddress.error.ipv6.segment.format`:                      0,
	`ipaddress.error.ipv6.invalid.segment.count`:               8,
	`ipaddress.host.error.bracketed.missing.end`:               24,
	`ipaddress.host.error.service`:                             56,
	`ipaddress.error.front.digit.count`:                        64,
	`ipaddress.error.invalidMultipleMask`:                      115,
	`ipaddress.host.error.empty.host.resolve`:                  4,
	`ipaddress.error.ipv6.ambiguous`:                           22,
	`ipaddress.host.error.invalid.service.hyphen.end`:          28,
	`ipaddress.host.error.segment.too.short`:                   78,
	`ipaddress.host.error.invalid.port.service`:                90,
	`ipaddress.error.lower.below.range`:                        93,
	`ipaddress.error.ipVersionMismatch`:                        134,
	`ipaddress.host.error`:                                     5,
	`ipaddress.error.address.is.ipv6`:                          18,
	`ipaddress.error.ipv4.invalid.byte.count`:                  73,
	`ipaddress.error.inconsistent.prefixes`:                    99,
	`ipaddress.mac.error.format`:                               13,
	`ipaddress.error.no.range`:                                 44,
	`ipaddress.host.error.all.numeric`:                         34,
	`ipaddress.error.exceeds.size`:                             3,
	`ipaddress.error.nullNetwork`:                              36,
	`ipaddress.error.segment.too.long.at.index`:                58,
	`ipaddress.error.index.exceeds.prefix.length`:              85,
	`ipaddress.error.no.iterator.element.to.remove`:            88,
	`ipaddress.error.invalid.zone.encoding`:                    92,
	`ipaddress.host.error.port`:                                109,
	`ipaddress.error.invalid.joined.ranges`:                    1,
	`ipaddress.host.error.invalid.character.at.index`:          137,
	`ipaddress.error.too.few.segments`:                         131,
	`ipaddress.error.mixedVersions`:                            17,
	`ipaddress.host.error.bracketed.not.ipv6`:                  30,
	`ipaddress.host.error.invalidService.no.chars`:             60,
	`ipaddress.error.only.ipv6.has.zone`:                       74,
	`ipaddress.error.reverseRange`:                             81,
	`ipaddress.error.invalid.position`:                         108,
	`ipaddress.error.separatePrefixFromMask`:                   127,
	`ipaddress.error.CIDRNotAllowed`:                           12,
	`ipaddress.error.sizeMismatch`:                             77,
	`ipaddress.error.address.out.of.range`:                     119,
	`ipaddress.error.invalid.mask.wildcard`:                    126,
	`ipaddress.error.invalidMixedRange`:                        37,
	`ipaddress.host.error.invalidPort.too.large`:               76,
	`ipaddress.error.address.too.large`:                        98,
	`ipaddress.error.ipv4.invalid.binary.digit`:                113,
	`ipaddress.error.mac.invalid.byte.count`:                   117,
	`ipaddress.error.invalidCIDRPrefixOrMask`:                  125,
	`ipaddress.error.wildcardOrRangeIPv6`:                      29,
	`ipaddress.error.segmentMismatch`:                          46,
	`ipaddress.mac.error.mix.format.characters.at.index`:       47,
	`ipaddress.error.mask.single.segment`:                      68,
	`ipaddress.host.error.invalid`:                             97,
	`ipaddress.host.error.too.many.segments`:                   31,
	`ipaddress.error.ipv6`:                                     70,
	`ipaddress.error.ipv4.invalid.segment.count`:               72,
	`ipaddress.error.segment.too.long`:                         95,
	`ipaddress.error.ipv6.cannot.start.with.single.separator`:  42,
	`ipaddress.host.error.bracketed.conflicting.mask`:          54,
}

var strIndices = []int{
	0, 15, 80, 109, 129, 158, 169, 217, 279, 317,
	368, 412, 580, 628, 674, 718, 748, 772, 830, 845,
	897, 945, 985, 1021, 1070, 1107, 1145, 1200, 1223, 1258,
	1315, 1345, 1362, 1437, 1454, 1480, 1506, 1521, 1583, 1604,
	1661, 1697, 1751, 1863, 1928, 1974, 2013, 2088, 2141, 2181,
	2225, 2246, 2285, 2327, 2434, 2491, 2560, 2607, 2643, 2668,
	2702, 2723, 2735, 2871, 2901, 2950, 3016, 3051, 3064, 3122,
	3197, 3233, 3305, 3343, 3378, 3413, 3435, 3456, 3489, 3508,
	3545, 3614, 3679, 3811, 3851, 3866, 3893, 3923, 3984, 4013,
	4067, 4115, 4190, 4224, 4236, 4263, 4279, 4324, 4336, 4353,
	4403, 4426, 4462, 4524, 4543, 4586, 4620, 4641, 4660, 4686,
	4725, 4766, 4790, 4818, 4838, 4880, 4917, 4956, 4990, 5009,
	5046, 5082, 5123, 5142, 5183, 5231, 5426, 5442, 5479, 5543,
	5574, 5594, 5622, 5645, 5689, 5714, 5761, 5788,
}

var strVals = `invalid segment` +
	`range of joined segments cannot be divided into individual ranges` +
	`address has too many segments` +
	`exceeds address size` +
	`empty host cannot be resolved` +
	`Host error:` +
	`back address in range has an invalid digit count` +
	`options do not allow IPv4 address with less than four segments` +
	`IPv6 address has invalid segment count` +
	`IP version of address must match IP version of mask` +
	`invalid zone or scope id character at index:` +
	`CIDR prefix must indicate the count of subnet bits, between 0 and 32 subnet bits for IP version 4 addresses and between 0 and 128 subnet bits for IP version 6 addresses` +
	`CIDR prefix or mask not allowed for this address` +
	`validation options do no allow this mac format` +
	`only ipv6 can be enclosed in square brackets` +
	`segment value missing at index` +
	`zone and prefix combined` +
	`Please specify either IPv4 or IPv6 addresses, but not both` +
	`address is IPv6` +
	`validation options do no allow empty string for host` +
	`invalid format of IPv4 (255.255.255.255) address` +
	`IPv4 CIDR prefix length starts with zero` +
	`IPv6 compressed address is ambiguous` +
	`invalid address range, lower bound exceeds upper:` +
	`bracketed address missing end bracket` +
	`invalid chars following mask at index:` +
	`please supply an address, not a CIDR prefix length only` +
	`invalid IP address type` +
	`service name cannot end in a hyphen` +
	`Wildcards and ranges are not supported for IPv6 addresses` +
	`bracketed address must be IPv6` +
	`too many segments` +
	`validation options do not allow you to specify a non-segmented single value` +
	`IP Address error:` +
	`host cannot be all numeric` +
	`segment too short at index` +
	`network is null` +
	`IPv4 segment ranges cannot be converted to IPv6 segment ranges` +
	`IPv6 zone not allowed` +
	`specify the IP address separately from the mask or prefix` +
	`the universal address is not allowed` +
	`address has too few segments or an invalid digit count` +
	`An IPv6 address cannot start with a single colon, it must start with either two colons or with the first segment` +
	`validation options do no allow single character wildcard segments` +
	`validation options do not allow range segments` +
	`with a zone you must specify an address` +
	`joining segments results in a joined segment that is not a sequential range` +
	`invalid mix of mac address format characters at index` +
	`IPv6 CIDR prefix length starts with zero` +
	`invalid combination of characters in segment` +
	`invalid decimal digit` +
	`service name cannot start with a hyphen` +
	`Address components have different networks` +
	`An IPv6 address cannot end with a single colon, it must end with either two colons or with the last segment` +
	`conflicting masks inside and outside of bracketed address` +
	`ipv6 addresses must be surrounded by square brackets [] in host names` +
	`validation options do no allow for service name` +
	`validation options do not allow IPv4` +
	`segment too long at index` +
	`IPv4 address has too many segments` +
	`service name is empty` +
	`above range:` +
	`invalid format of IP address, whether IPv4 (255.255.255.255) or IPv6 (ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff) or other supported format` +
	`a non-zero address is required` +
	`front address in range has an invalid digit count` +
	`conflicting prefix lengths inside and outside of bracketed address` +
	`IPv6 address has invalid byte count` +
	`mask is empty` +
	`mask with single segment not allowed by validation options` +
	`a special IP address with first segment larger than 255 cannot be used here` +
	`validation options do not allow IPv6` +
	`invalid format of IPv6 (ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff) address` +
	`IPv4 address has invalid segment count` +
	`IPv4 address has invalid byte count` +
	`only ipv6 can have a zone specified` +
	`IPv4 segment too large` +
	`port number too large` +
	`the number of segments must match` +
	`zero-length segment` +
	`MAC address has invalid segment count` +
	`applying the mask results in a segment that is not a sequential range` +
	`reversing a range of values does not result in a sequential range` +
	`splitting digits in range segments results in an invalid string (eg 12-22 becomes 1-2.2-2 which is 12 and 22 and nothing in between)` +
	`please supply an address, not a full URL` +
	`address is IPv4` +
	`index exceeds prefix length` +
	`segment value starts with zero` +
	`single wildcards can appear only as the end of segment values` +
	`no iterator element to remove` +
	`in segment range, lower value must precede upper value` +
	`invalid port or service name character at index:` +
	`the network prefix bit-length is negative or exceeds the address bit-length` +
	`invalid encoding in zone at index:` +
	`below range:` +
	`you must specify an address` +
	`segment too long` +
	`Unable to convert version of argument address` +
	`invalid host` +
	`address too large` +
	`Segments invalid due to inconsistent prefix values` +
	`host cannot be resolved` +
	`a prefix-only address is not allowed` +
	`invalid combination with earlier character at character number` +
	`invalid octal digit` +
	`No numeric value available for this address` +
	`invalid position of IPv6 separator` +
	`service name too long` +
	`invalid host length` +
	`Invalid index into address` +
	`validation options do no allow for port` +
	`MAC address cannot be converted to EUI 64` +
	`invalid character number` +
	`invalid character in segment` +
	`invalid binary digit` +
	`service name must have at least one letter` +
	`mask must specify a single IP address` +
	`IPv4 segment contains hexadecimal value` +
	`MAC address has invalid byte count` +
	`port value is empty` +
	`Address not within the assigned range` +
	`please supply a host, not a full URL` +
	`validation options do no allow IP address` +
	`range start missing` +
	`validation options do no allow mixed IPv6` +
	`validation options do no allow wildcard segments` +
	`A mask must be a single IP address, while a CIDR prefix length must indicate the count of subnet bits, between 0 and 32 for IP version 4 addresses and between 0 and 128 for IP version 6 addresses` +
	`wildcard in mask` +
	`specify a mask or prefix but not both` +
	`Address is neither a CIDR prefix block nor an individual address` +
	`address mechanism not supported` +
	`no ipv6 zone allowed` +
	`address has too few segments` +
	`mask with empty address` +
	`service name cannot have consecutive hyphens` +
	`the IP version must match` +
	`Section or grouping array contains a null value` +
	`mismatched address bit size` +
	`invalid character at index`

func lookupStr(key string) (result string) {
	if index, ok := keyStrMap[key]; ok {
		start, end := strIndices[index], strIndices[index+1]
		result = strVals[start:end]
	}
	return
}
