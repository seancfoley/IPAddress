package ipaddr

var keyStrMap = map[string]int{
	`ipaddress.error.mac.invalid.segment.count`:                8,
	`ipaddress.error.segmentMismatch`:                          18,
	`ipaddress.error.invalid.zone.encoding`:                    25,
	`ipaddress.host.error.invalid.length`:                      35,
	`ipaddress.error.separatePrefixFromAddress`:                58,
	`ipaddress.host.error.host.resolve`:                        117,
	`ipaddress.error.index.exceeds.prefix.length`:              59,
	`ipaddress.error.segment.leading.zeros`:                    110,
	`ipaddress.error.ipv6.has.zone`:                            136,
	`ipaddress.error.ipMismatch`:                               64,
	`ipaddress.error.ipv6.invalid.segment.count`:               79,
	`ipaddress.error.segment.too.long`:                         118,
	`ipaddress.host.error.service`:                             135,
	`ipaddress.host.error.empty`:                               1,
	`ipaddress.error.nullNetwork`:                              4,
	`ipaddress.error.maskMismatch`:                             17,
	`ipaddress.host.error.ipaddress`:                           113,
	`ipaddress.host.error.invalidPort.too.large`:               3,
	`ipaddress.host.error.port`:                                66,
	`ipaddress.error.ipv6.format`:                              71,
	`ipaddress.error.ipv4.prefix.leading.zeros`:                78,
	`ipaddress.error.no.wildcard`:                              12,
	`ipaddress.error.unavailable.numeric`:                      38,
	`ipaddress.error.invalidMixedRange`:                        52,
	`ipaddress.error.address.not.block`:                        69,
	`ipaddress.mac.error.format`:                               131,
	`ipaddress.error.segment.too.long.at.index`:                137,
	`ipaddress.error.invalid.zone`:                             45,
	`ipaddress.error.too.few.segments.digit.count`:             50,
	`ipaddress.host.error.bracketed.not.ipv6`:                  88,
	`ipaddress.error.mac.invalid.byte.count`:                   101,
	`ipaddress.error.no.range`:                                 103,
	`ipaddress.error.invalid.character.at.index`:               133,
	`ipaddress.error.ipv4.invalid.segment.count`:               14,
	`ipaddress.host.error.invalidService.no.letter`:            26,
	`ipaddress.host.error.cidrprefixonly`:                      29,
	`ipaddress.host.error.invalid.service.hyphen.start`:        33,
	`ipaddress.error.ipv6`:                                     84,
	`ipaddress.error.prefix.only`:                              132,
	`ipaddress.error.only.ipv6.square.brackets`:                55,
	`ipaddress.error.ip.format`:                                13,
	`ipaddress.error.ipv4.segment.hex`:                         37,
	`ipaddress.error.null.segment`:                             39,
	`ipaddress.error.empty.start.of.range`:                     95,
	`ipaddress.error.invalid.character`:                        98,
	`ipaddress.error.lower.below.range`:                        109,
	`ipaddress.error.ipv6.prefix.leading.zeros`:                125,
	`ipaddress.error.ipv6.ambiguous`:                           32,
	`ipaddress.error.ipv4.format`:                              42,
	`ipaddress.error.no.single.wildcard`:                       43,
	`ipaddress.host.error.all.numeric`:                         124,
	`ipaddress.host.error.empty.host.resolve`:                  72,
	`ipaddress.error.mixedNetworks`:                            112,
	`ipaddress.host.error.url`:                                 30,
	`ipaddress.error.single.segment`:                           60,
	`ipaddress.error.only.ipv6.has.zone`:                       107,
	`ipaddress.mac.error.mix.format.characters.at.index`:       7,
	`ipaddress.error.cannot.end.with.single.separator`:         11,
	`ipaddress.error.single.wildcard.order`:                    51,
	`ipaddress.error.ipv4.invalid.octal.digit`:                 100,
	`ipaddress.error.segment.too.short.at.index`:               115,
	`ipaddress.error.lower.above.range`:                        6,
	`ipaddress.error.ipv6.cannot.start.with.single.separator`:  10,
	`ipaddress.host.error.invalidService.no.chars`:             105,
	`ipaddress.error.version.mismatch`:                         27,
	`ipaddress.mac.error.not.eui.convertible`:                  54,
	`ipaddress.host.error.too.many.segments`:                   65,
	`ipaddress.host.error.bracketed.conflicting.prefix.length`: 86,
	`ipaddress.error.invalidMultipleMask`:                      121,
	`ipaddress.error.address.out.of.range`:                     24,
	`ipaddress.error.ipv4.invalid.binary.digit`:                47,
	`ipaddress.error.ipv4.segment.too.large`:                   56,
	`ipaddress.error.ipv4.invalid.decimal.digit`:               68,
	`ipaddress.host.error.invalidPort.no.digits`:               16,
	`ipaddress.error.exceeds.size`:                             87,
	`ipaddress.error.all`:                                      114,
	`ipaddress.address.error`:                                  73,
	`ipaddress.host.error.bracketed.missing.end`:               89,
	`ipaddress.error.separatePrefixFromMask`:                   5,
	`ipaddress.error.reverseRange`:                             48,
	`ipaddress.error.zone`:                                     57,
	`ipaddress.host.error.invalid.service.hyphen.end`:          63,
	`ipaddress.error.invalid.mask.empty`:                       93,
	`ipaddress.error.empty.segment.at.index`:                   102,
	`ipaddress.error.no.iterator.element.to.remove`:            106,
	`ipaddress.error.CIDRNotAllowed`:                           129,
	`ipaddress.error.ipv4`:                                     31,
	`ipaddress.host.error`:                                     74,
	`ipaddress.error.no.mixed`:                                 82,
	`ipaddress.host.error.segment.too.short`:                   36,
	`ipaddress.error.sizeMismatch`:                             44,
	`ipaddress.error.ipv6.invalid.byte.count`:                  75,
	`ipaddress.error.invalidCIDRPrefixOrMask`:                  76,
	`ipaddress.error.zoneAndCIDRPrefix`:                        128,
	`ipaddress.error.invalidCIDRPrefix`:                        62,
	`ipaddress.error.invalid.joined.ranges`:                    81,
	`ipaddress.host.error.invalid.character.at.index`:          94,
	`ipaddress.error.zero.not.allowed`:                         99,
	`ipaddress.host.error.invalidService.too.long`:             104,
	`ipaddress.error.ipv4.too.few.segments`:                    120,
	`ipaddress.host.error.invalid.type`:                        123,
	`ipaddress.error.invalid.mask.address.empty`:               127,
	`ipaddress.error.only.zone`:                                20,
	`ipaddress.host.error.invalid.service.hyphen.consecutive`:  28,
	`ipaddress.error.special.ip`:                               70,
	`ipaddress.error.mixedVersions`:                            83,
	`ipaddress.host.error.invalid.port.service`:                85,
	`ipaddress.host.error.bracketed.conflicting.mask`:          90,
	`ipaddress.host.error.invalid.mechanism`:                   116,
	`ipaddress.error.ipv4.too.many.segments`:                   134,
	`ipaddress.error.invalid.character.combination.at.index`:   15,
	`ipaddress.error.ipv4.invalid.byte.count`:                  91,
	`ipaddress.error.empty`:                                    108,
	`ipaddress.error.wildcardOrRangeIPv6`:                      130,
	`ipaddress.error.invalid.mask.extra.chars`:                 9,
	`ipaddress.error.ipVersionMismatch`:                        19,
	`ipaddress.error.splitMismatch`:                            49,
	`ipaddress.error.front.digit.count`:                        67,
	`ipaddress.error.invalid.mask.wildcard`:                    2,
	`ipaddress.error.url`:                                      92,
	`ipaddress.error.too.few.segments`:                         111,
	`ipaddress.error.too.many.segments`:                        119,
	`ipaddress.error.invalid.character.combination`:            126,
	`ipaddress.error.mismatched.bit.size`:                      34,
	`ipaddress.error.address.lower.exceeds.upper`:              40,
	`ipaddress.error.ipv6.separator`:                           96,
	`ipaddress.error.address.too.large`:                        97,
	`ipaddress.error.back.digit.count`:                         22,
	`ipaddress.error.inconsistent.prefixes`:                    77,
	`ipaddress.error.address.is.ipv4`:                          80,
	`ipaddress.host.error.host.brackets`:                       41,
	`ipaddress.error.mask.single.segment`:                      46,
	`ipaddress.error.invalidRange`:                             61,
	`ipaddress.error.prefixSize`:                               122,
	`ipaddress.host.error.invalid`:                             0,
	`ipaddress.error.ipv6.segment.format`:                      21,
	`ipaddress.error.invalid.position`:                         23,
	`ipaddress.error.address.is.ipv6`:                          53,
}

var strIndices = []int{
	0, 12, 64, 80, 101, 116, 153, 165, 218, 255,
	293, 405, 512, 560, 696, 734, 796, 815, 884, 959,
	984, 1023, 1038, 1086, 1112, 1149, 1183, 1225, 1270, 1314,
	1369, 1405, 1441, 1477, 1516, 1543, 1562, 1581, 1620, 1663,
	1710, 1759, 1828, 1876, 1941, 1974, 2018, 2076, 2096, 2161,
	2293, 2347, 2408, 2470, 2485, 2526, 2570, 2592, 2613, 2670,
	2697, 2772, 2826, 2994, 3029, 3080, 3097, 3136, 3185, 3206,
	3270, 3345, 3417, 3446, 3463, 3474, 3509, 3704, 3754, 3794,
	3832, 3847, 3912, 3953, 4011, 4047, 4095, 4161, 4181, 4211,
	4248, 4305, 4340, 4380, 4393, 4419, 4438, 4472, 4489, 4517,
	4547, 4566, 4600, 4630, 4676, 4697, 4718, 4747, 4782, 4809,
	4821, 4851, 4879, 4921, 4962, 4998, 5024, 5055, 5078, 5094,
	5123, 5185, 5222, 5297, 5320, 5346, 5386, 5430, 5453, 5477,
	5525, 5582, 5628, 5664, 5688, 5722, 5769, 5789,
}

var strVals = `invalid host` +
	`validation options do no allow empty string for host` +
	`wildcard in mask` +
	`port number too large` +
	`network is null` +
	`specify a mask or prefix but not both` +
	`above range:` +
	`invalid mix of mac address format characters at index` +
	`MAC address has invalid segment count` +
	`invalid chars following mask at index:` +
	`An IPv6 address cannot start with a single colon, it must start with either two colons or with the first segment` +
	`An IPv6 address cannot end with a single colon, it must end with either two colons or with the last segment` +
	`validation options do no allow wildcard segments` +
	`invalid format of IP address, whether IPv4 (255.255.255.255) or IPv6 (ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff) or other supported format` +
	`IPv4 address has invalid segment count` +
	`invalid combination with earlier character at character number` +
	`port value is empty` +
	`applying the mask results in a segment that is not a sequential range` +
	`joining segments results in a joined segment that is not a sequential range` +
	`the IP version must match` +
	`with a zone you must specify an address` +
	`invalid segment` +
	`back address in range has an invalid digit count` +
	`invalidType index into address` +
	`Address not within the assigned range` +
	`invalid encoding in zone at index:` +
	`service name must have at least one letter` +
	`Unable to convert version of argument address` +
	`service name cannot have consecutive hyphens` +
	`please supply an address, not a CIDR prefix length only` +
	`please supply a host, not a full URL` +
	`validation options do not allow IPv4` +
	`IPv6 compressed address is ambiguous` +
	`service name cannot start with a hyphen` +
	`mismatched address bit size` +
	`invalid host length` +
	`zero-length segment` +
	`IPv4 segment contains hexadecimal value` +
	`No numeric value available for this address` +
	`Section or grouping array contains a null value` +
	`invalid address range, lower bound exceeds upper:` +
	`ipv6 addresses must be surrounded by square brackets [] in host names` +
	`invalid format of IPv4 (255.255.255.255) address` +
	`validation options do no allow single character wildcard segments` +
	`the number of segments must match` +
	`invalid zone or scope id character at index:` +
	`mask with single segment not allowed by validation options` +
	`invalid binary digit` +
	`reversing a range of values does not result in a sequential range` +
	`splitting digits in range segments results in an invalid string (eg 12-22 becomes 1-2.2-2 which is 12 and 22 and nothing in between)` +
	`address has too few segments or an invalid digit count` +
	`single wildcards can appear only as the end of segment values` +
	`IPv4 segment ranges cannot be converted to IPv6 segment ranges` +
	`address is IPv6` +
	`MAC address cannot be converted to EUI 64` +
	`only ipv6 can be enclosed in square brackets` +
	`IPv4 segment too large` +
	`IPv6 zone not allowed` +
	`specify the IP address separately from the mask or prefix` +
	`index exceeds prefix length` +
	`validation options do not allow you to specify a non-segmented single value` +
	`in segment range, lower value must precede upper value` +
	`CIDR prefix must indicate the count of subnet bits, between 0 and 32 subnet bits for IP version 4 addresses and between 0 and 128 subnet bits for IP version 6 addresses` +
	`service name cannot end in a hyphen` +
	`IP version of address must match IP version of mask` +
	`too many segments` +
	`validation options do no allow for port` +
	`front address in range has an invalid digit count` +
	`invalid decimal digit` +
	`Address is neither a CIDR prefix block nor an individual address` +
	`a special IP address with first segment larger than 255 cannot be used here` +
	`invalid format of IPv6 (ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff) address` +
	`empty host cannot be resolved` +
	`IP Address error:` +
	`Host error:` +
	`IPv6 address has invalid byte count` +
	`A mask must be a single IP address, while a CIDR prefix length must indicate the count of subnet bits, between 0 and 32 for IP version 4 addresses and between 0 and 128 for IP version 6 addresses` +
	`Segments invalid due to inconsistent prefix values` +
	`IPv4 CIDR prefix length starts with zero` +
	`IPv6 address has invalid segment count` +
	`address is IPv4` +
	`range of joined segments cannot be divided into individual ranges` +
	`validation options do no allow mixed IPv6` +
	`Please specify either IPv4 or IPv6 addresses, but not both` +
	`validation options do not allow IPv6` +
	`invalid port or service name character at index:` +
	`conflicting prefix lengths inside and outside of bracketed address` +
	`exceeds address size` +
	`bracketed address must be IPv6` +
	`bracketed address missing end bracket` +
	`conflicting masks inside and outside of bracketed address` +
	`IPv4 address has invalid byte count` +
	`please supply an address, not a full URL` +
	`mask is empty` +
	`invalid character at index` +
	`range start missing` +
	`invalid position of IPv6 separator` +
	`address too large` +
	`invalid character in segment` +
	`a non-zero address is required` +
	`invalid octal digit` +
	`MAC address has invalid byte count` +
	`segment value missing at index` +
	`validation options do not allow range segments` +
	`service name too long` +
	`service name is empty` +
	`no iterator element to remove` +
	`only ipv6 can have a zone specified` +
	`you must specify an address` +
	`below range:` +
	`segment value starts with zero` +
	`address has too few segments` +
	`Address components have different networks` +
	`validation options do no allow IP address` +
	`the universal address is not allowed` +
	`segment too short at index` +
	`address mechanism not supported` +
	`host cannot be resolved` +
	`segment too long` +
	`address has too many segments` +
	`options do not allow IPv4 address with less than four segments` +
	`mask must specify a single IP address` +
	`the network prefix bit-length is negative or exceeds the address bit-length` +
	`invalid IP address type` +
	`host cannot be all numeric` +
	`IPv6 CIDR prefix length starts with zero` +
	`invalid combination of characters in segment` +
	`mask with empty address` +
	`zone and prefix combined` +
	`CIDR prefix or mask not allowed for this address` +
	`Wildcards and ranges are not supported for IPv6 addresses` +
	`validation options do no allow this mac format` +
	`a prefix-only address is not allowed` +
	`invalid character number` +
	`IPv4 address has too many segments` +
	`validation options do no allow for service name` +
	`no ipv6 zone allowed` +
	`segment too long at index`

func lookupStr(key string) (result string) {
	if index, ok := keyStrMap[key]; ok {
		start, end := strIndices[index], strIndices[index+1]
		result = strVals[start:end]
	}
	return
}
