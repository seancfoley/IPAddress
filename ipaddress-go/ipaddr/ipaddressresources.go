package ipaddr

var keyStrMap = map[string]int{
	`ipaddress.error.unavailable.numeric`:                      68,
	`ipaddress.address.error`:                                  73,
	`ipaddress.host.error.invalid.service.hyphen.consecutive`:  106,
	`ipaddress.error.address.is.ipv4`:                          122,
	`ipaddress.error.ipv4.invalid.decimal.digit`:               33,
	`ipaddress.host.error.bracketed.missing.end`:               66,
	`ipaddress.host.error.invalid.length`:                      31,
	`ipaddress.error.separatePrefixFromMask`:                   65,
	`ipaddress.error.only.ipv6.square.brackets`:                24,
	`ipaddress.error.mismatched.bit.size`:                      30,
	`ipaddress.error.sizeMismatch`:                             55,
	`ipaddress.error.invalidRange`:                             78,
	`ipaddress.error.index.exceeds.prefix.length`:              93,
	`ipaddress.error.version.mismatch`:                         107,
	`ipaddress.error.segment.too.long`:                         9,
	`ipaddress.host.error.ipaddress`:                           35,
	`ipaddress.error.inconsistent.prefixes`:                    97,
	`ipaddress.host.error.bracketed.not.ipv6`:                  98,
	`ipaddress.error.ipv6.cannot.start.with.single.separator`:  102,
	`ipaddress.error.mac.invalid.segment.count`:                132,
	`ipaddress.error.empty.start.of.range`:                     50,
	`ipaddress.error.empty`:                                    82,
	`ipaddress.error.segment.leading.zeros`:                    44,
	`ipaddress.error.separatePrefixFromAddress`:                92,
	`ipaddress.error.only.ipv6.has.zone`:                       14,
	`ipaddress.error.front.digit.count`:                        27,
	`ipaddress.host.error.invalidService.no.letter`:            80,
	`ipaddress.error.ipv4.invalid.octal.digit`:                 17,
	`ipaddress.host.error.cidrprefixonly`:                      58,
	`ipaddress.error.url`:                                      71,
	`ipaddress.error.ipv6.ambiguous`:                           110,
	`ipaddress.error.ipv4.prefix.leading.zeros`:                40,
	`ipaddress.error.invalid.mask.address.empty`:               19,
	`ipaddress.error.no.mixed`:                                 36,
	`ipaddress.error.ipv6.format`:                              100,
	`ipaddress.error.ipv6.has.zone`:                            120,
	`ipaddress.host.error.url`:                                 22,
	`ipaddress.error.address.lower.exceeds.upper`:              57,
	`ipaddress.host.error.too.many.segments`:                   59,
	`ipaddress.error.ip.format`:                                60,
	`ipaddress.error.too.many.segments`:                        118,
	`ipaddress.error.segmentMismatch`:                          127,
	`ipaddress.error.lower.below.range`:                        20,
	`ipaddress.mac.error.mix.format.characters.at.index`:       39,
	`ipaddress.error.splitMismatch`:                            96,
	`ipaddress.error.no.wildcard`:                              42,
	`ipaddress.error.zero.not.allowed`:                         75,
	`ipaddress.host.error.invalidPort.no.digits`:               70,
	`ipaddress.error.mixedNetworks`:                            85,
	`ipaddress.error.maskMismatch`:                             54,
	`ipaddress.host.error.invalid.port.service`:                63,
	`ipaddress.error.ipMismatch`:                               89,
	`ipaddress.error.ipVersionMismatch`:                        121,
	`ipaddress.mac.error.format`:                               0,
	`ipaddress.error.too.few.segments.digit.count`:             11,
	`ipaddress.mac.error.not.eui.convertible`:                  108,
	`ipaddress.error.single.wildcard.order`:                    119,
	`ipaddress.host.error.bracketed.conflicting.prefix.length`: 129,
	`ipaddress.host.error.empty.host.resolve`:                  136,
	`ipaddress.host.error.empty`:                               21,
	`ipaddress.host.error.invalid.service.hyphen.end`:          105,
	`ipaddress.host.error.invalidService.no.chars`:             52,
	`ipaddress.host.error.host.brackets`:                       5,
	`ipaddress.host.error.invalidService.too.long`:             51,
	`ipaddress.error.ipv4.segment.too.large`:                   67,
	`ipaddress.host.error.invalid.character.at.index`:          16,
	`ipaddress.error.prefix.only`:                              43,
	`ipaddress.error.ipv4.segment.hex`:                         101,
	`ipaddress.host.error.all.numeric`:                         32,
	`ipaddress.error.empty.segment.at.index`:                   41,
	`ipaddress.error.ipv4.too.few.segments`:                    53,
	`ipaddress.error.single.segment`:                           125,
	`ipaddress.error.no.iterator.element.to.remove`:            134,
	`ipaddress.error.invalid.zone`:                             34,
	`ipaddress.host.error.invalid`:                             38,
	`ipaddress.error.address.is.ipv6`:                          47,
	`ipaddress.error.mixedVersions`:                            112,
	`ipaddress.error.invalid.character`:                        13,
	`ipaddress.error.too.few.segments`:                         45,
	`ipaddress.error.lower.above.range`:                        86,
	`ipaddress.error.null.segment`:                             94,
	`ipaddress.host.error.invalidPort.too.large`:               104,
	`ipaddress.error.ipv4.invalid.binary.digit`:                111,
	`ipaddress.error.ipv4.invalid.segment.count`:               1,
	`ipaddress.error.segment.too.short.at.index`:               10,
	`ipaddress.error.zone`:                                     81,
	`ipaddress.error.ipv6.prefix.leading.zeros`:                83,
	`ipaddress.error.ipv4.too.many.segments`:                   12,
	`ipaddress.host.error.port`:                                23,
	`ipaddress.error.ipv6.invalid.segment.count`:               77,
	`ipaddress.error.invalid.character.combination`:            103,
	`ipaddress.error.no.range`:                                 37,
	`ipaddress.error.segment.too.long.at.index`:                49,
	`ipaddress.error.ipv6`:                                     76,
	`ipaddress.error.invalid.mask.wildcard`:                    95,
	`ipaddress.error.nullNetwork`:                              113,
	`ipaddress.error.address.not.block`:                        128,
	`ipaddress.error.ipv6.invalid.byte.count`:                  7,
	`ipaddress.host.error.invalid.mechanism`:                   15,
	`ipaddress.error.special.ip`:                               130,
	`ipaddress.error.ipv6.separator`:                           133,
	`ipaddress.host.error.segment.too.short`:                   99,
	`ipaddress.error.address.out.of.range`:                     115,
	`ipaddress.error.mac.invalid.byte.count`:                   126,
	`ipaddress.host.error.invalid.service.hyphen.start`:        135,
	`ipaddress.error.cannot.end.with.single.separator`:         28,
	`ipaddress.error.invalid.mask.empty`:                       69,
	`ipaddress.error.ipv6.segment.format`:                      88,
	`ipaddress.host.error.invalid.type`:                        124,
	`ipaddress.error.address.too.large`:                        131,
	`ipaddress.error.invalid.position`:                         29,
	`ipaddress.error.invalidCIDRPrefixOrMask`:                  62,
	`ipaddress.error.invalid.joined.ranges`:                    84,
	`ipaddress.host.error.service`:                             87,
	`ipaddress.error.wildcardOrRangeIPv6`:                      90,
	`ipaddress.error.zoneAndCIDRPrefix`:                        64,
	`ipaddress.error.invalid.character.combination.at.index`:   79,
	`ipaddress.error.mask.single.segment`:                      48,
	`ipaddress.error.only.zone`:                                114,
	`ipaddress.host.error`:                                     8,
	`ipaddress.error.invalidCIDRPrefix`:                        18,
	`ipaddress.error.prefixSize`:                               56,
	`ipaddress.error.exceeds.size`:                             72,
	`ipaddress.error.back.digit.count`:                         61,
	`ipaddress.host.error.bracketed.conflicting.mask`:          74,
	`ipaddress.error.invalid.mask.extra.chars`:                 3,
	`ipaddress.error.ipv4.invalid.byte.count`:                  6,
	`ipaddress.error.no.single.wildcard`:                       25,
	`ipaddress.error.invalidMixedRange`:                        26,
	`ipaddress.error.ipv4`:                                     116,
	`ipaddress.error.invalid.character.at.index`:               2,
	`ipaddress.error.CIDRNotAllowed`:                           4,
	`ipaddress.error.all`:                                      109,
	`ipaddress.error.ipv4.format`:                              117,
	`ipaddress.error.invalid.zone.encoding`:                    123,
	`ipaddress.error.reverseRange`:                             46,
	`ipaddress.error.invalidMultipleMask`:                      91,
}

var strIndices = []int{
	0, 46, 84, 108, 146, 194, 263, 298, 333, 344,
	360, 386, 440, 474, 502, 537, 568, 594, 613, 781,
	804, 816, 868, 904, 943, 987, 1052, 1114, 1163, 1270,
	1296, 1323, 1342, 1368, 1389, 1433, 1474, 1515, 1561, 1573,
	1626, 1666, 1696, 1744, 1780, 1810, 1838, 1903, 1918, 1976,
	2001, 2020, 2041, 2062, 2124, 2193, 2226, 2301, 2350, 2405,
	2422, 2558, 2606, 2801, 2849, 2873, 2910, 2947, 2969, 3012,
	3025, 3044, 3084, 3104, 3121, 3178, 3208, 3244, 3282, 3336,
	3398, 3440, 3461, 3488, 3528, 3593, 3635, 3647, 3694, 3709,
	3760, 3817, 3854, 3911, 3938, 3985, 4001, 4133, 4183, 4213,
	4232, 4304, 4343, 4455, 4499, 4520, 4555, 4599, 4644, 4685,
	4721, 4757, 4777, 4835, 4850, 4889, 4926, 4962, 5010, 5039,
	5100, 5120, 5145, 5160, 5194, 5217, 5292, 5326, 5401, 5465,
	5531, 5606, 5623, 5660, 5694, 5723, 5762,
}

var strVals = `validation options do no allow this mac format` +
	`IPv4 address has invalid segment count` +
	`invalid character number` +
	`invalid chars following mask at index:` +
	`CIDR prefix or mask not allowed for this address` +
	`ipv6 addresses must be surrounded by square brackets [] in host names` +
	`IPv4 address has invalid byte count` +
	`IPv6 address has invalid byte count` +
	`Host error:` +
	`segment too long` +
	`segment too short at index` +
	`address has too few segments or an invalid digit count` +
	`IPv4 address has too many segments` +
	`invalid character in segment` +
	`only ipv6 can have a zone specified` +
	`address mechanism not supported` +
	`invalid character at index` +
	`invalid octal digit` +
	`CIDR prefix must indicate the count of subnet bits, between 0 and 32 subnet bits for IP version 4 addresses and between 0 and 128 subnet bits for IP version 6 addresses` +
	`mask with empty address` +
	`below range:` +
	`validation options do no allow empty string for host` +
	`please supply a host, not a full URL` +
	`validation options do no allow for port` +
	`only ipv6 can be enclosed in square brackets` +
	`validation options do no allow single character wildcard segments` +
	`IPv4 segment ranges cannot be converted to IPv6 segment ranges` +
	`front address in range has an invalid digit count` +
	`An IPv6 address cannot end with a single colon, it must end with either two colons or with the last segment` +
	`Invalid index into address` +
	`mismatched address bit size` +
	`invalid host length` +
	`host cannot be all numeric` +
	`invalid decimal digit` +
	`invalid zone or scope id character at index:` +
	`validation options do no allow IP address` +
	`validation options do no allow mixed IPv6` +
	`validation options do not allow range segments` +
	`invalid host` +
	`invalid mix of mac address format characters at index` +
	`IPv4 CIDR prefix length starts with zero` +
	`segment value missing at index` +
	`validation options do no allow wildcard segments` +
	`a prefix-only address is not allowed` +
	`segment value starts with zero` +
	`address has too few segments` +
	`reversing a range of values does not result in a sequential range` +
	`address is IPv6` +
	`mask with single segment not allowed by validation options` +
	`segment too long at index` +
	`range start missing` +
	`service name too long` +
	`service name is empty` +
	`options do not allow IPv4 address with less than four segments` +
	`applying the mask results in a segment that is not a sequential range` +
	`the number of segments must match` +
	`the network prefix bit-length is negative or exceeds the address bit-length` +
	`invalid address range, lower bound exceeds upper:` +
	`please supply an address, not a CIDR prefix length only` +
	`too many segments` +
	`invalid format of IP address, whether IPv4 (255.255.255.255) or IPv6 (ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff) or other supported format` +
	`back address in range has an invalid digit count` +
	`A mask must be a single IP address, while a CIDR prefix length must indicate the count of subnet bits, between 0 and 32 for IP version 4 addresses and between 0 and 128 for IP version 6 addresses` +
	`invalid port or service name character at index:` +
	`zone and prefix combined` +
	`specify a mask or prefix but not both` +
	`bracketed address missing end bracket` +
	`IPv4 segment too large` +
	`No numeric value available for this address` +
	`mask is empty` +
	`port value is empty` +
	`please supply an address, not a full URL` +
	`exceeds address size` +
	`IP Address error:` +
	`conflicting masks inside and outside of bracketed address` +
	`a non-zero address is required` +
	`validation options do not allow IPv6` +
	`IPv6 address has invalid segment count` +
	`in segment range, lower value must precede upper value` +
	`invalid combination with earlier character at character number` +
	`service name must have at least one letter` +
	`IPv6 zone not allowed` +
	`you must specify an address` +
	`IPv6 CIDR prefix length starts with zero` +
	`range of joined segments cannot be divided into individual ranges` +
	`Address components have different networks` +
	`above range:` +
	`validation options do no allow for service name` +
	`invalid segment` +
	`IP version of address must match IP version of mask` +
	`Wildcards and ranges are not supported for IPv6 addresses` +
	`mask must specify a single IP address` +
	`specify the IP address separately from the mask or prefix` +
	`index exceeds prefix length` +
	`Section or grouping array contains a null value` +
	`wildcard in mask` +
	`splitting digits in range segments results in an invalid string (eg 12-22 becomes 1-2.2-2 which is 12 and 22 and nothing in between)` +
	`Segments invalid due to inconsistent prefix values` +
	`bracketed address must be IPv6` +
	`zero-length segment` +
	`invalid format of IPv6 (ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff) address` +
	`IPv4 segment contains hexadecimal value` +
	`An IPv6 address cannot start with a single colon, it must start with either two colons or with the first segment` +
	`invalid combination of characters in segment` +
	`port number too large` +
	`service name cannot end in a hyphen` +
	`service name cannot have consecutive hyphens` +
	`Unable to convert version of argument address` +
	`MAC address cannot be converted to EUI 64` +
	`the universal address is not allowed` +
	`IPv6 compressed address is ambiguous` +
	`invalid binary digit` +
	`Please specify either IPv4 or IPv6 addresses, but not both` +
	`network is null` +
	`with a zone you must specify an address` +
	`Address not within the assigned range` +
	`validation options do not allow IPv4` +
	`invalid format of IPv4 (255.255.255.255) address` +
	`address has too many segments` +
	`single wildcards can appear only as the end of segment values` +
	`no ipv6 zone allowed` +
	`the IP version must match` +
	`address is IPv4` +
	`invalid encoding in zone at index:` +
	`invalid IP address type` +
	`validation options do not allow you to specify a non-segmented single value` +
	`MAC address has invalid byte count` +
	`joining segments results in a joined segment that is not a sequential range` +
	`Address is neither a CIDR prefix block nor an individual address` +
	`conflicting prefix lengths inside and outside of bracketed address` +
	`a special IP address with first segment larger than 255 cannot be used here` +
	`address too large` +
	`MAC address has invalid segment count` +
	`invalid position of IPv6 separator` +
	`no iterator element to remove` +
	`service name cannot start with a hyphen` +
	`empty host cannot be resolved`

func lookupStr(key string) (result string) {
	if index, ok := keyStrMap[key]; ok {
		start, end := strIndices[index], strIndices[index+1]
		result = strVals[start:end]
	}
	return
}
