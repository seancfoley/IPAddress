/*
 * Copyright 2016-2018 Sean C Foley
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *     or at
 *     https://github.com/seancfoley/IPAddress/blob/master/LICENSE
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package inet.ipaddr.test;

import java.util.HashMap;
import java.util.Map;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.concurrent.ConcurrentHashMap;

import inet.ipaddr.IPAddress;
import inet.ipaddr.IPAddressNetwork.IPAddressStringGenerator;
import inet.ipaddr.IPAddressString;
import inet.ipaddr.IPAddressStringParameters;
import inet.ipaddr.IncompatibleAddressException;
import inet.ipaddr.ipv6.IPv6Address;

public class IPAddressAllTest extends IPAddressRangeTest {
	
	static String[] ADDRESS_SAMPLING = {
		"bla",
		"foo",
		"",
		"  ",
		"     ",
		"",
		"1.0.0.0",
		"1.002.3.4",
		"1.2.003.4",
		"1.2.3.4",
		"000100401404",
		"0x01020304",
		"001.002.003.004",
		"1.002.3.*",
		"1.002.3.*/31",
		"1.002.3.*/17",
		"1.002.3.4/16",
		"1.002.3.*/16",
		"001.002.003.004/16",
		"1.2.003.4/15",
		"1.2.3.4/15",
		"255.254.255.254",
		"255.254.255.255",
		"*.*.1-3.*",
		"255.255.255.254",
		"*.*.*.*",
		"*.*.%*.*",
		"255.255.255.255",
		"1::",
		"1::2:3:4",
		"1::2:003:4",
		"1::2:3:4",
		"0001:0000::0002:0003:0004",
		"1::2:3:*/111",
		"1::2:3:*/127",
		"1::2:3:*",
		"1::2:1-3:4:*",
		"1::2:3:*/31",
		"1::2:3:*/17",
		"1::2:003:4/17",
		"1::2:7:8/17",
		"1::2:003:4/15",
		"1::2:3:4/15",
		"1::2:003:4/16",
		"1::2:003:*/16",
		"0001:0000::0002:0003:0004/16",
		"1:f000::2/17",
		"a1:f000::2/17",
		"ffff::fffe:ffff:fffe",
		"ffff::fffe:ffff:ffff",
		"ffff::ffff:ffff:fffe",
		"*::*:*:*",//
		"*::*:%*:*",
		"ffff::ffff:ffff:ffff",
		"*:*:a:*:*:*:*:*",
		"*:*:a:*:*:*:*:*/16",
		"*:*",
		"*:*:*:*:*:*:*:*",
		"/33",
		"/64",
		"/128",
		"/32",
		"/24",
		"/0",
		"*",
		"**",
		" *",
		"%%",

		"1.2.*.*",
		"1.2.0.0/16",
		"000100400000-000100577777",
		"0x01020000-0x0102ffff",
		
		"1.*.*.*",
		"1.*.0.0/16",
		"1.*.0.0/12",
		"000100000000-000177777777",
		"0x01000000-0x01ffffff",

		"0.0.0.0",
		"000000000000",
		"0x00000000",

		"9.63.127.254",
		"001117677776",
		"0x093f7ffe",

		"9.63.*.*",
		"9.63.0.0/16",
		"001117600000-001117777777",
		"0x093f0000-0x093fffff",

		"9.*.*.*",
		"9.*.0.0/16",
		"001100000000-001177777777",
		"0x09000000-0x09ffffff",

		"000100401772-000100401777",
		"0x010203fa-0x010203ff",
		"1.2.3.250-255",

		"000100401710-000100401777",
		"0x010203c8-0x010203ff",
		"1.2.3.200-255",

		"000100401544-000100401707",
		"0x01020364-0x010203c7",
		"1.2.3.100-199",

		"100-199.2.3.100-199",

		"100-199.2.3.100-198",

		"000100401400-000100401543",
		"0x01020300-0x01020363",
		"1.2.3.0-99",

		"000100401544-000100401633",
		"0x01020364-0x0102039b",
		"1.2.3.100-155",

		"1.2.3.100-255",
		"000100401544-000100401777",
		"0x01020364-0x010203ff",

		"1.128-240.0.0/12",
		"1.128-255.*.*",
		"000140000000-000177777777",
		"0x01800000-0x01ffffff",

		"1.200-252.0.0/14",
		"1.200-255.*.*",
		"000162000000-000177777777",
		"0x01c80000-0x01ffffff",
		
		"000a:000b:000c:000d:000e:000f:000a:000b",
		"00|N0s0$ND2DCD&%D3QB",
		"0x000a000b000c000d000e000f000a000b",
		"a:b:c:d:e:f:0.10.0.11",
		"a:b:c:d:e:f:a:b",

		"a:b:c:d:*/64",
		"a:b:c:d:*:*:*:*/64",
		
		"000a:000b:000c:000d:0000:0000:0000:0000/64",
		"00|N0s0$ND2BxK96%Chk" + IPv6Address.ALTERNATIVE_RANGE_SEPARATOR + "00|N0s0$ND{&WM}~o9(k/64",
		"0x000a000b000c000d0000000000000000-0x000a000b000c000dffffffffffffffff",
		"a:b:c:d:*:*:*:*",
		"a:b:c:d:0:0:0:0/64",
		"a:b:c:d::/64",

		"0000001G~Ie?xF;x&)@P" + IPv6Address.ALTERNATIVE_RANGE_SEPARATOR + "0000001G~JZkWI!qp&GP/64",
		"0000:0000:000c:000d:0000:0000:0000:0000/64",
		"0x00000000000c000d0000000000000000-0x00000000000c000dffffffffffffffff",
		"0:0:c:d:*:*:*:*",
		"0:0:c:d:0:0:0:0/64",
		"0:0:c:d::/64",
		"::c:d:*:*:*:*",

		"0000001G~Ie^C9jXExx>",
		"0000:0000:000c:000d:000e:000f:000a:000b",
		"0:0:c:d:e:f:a:b",
		"0x00000000000c000d000e000f000a000b",
		"::c:d:e:f:0.10.0.11",
		"::c:d:e:f:a:b",

		"000a:000b:000c:000d:0000:0000:0000:0000",
		"00|N0s0$ND2BxK96%Chk",
		"0x000a000b000c000d0000000000000000",
		"a:b:c:d:0:0:0:0",
		"a:b:c:d::",

		"000a:000b:000c:000d:0000:0000:0000:0000/64",
		"00|N0s0$ND2BxK96%Chk" + IPv6Address.ALTERNATIVE_RANGE_SEPARATOR + "00|N0s0$ND{&WM}~o9(k/64",
		"0x000a000b000c000d0000000000000000-0x000a000b000c000dffffffffffffffff",
		"a:b:c:d:*:*:*:*",
		"a:b:c:d:0:0:0:0/64",
		"a:b:c:d::/64",

		"000a:0000:0000:000d:0000-8000:0000:0000:0000/65",
		"00|M>t|tt+WbKhfd5~qN" + IPv6Address.ALTERNATIVE_RANGE_SEPARATOR + "00|M>t|tt-R6^kVV>{?N/65",
		"0x000a00000000000d0000000000000000-0x000a00000000000dffffffffffffffff",
		"a:0:0:d:*:*:*:*",
		"a:0:0:d:*:0:0:0/65",
		"a:0:0:d:*::/65",
		"a::d:*:*:*:*",

		"000a:0000:0000:000d:0000-8000:0000:0000:0000/65",
		"00|M>t|tt+WbKhfd5~qN" + IPv6Address.ALTERNATIVE_RANGE_SEPARATOR + "00|M>t|tt-R6^kVV>{?N/65",
		"0x000a00000000000d0000000000000000-0x000a00000000000dffffffffffffffff",
		"a:0:0:d:*:*:*:*",
		"a:0:0:d:*:0:0:0/65",
		"a:0:0:d:*::/65",
		"a::d:*:*:*:*",

		"000a:000b:000c:0000-ffff:0000:0000:0000:0000/64",
		"00|N0s0$N0-%*(tF5l-X" + IPv6Address.ALTERNATIVE_RANGE_SEPARATOR + "00|N0s0;%a&*sUa#KSGX/64",
		"0x000a000b000c00000000000000000000-0x000a000b000cffffffffffffffffffff",
		"a:b:c:*:*:*:*:*",
		"a:b:c:*:0:0:0:0/64",
		"a:b:c:*::/64",

		"000a:000b:000c:000d:0000:0000:0000:0000/64",
		"00|N0s0$ND2BxK96%Chk" + IPv6Address.ALTERNATIVE_RANGE_SEPARATOR + "00|N0s0$ND{&WM}~o9(k/64",
		"0x000a000b000c000d0000000000000000-0x000a000b000c000dffffffffffffffff",
		"a:b:c:d:*:*:*:*",
		"a:b:c:d:0:0:0:0/64",
		"a:b:c:d::/64",

		"000a:0000:0000:0000:0000:0000:0000:0000/64",
		"00|M>t|ttwH6V62lVY`A" + IPv6Address.ALTERNATIVE_RANGE_SEPARATOR + "00|M>t|ttxBz48@eGWJA/64",
		"0x000a0000000000000000000000000000-0x000a000000000000ffffffffffffffff",
		"a:0:0:0:*:*:*:*",
		"a:0:0:0:0:0:0:0/64",
		"a::*:*:*:*",
		"a::/64",

		"000a:000b:000c:0000-ffff:0000-ffff:0000-ffff:0000-ffff:0000-ffff",
		"00|N0s0$N0-%*(tF5l-X" + IPv6Address.ALTERNATIVE_RANGE_SEPARATOR + "00|N0s0;%a&*sUa#KSGX",
		"0x000a000b000c00000000000000000000-0x000a000b000cffffffffffffffffffff",
		"a:b:c:*:*:*:*.*.*.*",
		"a:b:c:*:*:*:*:*",

		"000a:0000:0000:000d:000e:000f:0000:0000/112",
		"00|M>t|tt+WcwbECb*xq/112",
		"0x000a00000000000d000e000f00000000-0x000a00000000000d000e000f0000ffff",
		"a:0:0:d:e:f:0:*",
		"a:0:0:d:e:f:0:0/112",
		"a:0:0:d:e:f::/112",
		"a::d:e:f:0:*",
		"a::d:e:f:0:0/112",

		"000a:0000:000c:000d:000e:000f:0000:0000/112",
		"00|M>t};s?v~hFl`j3_$/112",
		"0x000a0000000c000d000e000f00000000-0x000a0000000c000d000e000f0000ffff",
		"a:0:c:d:e:f:0:*",
		"a:0:c:d:e:f:0:0/112",
		"a:0:c:d:e:f::/112",
		"a::c:d:e:f:0:*",

		"000a:0000:000c:000d:000e:000f:0000:0000/97",
		"00|M>t};s?v~hFl`j3_$/97",
		"0x000a0000000c000d000e000f00000000-0x000a0000000c000d000e000f7fffffff",
		"a:0:c:d:e:f:0-7fff:*",
		"a:0:c:d:e:f:0:0/97",
		"a:0:c:d:e:f::/97",
		"a::c:d:e:f:0-7fff:*",

		"000a:0000:000c:000d:000e:000f:0000:0000/96",
		"00|M>t};s?v~hFl`j3_$/96",
		"0x000a0000000c000d000e000f00000000-0x000a0000000c000d000e000fffffffff",
		"a:0:c:d:e:f:*:*",
		"a:0:c:d:e:f:0:0/96",
		"a:0:c:d:e:f::/96",
		"a::c:d:e:f:*:*",

		"000a:0000:000c:000d:000e:000f:0001:0000/112",
		"00|M>t};s?v~hFl`jD0%/112",
		"0x000a0000000c000d000e000f00010000-0x000a0000000c000d000e000f0001ffff",
		"a:0:c:d:e:f:1:*",
		"a:0:c:d:e:f:1:0/112",
		"a:0:c:d:e:f:1::/112",
		"a::c:d:e:f:0.1.0.0/112",
		"a::c:d:e:f:1:*",
		"a::c:d:e:f:1:0/112",

		"000a:0000:000c:000d:0000:0000:0001:0000/112",
		"00|M>t};s?v}5L>MDR^a/112",
		"0x000a0000000c000d0000000000010000-0x000a0000000c000d000000000001ffff",
		"a:0:c:d:0:0:1:*",
		"a:0:c:d:0:0:1:0/112",
		"a:0:c:d:0:0:1::/112",
		"a:0:c:d::0.1.0.0/112",
		"a:0:c:d::1:*",
		"a:0:c:d::1:0/112",

		"000a:0000:000c:000d:000e:000f:000a:0000/112",
		"00|M>t};s?v~hFl`k9s=/112",
		"0x000a0000000c000d000e000f000a0000-0x000a0000000c000d000e000f000affff",
		"a:0:c:d:e:f:a:*",
		"a:0:c:d:e:f:a:0/112",
		"a:0:c:d:e:f:a::/112",
		"a::c:d:e:f:0.10.0.0/112",
		"a::c:d:e:f:a:*",
		"a::c:d:e:f:a:0/112",

		"000a:0000:000c:000d:0000:0000:0000:0100/120",
		"00|M>t};s?v}5L>MDI>a/120",
		"0x000a0000000c000d0000000000000100-0x000a0000000c000d00000000000001ff",
		"a:0:c:d:0:0:0:100-1ff",
		"a:0:c:d:0:0:0:100/120",
		"a:0:c:d::0.0.1.0/120",
		"a:0:c:d::100-1ff",
		"a:0:c:d::100/120",

		"000a:000b:000c:000d:0000-ffff:0000-ffff:0000-ffff:0000-ffff",
		"00|N0s0$ND2BxK96%Chk" + IPv6Address.ALTERNATIVE_RANGE_SEPARATOR + "00|N0s0$ND{&WM}~o9(k",
		"0x000a000b000c000d0000000000000000-0x000a000b000c000dffffffffffffffff",
		"a:b:c:d:*:*:*.*.*.*",
		"a:b:c:d:*:*:*:*",

		"000a:000b:000c:000d:0000:0000:0000:0000/64",
		"00|N0s0$ND2BxK96%Chk" + IPv6Address.ALTERNATIVE_RANGE_SEPARATOR + "00|N0s0$ND{&WM}~o9(k/64",
		"0x000a000b000c000d0000000000000000-0x000a000b000c000dffffffffffffffff",
		"a:b:c:d:*:*:*:*",
		"a:b:c:d:0:0:0:0/64",
		"a:b:c:d::/64",

		"000a:0000:0000:0000:0000:000c:000d:0000-ffff",
		"00|M>t|ttwH6V6EEzblZ" + IPv6Address.ALTERNATIVE_RANGE_SEPARATOR + "00|M>t|ttwH6V6EEzkrZ",
		"0x000a0000000000000000000c000d0000-0x000a0000000000000000000c000dffff",
		"a:0:0:0:0:c:d:*",
		"a::c:0.13.*.*",
		"a::c:d:*",

		"000a:0000:0000:000d:0000-ffff:0000-ffff:0000-ffff:0000-ffff",
		"00|M>t|tt+WbKhfd5~qN" + IPv6Address.ALTERNATIVE_RANGE_SEPARATOR + "00|M>t|tt-R6^kVV>{?N",
		"0x000a00000000000d0000000000000000-0x000a00000000000dffffffffffffffff",
		"a:0:0:d:*:*:*:*",
		"a::d:*:*:*.*.*.*",
		"a::d:*:*:*:*",

		"000a:0000:0000:0000:0000:0000:0000:0000/64",
		"00|M>t|ttwH6V62lVY`A" + IPv6Address.ALTERNATIVE_RANGE_SEPARATOR + "00|M>t|ttxBz48@eGWJA/64",
		"0x000a0000000000000000000000000000-0x000a000000000000ffffffffffffffff",
		"a:0:0:0:*:*:*:*",
		"a:0:0:0:0:0:0:0/64",
		"a::*:*:*:*",
		"a::/64",

		"000a:0000:0000:000d:0000:0000:0000:0000/64",
		"00|M>t|tt+WbKhfd5~qN" + IPv6Address.ALTERNATIVE_RANGE_SEPARATOR + "00|M>t|tt-R6^kVV>{?N/64",
		"0x000a00000000000d0000000000000000-0x000a00000000000dffffffffffffffff",
		"a:0:0:d:*:*:*:*",
		"a:0:0:d:0:0:0:0/64",
		"a:0:0:d::/64",
		"a::d:*:*:*:*",

		"0001:0000:0000:0000:0000:0000:0000:0000/32",
		"008JOm8Mm5*yBppL!sg1" + IPv6Address.ALTERNATIVE_RANGE_SEPARATOR + "008JPeGE6kXzV|T&xr^1/32",
		"0x00010000000000000000000000000000-0x00010000ffffffffffffffffffffffff",
		"1:0:*:*:*:*:*:*",
		"1:0:0:0:0:0:0:0/32",
		"1::*:*:*:*:*:*",
		"1::/32",

		"0xff000000000000000000000000000000-0xffffffffffffffffffffffffffffffff",
		"=SN{mv>Qn+T=L9X}Vo30" + IPv6Address.ALTERNATIVE_RANGE_SEPARATOR + "=r54lj&NUUO~Hi%c2ym0/8",
		"ff00-ffff:*:*:*:*:*:*:*",
		"ff00:0000:0000:0000:0000:0000:0000:0000/8",
		"ff00:0:0:0:0:0:0:0/8",
		"ff00::/8",

		"0xffff0000000000000000000000000000-0xffff0000000000000000000000ffffff",
		"=q{+M|w0(OeO5^EGP660/104",
		"ffff:0000:0000:0000:0000:0000:0000:0000/104",
		"ffff:0:0:0:0:0:0-ff:*",
		"ffff:0:0:0:0:0:0:0/104",
		"ffff::/104",
		"ffff::0-ff:*",

		"0xffff0000000000000000000000000000-0xffff00000000000000000000000fffff",
		"=q{+M|w0(OeO5^EGP660/108",
		"ffff:0000:0000:0000:0000:0000:0000:0000/108",
		"ffff:0:0:0:0:0:0-f:*",
		"ffff:0:0:0:0:0:0:0/108",
		"ffff::/108",
		"ffff::0-f:*",

		"0xffff0000000000000000000010000000-0xffff00000000000000000000100fffff",
		"=q{+M|w0(OeO5^ELbE%G/108",
		"ffff:0000:0000:0000:0000:0000:1000:0000/108",
		"ffff:0:0:0:0:0:1000-100f:*",
		"ffff:0:0:0:0:0:1000:0/108",
		"ffff:0:0:0:0:0:1000::/108",
		"ffff::1000-100f:*",
		"ffff::1000:0/108",
		"ffff::16.0.0.0/108",

		"0xffff00000000000000000000a0000000-0xffff00000000000000000000a00fffff",
		"=q{+M|w0(OeO5^E(z82>/108",
		"ffff:0000:0000:0000:0000:0000:a000:0000/108",
		"ffff:0:0:0:0:0:a000-a00f:*",
		"ffff:0:0:0:0:0:a000:0/108",
		"ffff:0:0:0:0:0:a000::/108",
		"ffff::160.0.0.0/108",
		"ffff::a000-a00f:*",
		"ffff::a000:0/108",

		"0xffff00000000000000000000eee00000-0xffff00000000000000000000eeefffff",
		"=q{+M|w0(OeO5^F85=Cb/108",
		"ffff:0000:0000:0000:0000:0000:eee0:0000/108",
		"ffff:0:0:0:0:0:eee0-eeef:*",
		"ffff:0:0:0:0:0:eee0:0/108",
		"ffff:0:0:0:0:0:eee0::/108",
		"ffff::238.224.0.0/108",
		"ffff::eee0-eeef:*",
		"ffff::eee0:0/108",

		"0xffff0000000000000000000000000000-0xffff00000000000000000000001fffff",
		"=q{+M|w0(OeO5^EGP660/107",
		"ffff:0000:0000:0000:0000:0000:0000:0000/107",
		"ffff:0:0:0:0:0:0-1f:*",
		"ffff:0:0:0:0:0:0:0/107",
		"ffff::/107",
		"ffff::0-1f:*",

		"0xabcd0000000000000000000000000000-0xabcd00000000000000000000001fffff",
		"abcd:0000:0000:0000:0000:0000:0000:0000/107",
		"abcd:0:0:0:0:0:0-1f:*",
		"abcd:0:0:0:0:0:0:0/107",
		"abcd::/107",
		"abcd::0-1f:*",
		"o6)n`s#^$cP5&p^H}p=a/107",

		"0001:0002:0003:0004:0000:0000:0000:0000%:%:%",
		"008JQWOV7Skb)C|ve)jA" + IPv6Address.ALTERNATIVE_ZONE_SEPARATOR + ":%:%",
		"1:2:3:4:0:0:0:0%:%:%",
		"1:2:3:4::%:%:%",
		"0x00010002000300040000000000000000%:%:%",

		"0001:0002:0003:0004:0000:0000-ffff:0000-ffff:0000-ffff",
		"008JQWOV7Skb)C|ve)jA" + IPv6Address.ALTERNATIVE_RANGE_SEPARATOR + "008JQWOV7Skb?_P3;X#A",
		"1:2:3:4:0:*:*:*",
		"1:2:3:4::*:*.*.*.*",
		"1:2:3:4::*:*:*",
		"0x00010002000300040000000000000000-0x00010002000300040000ffffffffffff",

		"0001:0002:0003:0004:0000:0000:0000:0000/80",
		"008JQWOV7Skb)C|ve)jA/80",
		"0x00010002000300040000000000000000-0x00010002000300040000ffffffffffff",
		"1:2:3:4:0:*:*:*",
		"1:2:3:4:0:0:0:0/80",
		"1:2:3:4::*:*:*",
		"1:2:3:4::/80",

		"0001:0002:0003:0004:0000:0000:0000:0000",
		"008JQWOV7Skb)C|ve)jA",
		"0x00010002000300040000000000000000",
		"1:2:3:4:0:0:0:0",
		"1:2:3:4::",

		"0001:0002:0003:0004:0000:0006:0000:0000",
		"008JQWOV7Skb)D3fCrWG",
		"0x00010002000300040000000600000000",
		"1:2:3:4:0:6:0:0",
		"1:2:3:4:0:6::",

		"0001:0002:0003:0000:0000:0006:0000:0000",
		"008JQWOV7O(=61h*;$LC",
		"0x00010002000300000000000600000000",
		"1:2:3:0:0:6:0:0",
		"1:2:3:0:0:6::",
		"1:2:3::6:0:0",

		"0x108000000000000000080800200c417a",
		"1080:0000:0000:0000:0008:0800:200c:417a",
		"1080:0:0:0:8:800:200c:417a",
		"1080::8:800:200c:417a",
		"1080::8:800:32.12.65.122",
		"4)+k&C#VzJ4br>0wv%Yp",

		"0000:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
		"008JOm8Mm5*yBppL!sg0",
		"0:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
		"0x0000ffffffffffffffffffffffffffff",
		"::ffff:ffff:ffff:ffff:ffff:255.255.255.255",
		"::ffff:ffff:ffff:ffff:ffff:ffff:ffff",

		"=r54lj&NUUO~Hi%c2ym0",
		"ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255",
		"0xffffffffffffffffffffffffffffffff",
		"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"
	};
	
	private static final IPAddressStringParameters DEFAULT_OPTIONS = new IPAddressStringParameters.Builder().toParams();
	
	IPAddressAllTest(AddressCreator creator) {
		super(creator);
	}
	
	@Override
	protected IPAddressString createInetAtonAddress(String x) {
		return createAddress(x);
	}
	
	@Override
	protected IPAddressString createAddress(String x) {
		return createAddress(x, DEFAULT_OPTIONS);
	}

	@Override
	boolean isLenient() {
		return true;
	}
	
	@Override
	void testStrings() {
		super.testStrings();
		
		testMatches(true, "aaaabbbbccccddddeeeeffffaaaabbbb", "aaaa:bbbb:cccc:dddd:eeee:ffff:aaaa:bbbb");
		testMatches(true, "4)+k&C#VzJ4br>0wv%Yp", "1080::8:800:200c:417a");
		testMatches(true, "=r54lj&NUUO~Hi%c2ym0", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff");
		testMatches(true, "aaaabbbbccccdddd0000000000000000-aaaabbbbcccccdddffffffffffffffff", "aaaa:bbbb:cccc:cddd-dddd:*:*:*:*");
		testMatches(true, "=r54lj&NUUO~Hi%c2yl0" + IPv6Address.ALTERNATIVE_RANGE_SEPARATOR + "=r54lj&NUUO~Hi%c2ym0", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffaa-ffff");

		
		//It is good to have at least one base 85 input test, since we have code that caches base 85 input strings for output
		testIPv6Strings("4)+k&C#VzJ4br>0wv%Yp",
				"1080:0:0:0:8:800:200c:417a", //normalized
				"1080:0:0:0:8:800:200c:417a", //normalizedWildcards
				"1080::8:800:200c:417a", //canonicalWildcards
				"1080:0:0:0:8:800:200c:417a", //sql
				"1080:0000:0000:0000:0008:0800:200c:417a",
				"1080::8:800:200c:417a",//compressed
				"1080::8:800:200c:417a",
				"1080::8:800:200c:417a",//subnet
				"1080::8:800:200c:417a",//compressedWildcard
				"1080::8:800:32.12.65.122",//mixed no compress
				"1080::8:800:32.12.65.122",//mixedNoCompressHost
				"1080::8:800:32.12.65.122",
				"1080::8:800:32.12.65.122",
				"a.7.1.4.c.0.0.2.0.0.8.0.8.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.0.1.ip6.arpa",
				"1080-0-0-0-8-800-200c-417a.ipv6-literal.net",
				"4)+k&C#VzJ4br>0wv%Yp",
				"0x108000000000000000080800200c417a",
				"00204000000000000000000000100200004003040572");
		
		testIPv6Strings("008JOm8Mm5*yBppL!sg0",
				"0:ffff:ffff:ffff:ffff:ffff:ffff:ffff", //normalized
				"0:ffff:ffff:ffff:ffff:ffff:ffff:ffff", //normalizedWildcards
				"0:ffff:ffff:ffff:ffff:ffff:ffff:ffff", //canonicalWildcards
				"0:ffff:ffff:ffff:ffff:ffff:ffff:ffff", //sql
				"0000:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
				"::ffff:ffff:ffff:ffff:ffff:ffff:ffff",//compressed
				"0:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
				"::ffff:ffff:ffff:ffff:ffff:ffff:ffff",//subnet
				"::ffff:ffff:ffff:ffff:ffff:ffff:ffff",//compressedWildcard
				"::ffff:ffff:ffff:ffff:ffff:255.255.255.255",//mixed no compress
				"::ffff:ffff:ffff:ffff:ffff:255.255.255.255",//mixedNoCompressHost
				"::ffff:ffff:ffff:ffff:ffff:255.255.255.255", 
				"::ffff:ffff:ffff:ffff:ffff:255.255.255.255",
				"f.f.f.f.f.f.f.f.f.f.f.f.f.f.f.f.f.f.f.f.f.f.f.f.f.f.f.f.0.0.0.0.ip6.arpa",
				"0-ffff-ffff-ffff-ffff-ffff-ffff-ffff.ipv6-literal.net",
				"008JOm8Mm5*yBppL!sg0",
				"0x0000ffffffffffffffffffffffffffff",
				"00000017777777777777777777777777777777777777");
		
		testIPv6Strings("=r54lj&NUUO~Hi%c2ym0",
				"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", //normalized
				"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", //normalizedWildcards
				"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", //canonicalWildcards
				"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", //sql
				"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
				"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",//compressed
				"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
				"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",//subnet
				"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",//compressedWildcard
				"ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255",//mixed no compress
				"ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255",//mixedNoCompressHost
				"ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255",
				"ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255",
				"f.f.f.f.f.f.f.f.f.f.f.f.f.f.f.f.f.f.f.f.f.f.f.f.f.f.f.f.f.f.f.f.ip6.arpa",
				"ffff-ffff-ffff-ffff-ffff-ffff-ffff-ffff.ipv6-literal.net",
				"=r54lj&NUUO~Hi%c2ym0",
				"0xffffffffffffffffffffffffffffffff",
				"03777777777777777777777777777777777777777777");
	}

	/*
	 * (non-Javadoc)
	 * @see inet.ipaddr.test.IPAddressRangeTest#createList(inet.ipaddr.IPAddressString)
	 */
	@Override
	void createList(IPAddressString str) {
		IPAddress ipAddr = str.getAddress();
		String c = ipAddr.toCompressedString();
		String canonical = ipAddr.toCanonicalString();
		String s = ipAddr.toSubnetString();
		String cidr = ipAddr.toPrefixLengthString();
		String n = ipAddr.toNormalizedString();
		String nw = ipAddr.toNormalizedWildcardString();
		String caw = ipAddr.toCanonicalWildcardString();
		String cw = ipAddr.toCompressedWildcardString();
		
		TreeSet<String> set = new TreeSet<String>();
		set.add(c);
		set.add(canonical);
		set.add(s);
		set.add(cidr);
		set.add(n);
		set.add(nw);
		set.add(cw);
		set.add(caw);

		try {
			String hex = ipAddr.toHexString(true);
			set.add(hex);
		} catch(IncompatibleAddressException e) {}
		
		if(ipAddr.isIPv4()) {
			try {
				String octal = ipAddr.toOctalString(true);
				set.add(octal);
			} catch(IncompatibleAddressException e) {}
		}
//		System.out.println(c);
//		System.out.println(canonical);
//		System.out.println(s);
//		System.out.println(cidr);
//		System.out.println(n);
//		System.out.println(nw);
//		System.out.println(caw);
//		System.out.println(cw);
		if(ipAddr.isIPv6()) {
			String full = ipAddr.toFullString();
			String base85 = ipAddr.toIPv6().toBase85String();
			String m = ipAddr.toIPv6().toMixedString();
//			System.out.println(full);
//			System.out.println(base85);
//			System.out.println(m);
			set.add(full);
			set.add(base85);
			set.add(m);
		}
		for(String string : set) {
			System.out.println('"' + string + "\",");
		}
		System.out.println();
	}
	
	void testCaches(Map<String, IPAddressString> map, boolean testSize, boolean useBytes) {
		IPAddressStringGenerator cache = new IPAddressStringGenerator(map);
		testCache(ADDRESS_SAMPLING, cache, str -> createAddress(str), testSize, useBytes);
	}
	
	void testAllContains(String cidr1, String cidr2, boolean result) {
		testAllContains(cidr1, cidr2, result, false);
	}

	void testAllContains(String cidr1, String cidr2, boolean result, boolean equal) {
		IPAddressString wstr = createAddress(cidr1);
		IPAddressString w2str = createAddress(cidr2);
		
		testStringContains(result, equal, wstr, w2str);

		incrementTestCount();
	}
	
	@Override
	void runTest() {
		super.runTest();
		testNormalized("aaaabbbbcccccddd0000000000000000-aaaabbbbccccddddffffffffffffffff", "aaaa:bbbb:cccc:cddd-dddd:*:*:*:*");
		testCanonical("aaaabbbbcccccddd0000000000000000-aaaabbbbccccddddffffffffffffffff", "aaaa:bbbb:cccc:cddd-dddd:*:*:*:*");
		testCaches(new TreeMap<String, IPAddressString>(), true, true);
		testCaches(new HashMap<String, IPAddressString>(), true, true);
		testCaches(new TreeMap<String, IPAddressString>(), true, false);
		testCaches(new HashMap<String, IPAddressString>(), true, false);
		ConcurrentHashMap<String, IPAddressString> map = new ConcurrentHashMap<String, IPAddressString>();
		HostAllTest.testCachesSync(new Runnable() {
			@Override
			public void run() {
				testCaches(map, false, false);
			}
		});
		testAllContains("*", "1:2:3:4:1:2:3:4", true);
		testAllContains("*", "1.2.3.4.5", false);
		testAllContains("*", "1.2.3.4", true);
		testAllContains("*/64", "1.2.3.4", false);
		testAllContains("*.*", "1::", false);
		testAllContains("*:*", "1::", true);
		testAllContains("*:*", "1.2.3.4", false);
		testAllContains("*.*", "1.2.3.4", true);
		testAllContains("*/64", "::", true);
	}
}
