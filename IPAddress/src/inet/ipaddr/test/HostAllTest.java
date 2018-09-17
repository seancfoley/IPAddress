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
import java.util.concurrent.ConcurrentHashMap;

import inet.ipaddr.HostName;
import inet.ipaddr.HostNameParameters;
import inet.ipaddr.IPAddressNetwork.HostNameGenerator;
import inet.ipaddr.IPAddressString;
import inet.ipaddr.IPAddressStringParameters;

public class HostAllTest extends HostRangeTest {
	
	static String HOST_SAMPLING[] = {
	 	"1.2.3.4",
		"1::",
		"[1::]",
		"bla.com",
		"::1",
		"[::1]",
		"localhost",
		"127.0.0.1",
		"[127.0.0.1]",
		"[localhost]",//square brackets are for ipv6
		"-ab-.com",
		"A.cOm",
		"a.comx",
		"a.com",
		"2::",
		"1:0::",
		"f::",
		"F:0::",
		"[1:0::]",
		"1:0:1::",
		"001.2.3.04",
		"::ffff:1.2.3.4",//ipv4 mapped
		"1:2:3:4:5:6:1.2.3.4%a",
		"1:2:3:4:5:6:102:304%a",
		"1:2:3:4:5:6:1.2.3.4%",
		"1:2:3:4:5:6:102:304%",
		"1:2:3:4:5:6:1.2.3.4%%",
		"1:2:3:4:5:6:102:304%%",
		"1:2:3:4:5:6:1.2.3.4/1:2:3:4:5:6:1.2.3.4",
		"1:2:3:4:5:6:1.2.3.4",
		"1:2:3:4:5:6:1.2.3.4/1:2:3:4:5:6:0.0.0.0",
		"1:2:3:4:5:6::",
		"1:2:3:4:5:6:1.2.3.4/1:2:3:4:5:0:0.0.0.0",
		"1:2:3:4:5::",
		"[1:2:3:4:5:6::%y]",
		"1:2:3:4:5:6::%y",
		"[1:2:3:4:5:6::%25y]",
		"1:2:3:4:5:6::%y",//see rfc 6874 about %25
		"[1:2:3:4:5:6::]/32",
		"1:2:3:4:5:6::/32",
		"1.2.3.4/255.0.0.0",
		"1.0.0.0/255.0.0.0",
		
		"[IPv6:1:2:3:4:5:6:7:8%y]",
		"1:2:3:4:5:6:7:8%y",
		"[IPv6:1:2:3:4:5:6:7:8]",
		"1:2:3:4:5:6:7:8",
		"[IPv6:1:2:3:4:5:6::]/32",
		"1:2:3:4:5:6::/32",
		"[IPv6:::1]",
		"[IPv6:1::]",
		
		"a::b:c:d:1.2.3.4%x",
		"a::b:c:d:1.2.3.4%x",
		"[a::b:c:d:1.2.3.4%x]",
		"a::b:c:d:1.2.3.4%x",
		"[a::b:c:d:1.2.3.4]",
		"a::b:c:d:1.2.3.4",
		"2001:0000:1234:0000:0000:C1C0:ABCD:0876%x",
		"2001:0:1234::c1c0:abcd:876%x",
		"[2001:0000:1234:0000:0000:C1C0:ABCD:0876%x]",
		"2001:0:1234::c1c0:abcd:876%x",
		"[2001:0000:1234:0000:0000:C1C0:ABCD:0876]",
		"2001:0:1234::C1C0:abcd:876",
		"2001:0000:1234:0000:0000:C1C0:ABCD:0876",
		"2001:0:1234::C1C0:abcd:876",
		"1.2.3.04",
		"1.2.3",
		"[1.2.3.4]",

		"espn.com",
		"espn.com/24",
		"instapundit.com",

		"[A::b:c:d:1.2.03.4]",
		"[a:0:0:b:c:d:102:304]", //square brackets can enclose ipv6 in host names but not addresses
		"[2001:0000:1234:0000:0000:C1C0:ABCD:0876]",
		"[2001:0:1234:0:0:c1c0:abcd:876]", //square brackets can enclose ipv6 in host names but not addresses
		
		"[A:0::c:d:1.2.03.4]",
		"a::c:d:102:304", //square brackets can enclose ipv6 in host names but not addresses
		"[2001:0000:1234:0000:0000:C1C0:ABCD:0876]",
		"2001:0:1234::c1c0:abcd:876", //square brackets can enclose ipv6 in host names but not addresses
		
		"WWW.ABC.COM",
		"www.abc.com",
		"WWW.AB-C.COM",
		"www.ab-c.com",

		"one.two.three.four.five.six.seven.EIGHT",
		"one.two.three.four.fIVE.sIX.seven",
		"one.two.THREE.four.five.six",
		"one.two.three.four.five",
		"one.two.three.four",
		"one.Two.three",
		"onE.two",
		"one",
		"",
		" ",
		"1:2:3:4:5:6:7:8",
		"[::]",
		"::",
		
	 	"aa-bb-cc-dd-ee-ff-aaaa-bbbb.ipv6-literal.net",
	 	"aa:bb:cc:dd:ee:ff:aaaa:bbbb",
		"aa-bb-cc-dd-ee-ff-aaaa-bbbbseth0.ipv6-literal.net",
		"aa:bb:cc:dd:ee:ff:aaaa:bbbb",
		"aa-bb-cc-dd-ee-ff.ipv6-literal.net", //not a valid address, too few segments
		"aa-Bb-cc-dd-ee-FF.ipv6-literal.net", 
		"aa-bb-cc-dd-ee-ff.ipv6-literal.net",//not a valid address, too few segments
		"aa-bb-cc-dd-ee-ff-aaaa-bbb.ipv6-literal.net",
		"aa:bb:cc:dd:ee:ff:aaaa:bbb",
		"aa-Bb-cc-dd-ee-FF-aaaa-bbb.ipv6-literal.net",
		"aa:bb:cc:dd:ee:ff:aaaa:bbb",
		"f.f.f.f.e.e.0.0.d.d.d.d.c.c.c.c.b.b.b.b.a.a.a.a.b.b.b.b.c.c.c.c.ip6.arpa",
		"cccc:bbbb:aaaa:bbbb:cccc:dddd:ee:ffff",
		"f.f.f.f.e.e.0.0.d.d.d.d.c.c.c.c.b.b.b.b.a.a.a.a.b.b.b.b.c.c.c.c.ip6.int",
		"cccc:bbbb:aaaa:bbbb:cccc:dddd:ee:ffff",
		"f.f.f.f.e.e.0.0.d.d.d.d.c.c.c.c.b.b.b.b.a.a.a.a.b.b.b.b.c.c.c.c.ip6.int:45",
		"cccc:bbbb:aaaa:bbbb:cccc:dddd:ee:ffff",
		"F.f.f.F.e.e.0.0.d.D.d.d.c.c.c.c.b.b.b.b.a.a.a.a.b.b.b.b.c.c.c.C.ip6.int:45",
		"cccc:bbbb:aaaa:bbbb:cccc:dddd:ee:ffff",
		"f.F.f.f.F.e.e.0.0.d.D.d.d.c.c.c.c.b.b.b.b.a.a.a.a.b.b.b.b.c.c.c.C.ip6.int:45",
		"f.f.f.f.f.e.e.0.0.d.d.d.d.c.c.c.c.b.b.b.b.a.a.a.a.b.b.b.b.c.c.c.c.ip6.int", //not a valid address
		"255.22.2.111.in-addr.arpa",
		"111.2.22.255",
		"255.22.2.111.in-addr.arpa:35",
		"111.2.22.255",
		"255.22.2.111.3.in-addr.arpa:35",
		"255.22.2.111.3.in-addr.arpa",
		"1.2.2.1:33",
		"1.2.2.1",
		"[::1]:33",
		"0:0:0:0:0:0:0:1",
		"::1:33",
		"0:0:0:0:0:0:1:33",
		"::1%eth0",
		"0:0:0:0:0:0:0:1",
		"[::1%eth0]:33",
		"0:0:0:0:0:0:0:1",
		"bla.bla:33",
		"bla.bla",
		"blA:33", 
		"bla",
		"f:33",
		"f",
		"f::33",
		"f:0:0:0:0:0:0:33",
		"::1",
		"0:0:0:0:0:0:0:1",
		"[::1]",
		"0:0:0:0:0:0:0:1",
		"/16",
		"/32",
		"/64",
		"ffff:ffff:ffff:ffff:*:*:*:*",
		"ffff:ffff:ffff:ffff:0:0:0:0/64",
		"123-123456789-123456789-123456789-123456789-123456789-123456789.com", //label 63 chars
		"aaa.123456789.123456789.123456789.123456789.123456789.123456789.123", //numbers everywhere but first label
		"1234-123456789-123456789-123456789-123456789-123456789-123456789.com", //label 64 chars  which is too long
		"123.123456789.123456789.123456789.123456789.123456789.123456789.123", //not valid host
		"-ab-.com",
		"ab-.com",
		"-ab.com",
		"ab.-com",
		"ab.com-"
	};
		
	
	private static final HostNameParameters HOST_ALL_OPTIONS = new HostNameParameters.Builder().toParams();
	private static final IPAddressStringParameters DEFAULT_OPTIONS = new IPAddressStringParameters.Builder().toParams();
			
	HostAllTest(AddressCreator creator) {
		super(creator);
	}
	
	@Override
	boolean isLenient() {
		return true;
	}
	
	@Override
	protected HostName createHost_inet_aton(String x) {
		HostKey key = new HostKey(x, HOST_ALL_OPTIONS);
		return createHost(key);
	}
	
	@Override
	protected HostName createHost(String x) {
		HostKey key = new HostKey(x, HOST_ALL_OPTIONS);
		return createHost(key);
	}

	@Override
	void testMatches(boolean matches, String host1, String host2) {
		testMatches(matches, host1, host2, HOST_ALL_OPTIONS);
	}

	@Override
	protected IPAddressString createAddress(String x) {
		IPAddressStringKey key = new IPAddressStringKey(x, DEFAULT_OPTIONS);
		return createAddress(key);
	}

	@Override
	protected IPAddressString createInetAtonAddress(String x) {
		return createAddress(x);
	}

	void testCaches(Map<String, HostName> map, boolean testSize, boolean useBytes) {
		HostNameGenerator cache2 = new HostNameGenerator(map);
		testCache(HOST_SAMPLING, cache2, str -> createHost(str), testSize, useBytes);
	}
	
	static void testCachesSync(Runnable runnable) {
		Thread threads[] = new Thread[10];
		for(int i = 0; i < threads.length; i++) {
			threads[i] = new Thread(runnable);
		}
		for(Thread thread : threads) {
			thread.start();
		}
		for(Thread thread : threads) {
			try {
				thread.join();
			} catch (InterruptedException e) {
				e.printStackTrace();
			}
		}
	}
	
	@Override
	void runTest() {
		super.runTest();
		testCaches(new TreeMap<String, HostName>(), true, false);
		testCaches(new HashMap<String, HostName>(), true, false);
		ConcurrentHashMap<String, HostName> map = new ConcurrentHashMap<String, HostName>();
		testCachesSync(new Runnable() {
			@Override
			public void run() {
				testCaches(map, false, false);
			}
		});
	}
}
