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

import inet.ipaddr.AddressStringParameters.RangeParameters;
import inet.ipaddr.HostName;
import inet.ipaddr.HostNameParameters;
import inet.ipaddr.IPAddress;
import inet.ipaddr.IPAddressString;
import inet.ipaddr.IPAddressStringParameters;

public class HostRangeTest extends HostTest {

	private static final HostNameParameters HOST_ONLY_OPTIONS = HOST_OPTIONS.toBuilder().allowIPAddress(false).toParams();
	
	private static final HostNameParameters HOST_WILDCARD_OPTIONS = HOST_OPTIONS.toBuilder().getAddressOptionsBuilder().
			allowAll(true).setRangeOptions(RangeParameters.WILDCARD_ONLY).getParentBuilder().toParams();

	private static final HostNameParameters HOST_WILDCARD_AND_RANGE_OPTIONS = HOST_WILDCARD_OPTIONS.toBuilder().getAddressOptionsBuilder().
			setRangeOptions(RangeParameters.WILDCARD_AND_RANGE).getParentBuilder().toParams();

	private static final HostNameParameters HOST_WILDCARD_AND_RANGE_INET_ATON_OPTIONS = HOST_WILDCARD_OPTIONS.toBuilder().getAddressOptionsBuilder().
			setRangeOptions(RangeParameters.WILDCARD_AND_RANGE).allow_inet_aton(true).getParentBuilder().toParams();

	private static final IPAddressStringParameters ADDRESS_WILDCARD_OPTIONS = ADDRESS_OPTIONS.toBuilder().allowAll(true).setRangeOptions(RangeParameters.WILDCARD_ONLY).toParams();
	
	HostRangeTest(AddressCreator creator) {
		super(creator);
	}
	
	@Override
	protected HostName createHost_inet_aton(String x) {
		HostKey key = new HostKey(x, HOST_INET_ATON_WILDCARD_AND_RANGE_OPTIONS);
		return createHost(key);
	}

	@Override
	protected HostName createHost(String x) {
		HostKey key = new HostKey(x, HOST_WILDCARD_OPTIONS);
		return createHost(key);
	}

	@Override
	void testMatches(boolean matches, String host1, String host2) {
		testMatches(matches, host1, host2, HOST_WILDCARD_OPTIONS);
	}
	
	@Override
	protected IPAddressString createAddress(String x) {
		IPAddressStringKey key = new IPAddressStringKey(x, ADDRESS_WILDCARD_OPTIONS);
		return createAddress(key);
	}
	
	private void testHostAndAddress(HostName h, int hostLabelCount, int addressLabelCount, boolean isValidHost, boolean isValidAddress, String normalizedHostString, String normalizedAddressString) {
		if(h.isValid() != isValidHost) {
			addFailure(new Failure("unexpected invalid host", h));
		} else if(h.getNormalizedLabels().length != (isValidAddress ? addressLabelCount : (isValidHost ? hostLabelCount : 1))) {
			addFailure(new Failure("labels length is " + h.getNormalizedLabels().length + " expected " + (isValidAddress ? addressLabelCount : (isValidHost ? hostLabelCount : 1)), h));
		} else {
			IPAddress addr = h.asAddress();
			if(isValidAddress != h.isAddress()) {
				addFailure(new Failure("not address " + addr, h));
			} else if(isValidAddress != (addr != null)) {
				addFailure(new Failure("addr is " + addr, h));
			} else if(isValidAddress && !addr.toNormalizedString().equals(normalizedAddressString)) {
				addFailure(new Failure("addr string is " + addr.toNormalizedString() + " expected " + normalizedAddressString, h));
			} else {
				String nhString = h.toNormalizedString();
				String expected;
				if(h.isAddress() && addr.isIPv6()) {
					expected = isValidHost ? normalizedHostString : h.toString();
				} else {
					expected = isValidAddress ? normalizedAddressString : (isValidHost ? normalizedHostString : h.toString());
				}
				if (!nhString.equals(expected)) {
					addFailure(new Failure("host string is " + nhString + " expected " + expected, h));
				}
			}
		}
		incrementTestCount();
	}
	
	private void testHostOrAddress_inet_aton(String x, int hostLabelCount, int addressLabelCount, String normalizedHostString, String normalizedAddressString) {
		testHostAndAddress(x, hostLabelCount, addressLabelCount, true, false, false, true, normalizedHostString, normalizedAddressString);
	}
	
	private void testHostOrRangeAddress(String x, int labelCount, String normalizedHostString, String normalizedAddressString) {
		testHostAndAddress(x, labelCount, labelCount, true, false, true, true, normalizedHostString, normalizedAddressString);
	}
	
	private void testHostOrWildcardAddress(String x, int labelCount, String normalizedHostString, String normalizedAddressString) {
		testHostAndAddress(x, labelCount, labelCount, true, true, true, true, normalizedHostString, normalizedAddressString);
	}
	
	private void testAddress(String x, int labelCount, String normalizedHostString, String normalizedAddressString) {
		testHostAndAddress(x, labelCount, labelCount, false, true, true, true, normalizedHostString, normalizedAddressString);
	}
	
	private void testHostOnly(String x, int labelCount, String normalizedHostString, String normalizedAddressString) {
		testHostAndAddress(x, labelCount, labelCount, true, false, false, false, normalizedHostString, normalizedAddressString);
	}
	
	private void testHostAndAddress(String x, int hostLabelCount, int addressLabelCount, boolean isHostName, boolean isAddressNotRanged, boolean isRangeAddress,
			boolean is_inet_aton_RangeAddress, 
			String normalizedHostString, String normalizedAddressString) {
		//we want to handle 4 cases
		//1. a.b.com host only
		//2. 1:: address
		//3. a-b.c__ either way inet_aton
		//4. a-b.c__.3.4 either way
		
		HostName h = createHost(x, HOST_ONLY_OPTIONS);
		testHostAndAddress(h, hostLabelCount, addressLabelCount, isHostName, false, normalizedHostString, normalizedAddressString);
		
		boolean isAddress = isAddressNotRanged;
		h = createHost(x, HOST_WILDCARD_OPTIONS);
		testHostAndAddress(h, hostLabelCount, addressLabelCount, isHostName || isAddress, isAddress, normalizedHostString, normalizedAddressString);
		
		isAddress = isAddressNotRanged || isRangeAddress;
		h = createHost(x, HOST_WILDCARD_AND_RANGE_OPTIONS);
		testHostAndAddress(h, hostLabelCount, addressLabelCount, isHostName || isAddress, isAddress, normalizedHostString, normalizedAddressString);
		
		isAddress = isAddressNotRanged || isRangeAddress || is_inet_aton_RangeAddress;
		h = createHost(x, HOST_WILDCARD_AND_RANGE_INET_ATON_OPTIONS);
		testHostAndAddress(h, hostLabelCount, addressLabelCount, isHostName || isAddress, isAddress, normalizedHostString, normalizedAddressString);
	}
	
	@Override
	void runTest()
	{
		testResolved("a::b:*:d:1.2.*%x", "a::b:*:d:1.2.*%x");
		testResolved("[a::b:*:d:1.2.*%x]", "a::b:*:d:1.2.*%x");
		testResolved("[a::*:c:d:1.*.3.4]", "a::*:c:d:1.*.3.4");
		testResolved("2001:0000:1234:0000:*:C1C0:ABCD:0876%x", "2001:0:1234:0:*:c1c0:abcd:876%x");
		testResolved("[2001:*:1234:0000:0000:C1C0:ABCD:0876%x]", "2001:*:1234::C1C0:abcd:876%x");
		testResolved("[2001:0000:*:0000:0000:C1C0:ABCD:0876]", "2001:0:*::C1C0:abcd:876");
		testResolved("2001:0000:*:0000:0000:C1C0:ABCD:0876", "2001:0:*::C1C0:abcd:876");
		testResolved("1.2.*.04", "1.2.*.4");
		testResolved("1.*.0-255.3", "1.*.*.3");
		testResolved("1.*.3", "1.*.0.3");
		testResolved("[1.2.*.4]", "1.2.*.4");
		
		testResolved("espn.*.com", null);//no wildcards for hosts, just addresses
		testResolved("*.instapundit.com", null);
		testResolved("es*n.com", null);
		testResolved("inst*undit.com", null);
		
		if(fullTest && runDNS) {
			testResolved("espn.com/24", "199.181.132.*");
		}
		
		testResolved("3*", null);
		testResolved("*", "*");
		testResolved("3.*", "3.*.*.*");
		testResolved("3:*", "3:*:*:*:*:*:*:*");
		testResolved("9.*.237.26", "9.*.237.26");
		testResolved("*.70.146.*", "*.70.146.*");
		
		hostTest(true, "1.2.3.4/1.2.3.4");
		hostTest(false, "1.2.3.4/*");
		hostTest(false, "1.*.3.4/*");
		hostTest(true, "1.*.3.4");
		hostTest(true, "1:*:3:4");
		
		hostLabelsTest("*", new String[] {"*"});
		hostLabelsTest("**", new String[] {"*"});
		
		testHostOrWildcardAddress("1_.2.3.4", 4, "1_.2.3.4", "10-19.2.3.4");
		testHostOrRangeAddress("1-2.2.3.4", 4, "1-2.2.3.4", "1-2.2.3.4");
		testHostOrAddress_inet_aton("1-9.1-2", 2, 4, "1-9.1-2", "1-9.0.0.1-2");
		testHostOrAddress_inet_aton("1-9.0x1-0x22", 2, 4, "1-9.0x1-0x22", "1-9.0.0.1-34");
		testHostOnly("9-1.0x1-0x22", 2, "9-1.0x1-0x22", null);
		testHostOrAddress_inet_aton("1-9.0x1-0x22.03.04", 4, 4, "1-9.0x1-0x22.03.04", "1-9.1-34.3.4");
		testAddress("1::2", 8, "[1:0:0:0:0:0:0:2]", "1:0:0:0:0:0:0:2");
		testAddress("1.2.3.4", 4, "1.2.3.4", "1.2.3.4");
		
		boolean allPrefixesAreSubnets = prefixConfiguration.allPrefixedAddressesAreSubnets();
		boolean isNoAutoSubnets = prefixConfiguration.prefixedSubnetsAreExplicit();
		
		testMatches(!isNoAutoSubnets, "1.*.*.*/255.0.0.0", "1.0.0.0/255.0.0.0");
		testMatches(true, "1.0.0.0/8", "1.0.0.0/255.0.0.0");

		if(allPrefixesAreSubnets) {
			testMatches(true, "1.2.3.4/255.0.0.0", "1.*.*.*");
			testMatches(true, "1.2.3.4/255.0.0.0", "1.*.___.*");
			testMatches(true, "1.2.3.4/255.0.0.0", "1.0-255.*.*", HOST_WILDCARD_AND_RANGE_OPTIONS);
		} else {
			testMatches(true, "1.2.3.4/255.0.0.0", "1.2.3.4");
			testMatches(true, "1.2.3.4/255.0.0.0", "1.2.3.4");
			testMatches(true, "1.2.3.4/255.0.0.0", "1.2.3.4");
		}
		testMatches(true, "1.0.0.0/255.0.0.0", isNoAutoSubnets ? "1.0.0.0" : "1.*.*.*");
		testMatches(true, "1.0.0.0/255.0.0.0", isNoAutoSubnets ? "1.0.0.0" : "1.*.___.*");
		testMatches(false, "1.0.0.0/255.0.0.0", "1.0-255.*.*");//failing due to the options
		testMatches(true, "1.0.0.0/255.0.0.0", isNoAutoSubnets ? "1.0.0.0" : "1.0-255.*.*", HOST_WILDCARD_AND_RANGE_OPTIONS);
		
		testMatches(true, "1-2.0-0.00-00.00-0", "1-2.0.0.0", HOST_WILDCARD_AND_RANGE_OPTIONS);
		testMatches(true, "1-2:0-0:00-00:00-0:0-000:0000-0000:0000-00:0000-0", "1-2:0:0:0:0:0:0:0", HOST_WILDCARD_AND_RANGE_OPTIONS);
		testMatches(true, "00-0.0-0.00-00.00-0", "0.0.0.0", HOST_WILDCARD_AND_RANGE_OPTIONS);
		testMatches(true, "0-00:0-0:00-00:00-0:0-000:0000-0000:0000-00:0000-0", "::", HOST_WILDCARD_AND_RANGE_OPTIONS);
		
		super.runTest();
	}
}