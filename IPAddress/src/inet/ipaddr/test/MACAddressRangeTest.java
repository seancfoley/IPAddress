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

import inet.ipaddr.AddressNetwork.PrefixConfiguration;
import inet.ipaddr.AddressStringException;
import inet.ipaddr.AddressStringParameters.RangeParameters;
import inet.ipaddr.IPAddress;
import inet.ipaddr.IPAddressString;
import inet.ipaddr.IncompatibleAddressException;
import inet.ipaddr.MACAddressString;
import inet.ipaddr.MACAddressStringParameters;
import inet.ipaddr.mac.MACAddress;
import inet.ipaddr.mac.MACAddressSection;
import inet.ipaddr.mac.MACAddressSegment;


public class MACAddressRangeTest extends MACAddressTest {
	
	private static final MACAddressStringParameters WILDCARD_AND_RANGE_ADDRESS_OPTIONS = MAC_ADDRESS_OPTIONS.toBuilder().allowAll(true).getFormatBuilder().setRangeOptions(RangeParameters.WILDCARD_AND_RANGE).getParentBuilder().toParams();
	private static final MACAddressStringParameters WILDCARD_ONLY_ADDRESS_OPTIONS = WILDCARD_AND_RANGE_ADDRESS_OPTIONS.toBuilder().getFormatBuilder().setRangeOptions(RangeParameters.WILDCARD_ONLY).getParentBuilder().toParams();
	private static final MACAddressStringParameters NO_RANGE_ADDRESS_OPTIONS = WILDCARD_AND_RANGE_ADDRESS_OPTIONS.toBuilder().getFormatBuilder().setRangeOptions(RangeParameters.NO_RANGE).getParentBuilder().toParams();
	
	MACAddressRangeTest(AddressCreator creator) {
		super(creator);
	}

	@Override
	protected IPAddressString createAddress(String x) {
		if(x.indexOf(IPAddress.RANGE_SEPARATOR) != -1) {
			return createAddress(x, IPAddressRangeTest.WILDCARD_AND_RANGE_ADDRESS_OPTIONS);
		}
		return createAddress(x, IPAddressRangeTest.WILDCARD_ONLY_ADDRESS_OPTIONS);
	}
	
	@Override
	protected MACAddressString createMACAddress(String x) {
		if(x.indexOf(IPAddress.RANGE_SEPARATOR) != -1) {
			return createMACAddress(x, WILDCARD_AND_RANGE_ADDRESS_OPTIONS);
		}
		return createMACAddress(x, WILDCARD_ONLY_ADDRESS_OPTIONS);
	}
	
	protected MACAddressString createMACAddress(String x, RangeParameters ipv4RangeOptions) {
		MACAddressStringParameters validationOptions = getOpts(ipv4RangeOptions);
		return createMACAddress(x, validationOptions);
	}
	
	private static MACAddressStringParameters getOpts(RangeParameters options) {
		if(options.equals(RangeParameters.NO_RANGE)) {
			return NO_RANGE_ADDRESS_OPTIONS;
		} else if(options.equals(RangeParameters.WILDCARD_ONLY)) {
			return WILDCARD_ONLY_ADDRESS_OPTIONS;
		} else if(options.equals(RangeParameters.WILDCARD_AND_RANGE)) {
			return WILDCARD_AND_RANGE_ADDRESS_OPTIONS;
		}
		return WILDCARD_AND_RANGE_ADDRESS_OPTIONS.toBuilder().getFormatBuilder().setRangeOptions(options).getParentBuilder().toParams();
	}
	
	protected MACAddressString createAddress(String x, RangeParameters options) {
		return createMACAddress(x, getOpts(options));
	}
	
	@Override
	boolean testBytes(MACAddress origAddr) {
		boolean failed = false;
		if(origAddr.isMultiple()) {
			try {
				origAddr.getBytes();
			} catch(IncompatibleAddressException e) {
				failed = true;
			}
		} else {
			failed = !super.testBytes(origAddr);
		}
		return !failed;
	}
	
	private void testCount(String original, int number) {
		MACAddressString w = createMACAddress(original);
		testCount(w, number);
	}
	
	private void testCount(MACAddressString w, int number) {
		IPAddressRangeTest.testCount(this, w, number, -1);
	}
	
	private void testPrefixCount(String original, int number) {
		MACAddressString w = createMACAddress(original);
		testPrefixCount(w, number);
	}
	
	private void testPrefixCount(MACAddressString w, int number) {
		IPAddressRangeTest.testPrefixCount(this, w, number);
	}
	
	private void testToOUIPrefixed(String addrString) {
		MACAddressString w = createMACAddress(addrString);
		MACAddress v = w.getAddress();
		MACAddressSegment suffixSeg = new MACAddressSegment(0, 0xff);
		MACAddressSegment suffixSegs[] = new MACAddressSegment[v.getSegmentCount()];
		v.getSegments(0, 3, suffixSegs, 0);
		for(int i = 3; i < suffixSegs.length; i++) {
			suffixSegs[i] = suffixSeg;
		}
		MACAddressSection suffix = new MACAddressSection(suffixSegs);
		MACAddress suffixed = new MACAddress(suffix);
		MACAddress prefixed = v.toOUIPrefixBlock();
		if(!prefixed.equals(suffixed)) {
			addFailure(new Failure("failed oui prefixed " + prefixed + " constructed " + suffixed, w));
		}
		incrementTestCount();
	}
	
	private void testEquivalentPrefix(String host, int prefix) {
		testEquivalentPrefix(host, prefix, prefix);
	}
	
	private void testEquivalentPrefix(String host, Integer equivPrefix, int minPrefix) {
		MACAddressString str = createMACAddress(host);
		try {
			MACAddress h1 = str.toAddress();
			Integer equiv = h1.getPrefixLengthForSingleBlock();
			if(equiv == null ? (equivPrefix != null) : (!equivPrefix.equals(equiv))) {
				addFailure(new Failure("failed: prefix expected: " + equivPrefix + " prefix got: " + equiv, h1));
			} else {
					int minPref = h1.getMinPrefixLengthForBlock();
					if(minPref != minPrefix) {
						addFailure(new Failure("failed: prefix expected: " + minPrefix + " prefix got: " + minPref, h1));
					}
			}
		} catch(AddressStringException e) {
			addFailure(new Failure("failed " + e, str));
		} catch(IncompatibleAddressException e) {
			addFailure(new Failure("failed " + e, str));
		}
		incrementTestCount();
	}
	
	void testPrefixBlock(String prefixedAddressStr, int expectedPref) {
		//starting with prefixed address like 1:2:3:*:*:*, get lower (whcih should retain prefix except for allsubnets)
		//check if prefix block (not), then for all subnets assign prefix, then for all call toPrefixBlock, compare with original and also the prefix
		
		MACAddressString prefixedAddressString = createMACAddress(prefixedAddressStr);
		MACAddress prefixedAddress = prefixedAddressString.getAddress();
		PrefixConfiguration prefConf = prefixedAddress.getNetwork().getPrefixConfiguration();
		if(!prefixConfiguration.equals(prefConf)) {
			addFailure(new Failure("prefix config  " + prefixConfiguration + " mismatch with " + prefConf, prefixedAddress));
		}
		boolean allPrefixesAreSubnets = prefixConfiguration.allPrefixedAddressesAreSubnets();
		
		//a whole bunch of address manipulations, all of which we will reverse and then convert back to the prefix block
		MACAddress lower = prefixedAddress.getLower();
		MACAddress upper = prefixedAddress.getUpper();
		MACAddress removedPrefix = prefixedAddress.removePrefixLength(); 
		MACAddress adjustPrefix = prefixedAddress.adjustPrefixLength(1);
		MACAddress adjustPrefix2 = prefixedAddress.adjustPrefixLength(-1);
		int hostSeg = (prefixedAddress.getPrefixLength() + (MACAddress.BITS_PER_SEGMENT - 1)) / MACAddress.BITS_PER_SEGMENT;
		MACAddress replaced = prefixedAddress;
		MACAddress replacement = createMACAddress("1:1:1:1:1:1").getAddress();
		for(int i = hostSeg; i < replaced.getSegmentCount(); i++) {
			replaced = replaced.replace(i, i + 1, replacement, i);
		}
		if(lower.equals(upper)) {
			addFailure(new Failure("lower / upper " + lower + " / " + upper, prefixedAddress));
		}
		if(!prefixedAddress.isPrefixBlock()) {
			addFailure(new Failure("not prefix block", prefixedAddress));
		}
		if(!adjustPrefix.isPrefixBlock()) {
			addFailure(new Failure("adjustPrefix is not prefix block: " + adjustPrefix, prefixedAddress));
		}
		if(!adjustPrefix.isPrefixed()) {
			addFailure(new Failure("adjustPrefix not prefixed: " + adjustPrefix.getPrefixLength(), prefixedAddress));
		}
		if(!adjustPrefix2.isPrefixed()) {
			addFailure(new Failure("adjustPrefix2 not prefixed: " + adjustPrefix2.getPrefixLength(), prefixedAddress));
		}
		if(removedPrefix.isPrefixed()) {
			addFailure(new Failure("removedPrefix prefixed: " + removedPrefix.getPrefixLength(), prefixedAddress));
		}
		if(!replaced.isPrefixed()) {
			addFailure(new Failure("replaced prefixed: " + replaced.getPrefixLength(), prefixedAddress));
		}
		if(allPrefixesAreSubnets) {
			if(!replaced.isPrefixBlock()) {
				addFailure(new Failure("replaced is prefix block: " + replaced, prefixedAddress));
			}
			if(!adjustPrefix2.isPrefixBlock()) {
				addFailure(new Failure("adjustPrefix2 is not prefix block: " + adjustPrefix2, prefixedAddress));
			}
			if(lower.isPrefixed()) {
				addFailure(new Failure("lower prefixed: " + lower, prefixedAddress));
			}
			if(lower.isPrefixBlock()) {
				addFailure(new Failure("lower is prefix block: " + lower, prefixedAddress));
			}
			if(upper.isPrefixed()) {
				addFailure(new Failure("upper prefixed: " + upper, prefixedAddress));
			}
			if(upper.isPrefixBlock()) {
				addFailure(new Failure("upper is prefix block: " + upper, prefixedAddress));
			}
			lower = lower.applyPrefixLength(prefixedAddress.getPrefixLength());
			upper = upper.applyPrefixLength(prefixedAddress.getPrefixLength());
		} else {
			if(hostSeg < replaced.getSegmentCount() && replaced.isPrefixBlock()) {
				addFailure(new Failure("replaced is prefix block: " + replaced, prefixedAddress));
			}
			if(adjustPrefix2.isPrefixBlock()) {
				addFailure(new Failure("adjustPrefix2 is not prefix block: " + adjustPrefix2, prefixedAddress));
			}
			if(!lower.isPrefixed()) {
				addFailure(new Failure("lower not prefixed: " + lower, prefixedAddress));
			}
			if(lower.isPrefixBlock()) {
				addFailure(new Failure("lower is prefix block: " + lower, prefixedAddress));
			}
			if(!upper.isPrefixed()) {
				addFailure(new Failure("upper not prefixed: " + upper, prefixedAddress));
			}
			if(upper.isPrefixBlock()) {
				addFailure(new Failure("upper is prefix block: " + upper, prefixedAddress));
			}
		}
		MACAddress prefixedBlockAgain = lower.toPrefixBlock();
		if(!prefixedBlockAgain.isPrefixBlock()) {
			addFailure(new Failure("reconstituted prefix block not a prefix block: " + prefixedBlockAgain, prefixedAddress));
		}
		if(!prefixedBlockAgain.equals(prefixedAddress)) {
			addFailure(new Failure("reconstituted prefix block mismatch: " + prefixedBlockAgain + " original: " + prefixedAddress, prefixedAddress));
		}
		if(!prefixedBlockAgain.getPrefixLength().equals(prefixedAddress.getPrefixLength())) {
			addFailure(new Failure("reconstituted prefix block prefix mismatch: " + prefixedBlockAgain.getPrefixLength() + " original: " + prefixedAddress.getPrefixLength(), prefixedAddress));
		}

		//now revert all our operations, convert them all back to prefix blocks, and compare
		removedPrefix = removedPrefix.applyPrefixLength(prefixedAddress.getPrefixLength());
		adjustPrefix = adjustPrefix.adjustPrefixLength(-1);
		adjustPrefix2 = adjustPrefix2.adjustPrefixLength(1);
		if(!prefixedBlockAgain.equals(removedPrefix.toPrefixBlock()) || !prefixedBlockAgain.getPrefixLength().equals(removedPrefix.getPrefixLength())) {
			addFailure(new Failure("reconstituted prefix block mismatch with other: " + prefixedBlockAgain + " other: " + removedPrefix, prefixedAddress));
		}
		if(!prefixedBlockAgain.equals(adjustPrefix.toPrefixBlock()) || !prefixedBlockAgain.getPrefixLength().equals(adjustPrefix.getPrefixLength())) {
			addFailure(new Failure("reconstituted prefix block mismatch with other: " + prefixedBlockAgain + " other: " + adjustPrefix, prefixedAddress));
		}
		if(!prefixedBlockAgain.getPrefixLength().equals(adjustPrefix2.getPrefixLength())) {
			addFailure(new Failure("reconstituted prefix block mismatch with other: " + prefixedBlockAgain + " other: " + adjustPrefix2, prefixedAddress));
		}
		if(!prefixedBlockAgain.equals(replaced.toPrefixBlock()) || !prefixedBlockAgain.getPrefixLength().equals(replaced.getPrefixLength())) {
			addFailure(new Failure("reconstituted prefix block mismatch with other: " + prefixedBlockAgain + " other: " + replaced, prefixedAddress));
		}
		if(!prefixedBlockAgain.equals(upper.toPrefixBlock()) || !prefixedBlockAgain.getPrefixLength().equals(upper.getPrefixLength())) {
			addFailure(new Failure("reconstituted prefix block mismatch with other: " + prefixedBlockAgain + " other: " + upper, prefixedAddress));
		}
		
		incrementTestCount();
	}
	
	private void testTree(String start, String parents[]) {
		try {
			MACAddressString str = createMACAddress(start, WILDCARD_AND_RANGE_ADDRESS_OPTIONS);
			MACAddress addr = str.getAddress();
			//now do the same thing but use the IPAddress objects instead
			int i = 0, j = 0;
			Integer pref;
			boolean brokeEarly = false;
			do {
				String label = getLabel(addr.toAddressString());
				String expected = parents[i];
				if(!label.equals(expected)) {
					addFailure(new Failure("failed expected: " + expected + " actual: " + label, str));
					brokeEarly = true;
					break;
				}
				pref = addr.getPrefixLength();
				addr = addr.adjustPrefixBySegment(false, false);
				if(prefixConfiguration.allPrefixedAddressesAreSubnets()) {
					i++;
				}
				j++;
				
			} while(pref == null || pref != 0); //when network prefix is 0, Address.toSupernet() returns the same address
			if(!brokeEarly && j != parents.length) {
				addFailure(new Failure("failed: invalid label count " + parents.length + " expected " + j));
			}
		} catch(RuntimeException e) {
			addFailure(new Failure("failed: " + e + " " + start));
		}
		incrementTestCount();
	}
	
	private static String getLabel(MACAddressString addressString) {
		MACAddress address = addressString.getAddress();
		if(address == null) {
			return addressString.toString();
		}
		return address.toNormalizedString();
	}
	
	private void testTrees() {
		testTree("1:2:0-8f:*", new String[] {
				"01:02:00-8f:*:*:*",
				"01:02:*:*:*:*",
				"01:*:*:*:*:*",
				"*:*:*:*:*:*"
		});
		testTree("a:b:c:d:e:f", new String[] {
				"0a:0b:0c:0d:0e:0f",
				"0a:0b:0c:0d:0e:*",
				"0a:0b:0c:0d:*:*",
				"0a:0b:0c:*:*:*",
				"0a:0b:*:*:*:*",
				"0a:*:*:*:*:*",
				"*:*:*:*:*:*"
		});
		testTree("a:b:c:d:e:f:a:b", new String[] {
				"0a:0b:0c:0d:0e:0f:0a:0b",
				"0a:0b:0c:0d:0e:0f:0a:*",
				"0a:0b:0c:0d:0e:0f:*:*",
				"0a:0b:0c:0d:0e:*:*:*",
				"0a:0b:0c:0d:*:*:*:*",
				"0a:0b:0c:*:*:*:*:*",
				"0a:0b:*:*:*:*:*:*",
				"0a:*:*:*:*:*:*:*",
				"*:*:*:*:*:*:*:*"
		});
		testTree("a:b:c:d:e:f:a0-bf:*", new String[] {//this one is good now
				"0a:0b:0c:0d:0e:0f:a0-bf:*",
				"0a:0b:0c:0d:0e:0f:*:*",
				"0a:0b:0c:0d:0e:*:*:*",
				"0a:0b:0c:0d:*:*:*:*",
				"0a:0b:0c:*:*:*:*:*",
				"0a:0b:*:*:*:*:*:*",
				"0a:*:*:*:*:*:*:*",
				"*:*:*:*:*:*:*:*"
		});
		testTree("a:b:c:d:e:f:a2-a3:*", new String[] {//this one is good now
				"0a:0b:0c:0d:0e:0f:a2-a3:*",
				"0a:0b:0c:0d:0e:0f:*:*",
				"0a:0b:0c:0d:0e:*:*:*",
				"0a:0b:0c:0d:*:*:*:*",
				"0a:0b:0c:*:*:*:*:*",
				"0a:0b:*:*:*:*:*:*",
				"0a:*:*:*:*:*:*:*",
				"*:*:*:*:*:*:*:*"
		});
		testTree("a:b:c:d:e:f:1f-80:*", new String[] {
				"0a:0b:0c:0d:0e:0f:1f-80:*",
				"0a:0b:0c:0d:0e:0f:*:*",
				"0a:0b:0c:0d:0e:*:*:*",
				"0a:0b:0c:0d:*:*:*:*",
				"0a:0b:0c:*:*:*:*:*",
				"0a:0b:*:*:*:*:*:*",
				"0a:*:*:*:*:*:*:*",
				"*:*:*:*:*:*:*:*"
		});
		testTree("a:b:c:11-12:*", new String[] {
				"0a:0b:0c:11-12:*:*",
				"0a:0b:0c:*:*:*",
				"0a:0b:*:*:*:*",
				"0a:*:*:*:*:*",
				"*:*:*:*:*:*"
		});
	}
	
	@Override
	void testStrings() {
		super.testStrings();
		
		testMACStrings("a:b:c:d:*:*:*",
				"0a:0b:0c:0d:*:*:*:*",//normalizedString, //toColonDelimitedString
				"a:b:c:d:*:*:*:*",//compressedString,
				"0a-0b-0c-0d-*-*-*-*",//canonicalString, //toDashedString
				"0a0b.0c0d.*.*",//dottedString,
				"0a 0b 0c 0d * * * *",//spaceDelimitedString,
				"0a0b0c0d00000000-0a0b0c0dffffffff");//singleHex
		
		testMACStrings("a:b:c:*:*:*:*",
				"0a:0b:0c:*:*:*:*:*",//normalizedString, //toColonDelimitedString
				"a:b:c:*:*:*:*:*",//compressedString,
				"0a-0b-0c-*-*-*-*-*",//canonicalString, //toDashedString
				"0a0b.0c00-0cff.*.*",//dottedString,
				"0a 0b 0c * * * * *",//spaceDelimitedString,
				"0a0b0c0000000000-0a0b0cffffffffff");//singleHex
		
		testMACStrings("a:b:c:d:*",
				"0a:0b:0c:0d:*:*",//normalizedString, //toColonDelimitedString
				"a:b:c:d:*:*",//compressedString,
				"0a-0b-0c-0d-*-*",//canonicalString, //toDashedString
				"0a0b.0c0d.*",//dottedString,
				"0a 0b 0c 0d * *",//spaceDelimitedString,
				"0a0b0c0d0000-0a0b0c0dffff");//singleHex
		
		testMACStrings("a:b:c:d:1-2:*",
				"0a:0b:0c:0d:01-02:*",//normalizedString, //toColonDelimitedString
				"a:b:c:d:1-2:*",//compressedString,
				"0a-0b-0c-0d-01|02-*",//canonicalString, //toDashedString 
				"0a0b.0c0d.0100-02ff",//dottedString,
				"0a 0b 0c 0d 01-02 *",//spaceDelimitedString,
				"0a0b0c0d0100-0a0b0c0d02ff");//singleHex
		
		testMACStrings("0:0:c:d:e:f:10-1f:b",
				"00:00:0c:0d:0e:0f:10-1f:0b",//normalizedString, //toColonDelimitedString
				"0:0:c:d:e:f:10-1f:b",//compressedString,
				"00-00-0c-0d-0e-0f-10|1f-0b",//canonicalString, //toDashedString
				null,//dottedString,
				"00 00 0c 0d 0e 0f 10-1f 0b",//spaceDelimitedString,
				null);//singleHex
		
		testMACStrings("0:0:c:d:e:f:10-1f:*",
				"00:00:0c:0d:0e:0f:10-1f:*",//normalizedString, //toColonDelimitedString
				"0:0:c:d:e:f:10-1f:*",//compressedString,
				"00-00-0c-0d-0e-0f-10|1f-*",//canonicalString, //toDashedString
				"0000.0c0d.0e0f.1000-1fff",//dottedString,
				"00 00 0c 0d 0e 0f 10-1f *",//spaceDelimitedString,
				"00000c0d0e0f1000-00000c0d0e0f1fff");//singleHex
		
		testMACStrings("a-b:b-c:0c-0d:0d-e:e-0f:f-ff:aa-bb:bb-cc",
				"0a-0b:0b-0c:0c-0d:0d-0e:0e-0f:0f-ff:aa-bb:bb-cc",//normalizedString, //toColonDelimitedString
				"a-b:b-c:c-d:d-e:e-f:f-ff:aa-bb:bb-cc",//compressedString,
				"0a|0b-0b|0c-0c|0d-0d|0e-0e|0f-0f|ff-aa|bb-bb|cc",//canonicalString, //toDashedString
				null,//dottedString,
				"0a-0b 0b-0c 0c-0d 0d-0e 0e-0f 0f-ff aa-bb bb-cc",//spaceDelimitedString,
				null);//singleHex
		
		testMACStrings("12-ef:*:cd:d:0:*",
				"12-ef:*:cd:0d:00:*",//normalizedString, //toColonDelimitedString
				"12-ef:*:cd:d:0:*",//compressedString,
				"12|ef-*-cd-0d-00-*",//canonicalString, //toDashedString
				"1200-efff.cd0d.0000-00ff",//dottedString,
				"12-ef * cd 0d 00 *",//spaceDelimitedString,
				null);//singleHex
		
		testMACStrings("ff:ff:*:*:aa-ff:0-de",
				"ff:ff:*:*:aa-ff:00-de",//normalizedString, //toColonDelimitedString
				"ff:ff:*:*:aa-ff:0-de",//compressedString,
				"ff-ff-*-*-aa|ff-00|de",//canonicalString, //toDashedString
				null,//dottedString,
				"ff ff * * aa-ff 00-de",//spaceDelimitedString,
				null);//singleHex
		
		testMACStrings("ff:ff:aa-ff:*:*:*",
				"ff:ff:aa-ff:*:*:*",//normalizedString, //toColonDelimitedString
				"ff:ff:aa-ff:*:*:*",//compressedString,
				"ff-ff-aa|ff-*-*-*",//canonicalString, //toDashedString
				"ffff.aa00-ffff.*",//dottedString,
				"ff ff aa-ff * * *",//spaceDelimitedString,
				"ffffaa000000-ffffffffffff");//singleHex
		
		testMACStrings("ff:f:aa-ff:*:*:*",
				"ff:0f:aa-ff:*:*:*",//normalizedString, //toColonDelimitedString
				"ff:f:aa-ff:*:*:*",//compressedString,
				"ff-0f-aa|ff-*-*-*",//canonicalString, //toDashedString
				"ff0f.aa00-ffff.*",//dottedString,
				"ff 0f aa-ff * * *",//spaceDelimitedString,
				"ff0faa000000-ff0fffffffff");//singleHex
		
		testMACStrings("ff:ff:ee:aa-ff:*:*",
				"ff:ff:ee:aa-ff:*:*",//normalizedString, //toColonDelimitedString
				"ff:ff:ee:aa-ff:*:*",//compressedString,
				"ff-ff-ee-aa|ff-*-*",//canonicalString, //toDashedString
				"ffff.eeaa-eeff.*",//dottedString,
				"ff ff ee aa-ff * *",//spaceDelimitedString,
				"ffffeeaa0000-ffffeeffffff");//singleHex
		
		testMACStrings("*",
				"*:*:*:*:*:*",//normalizedString, //toColonDelimitedString
				"*:*:*:*:*:*",//compressedString,
				"*-*-*-*-*-*",//canonicalString, //toDashedString
				"*.*.*",//dottedString,
				"* * * * * *",//spaceDelimitedString,
				"000000000000-ffffffffffff");//singleHex

		testMACStrings("1-3:2:33:4:55-60:6",
				"01-03:02:33:04:55-60:06",
				"1-3:2:33:4:55-60:6",
				"01|03-02-33-04-55|60-06",
				null,
				"01-03 02 33 04 55-60 06",
				null);
		
		testMACStrings("f3:2:33:4:6:55-60",
				"f3:02:33:04:06:55-60",
				"f3:2:33:4:6:55-60",
				"f3-02-33-04-06-55|60",
				"f302.3304.0655-0660",
				"f3 02 33 04 06 55-60",
				"f30233040655-f30233040660");

		testMACStrings("*-b00cff",
				"*:*:*:b0:0c:ff",
				"*:*:*:b0:c:ff",
				"*-*-*-b0-0c-ff",
				null,
				"* * * b0 0c ff",
				null);
				
		testMACStrings("0aa0bb-*",
				"0a:a0:bb:*:*:*",
				"a:a0:bb:*:*:*",
				"0a-a0-bb-*-*-*",
				"0aa0.bb00-bbff.*",
				"0a a0 bb * * *",
				"0aa0bb000000-0aa0bbffffff");
			
		testMACStrings("0000aa|0000bb-000b00|000cff",
				"00:00:aa-bb:00:0b-0c:*",
				"0:0:aa-bb:0:b-c:*",
				"00-00-aa|bb-00-0b|0c-*",
				null,
				"00 00 aa-bb 00 0b-0c *",
				null);
		
		testMACStrings("c000aa|c000bb-c00b00|c00cff",
			"c0:00:aa-bb:c0:0b-0c:*",
			"c0:0:aa-bb:c0:b-c:*",
			"c0-00-aa|bb-c0-0b|0c-*",
			null,
			"c0 00 aa-bb c0 0b-0c *",
			null);

		testMACStrings("0000aa|0000bb-000b00",
			"00:00:aa-bb:00:0b:00",
			"0:0:aa-bb:0:b:0",
			"00-00-aa|bb-00-0b-00",
			null,
			"00 00 aa-bb 00 0b 00",
			null);
			
		testMACStrings("0000bb-000b00|000cff",
			"00:00:bb:00:0b-0c:*",
			"0:0:bb:0:b-c:*",
			"00-00-bb-00-0b|0c-*",
			"0000.bb00.0b00-0cff",
			//null,
			"00 00 bb 00 0b-0c *",
			"0000bb000b00-0000bb000cff");
				
		testMACStrings("0000aa|0000bb-*",
			"00:00:aa-bb:*:*:*",
			"0:0:aa-bb:*:*:*",
			"00-00-aa|bb-*-*-*",
			"0000.aa00-bbff.*",
			"00 00 aa-bb * * *",
			"0000aa000000-0000bbffffff");
			
		testMACStrings("*-000b00|000cff",
			"*:*:*:00:0b-0c:*",
			"*:*:*:0:b-c:*",
			"*-*-*-00-0b|0c-*",
			null,
			"* * * 00 0b-0c *",
			null);
	}
	
	@Override
	boolean allowsRange() {
		return true;
	}
	
	@Override
	void runTest() {
		
		testEquivalentPrefix("*:*", 0);
		testEquivalentPrefix("*:*:*:*:*:*", 0);
		testEquivalentPrefix("*:*:*:*:*:*:*:*", 0);
		testEquivalentPrefix("80-ff:*", 1);
		testEquivalentPrefix("0-7f:*", 1);
		testEquivalentPrefix("1:2:*", 16);
		testEquivalentPrefix("1:2:*:*:*:*", 16);
		testEquivalentPrefix("1:2:*:0:*:*", null, 32);
		testEquivalentPrefix("1:2:*:0:0:0", null, 48);
		
		testEquivalentPrefix("1:2:80-ff:*", 17);
		testEquivalentPrefix("1:2:00-7f:*", 17);
		testEquivalentPrefix("1:2:c0-ff:*", 18);
		testEquivalentPrefix("1:2:00-3f:*", 18);
		testEquivalentPrefix("1:2:80-bf:*", 18);
		testEquivalentPrefix("1:2:40-7f:*", 18);
		testEquivalentPrefix("1:2:fc-ff:*", 22);
		testEquivalentPrefix("1:2:fc-ff:0-ff:*", 22);
		testEquivalentPrefix("1:2:fd-ff:0-ff:*", null, 24);
		testEquivalentPrefix("1:2:fc-ff:0-fe:*", null, 32);
		testEquivalentPrefix("1:2:fb-ff:0-fe:*", null, 32);
		testEquivalentPrefix("1:2:fb-ff:0-ff:*", null, 24);

		testReverse("1:2:*:4:5:6", false, false);
		testReverse("1:1:1-ff:2:3:3", false, false);
		testReverse("1:1:0-fe:1-fe:*:1", false, false);
		testReverse("ff:80:*:ff:01:ff", false, false);
		testReverse("ff:80:fe:7f:01:ff", true, false);
		testReverse("ff:80:*:*:01:ff", true, false);
		testReverse("ff:81:ff:*:1-fe:ff", false, true);
		testReverse("ff:81:c3:42:24:0-fe", false, true);
		testReverse("ff:1:ff:ff:*:*", false, false);
		
		boolean isAllSubnets = prefixConfiguration.allPrefixedAddressesAreSubnets();
		
		if(isAllSubnets) {
			testPrefixes("25:51:27:12:82:55", 
					16, -5, 
					"25:51:27:12:82:55",
					"25:51:27:12:82:*",
					"25:51:27:12:82:40-5f",
					"25:51:*:*:*:*",
					"25:51:*:*:*:*");
			
			testPrefixes("25:51:27:*:*:*", 
					16, -5, 
					"25:51:27:00:*:*",
					"25:51:*:*:*:*",
					"25:51:20-3f:*:*:*",
					"25:51:*:*:*:*",
					"25:51:*:*:*:*");
		} else {
			testPrefixes("25:51:27:12:82:55",
					16, -5, 
					"25:51:27:12:82:55",
					"25:51:27:12:82:0",
					"25:51:27:12:82:40",
					"25:51:0:0:0:0",
					"25:51:0:0:0:0");
			
			testPrefixes("25:51:27:*:*:*",
					16, -5, 
					"25:51:27:00:*:*",
					"25:51:0:*:*:*",
					"25:51:20:*:*:*",
					"25:51:0:*:*:*",
					"25:51:0:*:*:*");
		}
		
		
		if(isAllSubnets) {
			testPrefixes("*:*:*:*:*:*:0-fe:*", 
					15, 2, 
					"*:*:*:*:*:*:0-fe:0",
					"*:*:*:*:*:*:*:*",//*:*:*:*:*:*:00:*
					"*:*:*:*:*:*:0-fe:0-3f", 
					"*:*:*:*:*:*:*:*",
					"*:*:*:*:*:*:*:*");
			
			testPrefixes("*:*:*:*:*:*:*:*", 
					15, 2, 
					"0:*:*:*:*:*:*:*",
					"*:*:*:*:*:*:*:*",
					"0-3f:*:*:*:*:*:*:*",
					"0:0-1:*:*:*:*:*:*",
					"*:*:*:*:*:*:*:*");
			
			testPrefixes("1:*:*:*:*:*", 
					15, 2, 
					"1:0:*:*:*:*",
					"*:*:*:*:*:*",
					"1:0-3f:*:*:*:*",
					"1:0-1:*:*:*:*",
					"1:*:*:*:*:*");
			
			testPrefixes("3.8000-ffff.*.*",
					15, 2, 
					"3.8000-80ff.*.*",
					"3.*.*.*",
					"3.8000-9fff.*.*",
					"2-3.*.*.*",
					"2-3.*.*.*");
			
			testPrefixes("3.8000-ffff.*.*", 
					31, 2, 
					"3.8000-80ff.*.*",
					"3.*.*.*",
					"3.8000-9fff.*.*",
					"3.8000-8001.*.*",
					"3.8000-ffff.*.*");
		} else {
			testPrefixes("*:*:*:*:*:*:0-fe:*", 
					15, 2, 
					"*:*:*:*:*:*:0-fe:0",
					"*:*:*:*:*:*:0:*",
					"*:*:*:*:*:*:0-fe:0-3f", 
					"*:00-fe:00:00:00:00:00:*",
					"*:00-fe:00:00:00:00:00:*");
			
			testPrefixes("*:*:*:*:*:*:*:*", 
					15, 2, 
					"0:*:*:*:*:*:*:*",
					"*:*:*:*:*:*:*:*",
					"0-3f:*:*:*:*:*:*:*",
					"0:0-1:*:*:*:*:*:*",
					"*:*:*:*:*:*:*:*");
			
			testPrefixes("1:*:*:*:*:*", 
					15, 2, 
					"1:0:*:*:*:*",
					"0:*:*:*:*:*",
					"1:0-3f:*:*:*:*",
					"1:0-1:*:*:*:*",
					"1:*:*:*:*:*");
			
			testPrefixes("3.8000-ffff.*.*",
					15, 2, 
					"3.8000-80ff.*.*",
					"00:03:00-7f:*:*:*:*:*",
					"3.8000-9fff.*.*",
					"00:02:00-7f:*:*:*:*:*",
					"00:02:00-7f:*:*:*:*:*");
			
			testPrefixes("3.8000-ffff.*.*",
					31, 2,
					"3.8000-80ff.*.*",
					"00:03:00-7f:*:*:*:*:*",
					"3.8000-9fff.*.*",
					"3.8000-8001.*.*",
					"3.8000-ffff.*.*");
		}

		testPrefix("25:51:27:*:*:*", 24, 24);
		testPrefix("25:50-51:27:*:*:*", 24, null);
		testPrefix("25:51:27:12:82:55", null, 48);
		testPrefix("*:*:*:*:*:*", 0, 0);
		testPrefix("*:*:*:*:*:*:*:*", 0, 0);
		testPrefix("*:*:*:*:*:*:0-fe:*", 56, null);
		testPrefix("*:*:*:*:*:*:0-ff:*", 0, 0);
		testPrefix("*:*:*:*:*:*:0-7f:*", 49, null);
		testPrefix("*:*:*:*:*:*:80-ff:*", 49, null);
		testPrefix("*.*.*.*", 0, 0);
		testPrefix("3.*.*.*", 16, 16);
		testPrefix("3.*.*.1-3", null, null);
		testPrefix("3.0-7fff.*.*", 17, 17);
		testPrefix("3.8000-ffff.*.*", 17, 17);

		testToOUIPrefixed("25:51:27:*:*:*");
		testToOUIPrefixed("*:*:*:*:*:*");
		testToOUIPrefixed("*:*:*:25:51:27");
		testToOUIPrefixed("ff:ee:25:51:27:*:*:*");
		testToOUIPrefixed("*:*:*:*:*:*:*:*");
		testToOUIPrefixed("*:*:*:25:51:27:ff:ee");
		testToOUIPrefixed("123.456.789.abc");
		testToOUIPrefixed("123.456.789.*");

		testOUIPrefixed("ff:7f:fe:2:7f:fe", "ff:7f:fe:*", 24);
		testOUIPrefixed("ff:7f:fe:2:7f:*", "ff:7f:fe:*", 24);
		testOUIPrefixed("ff:7f:fe:*", "ff:7f:fe:*", 24);
		testOUIPrefixed("ff:*", "ff:*", 8);
		testOUIPrefixed("ff:7f:fe:2:7f:fe:7f:fe", "ff:7f:fe:*:*:*:*:*", 24);
		testOUIPrefixed("ff:7f:0-f:*", "ff:7f:0-f:*", 20);
		
		testTrees();

		testDelimitedCount("1,2|3,4-3-4,5-6-7-8", 8); //this will iterate through 1.3.4.6 1.3.5.6 2.3.4.6 2.3.5.6
		testDelimitedCount("1,2-3,6-7-8-4,5|6-6,8", 16); //this will iterate through 1.3.4.6 1.3.5.6 2.3.4.6 2.3.5.6
		testDelimitedCount("1:2:3:*:4:5", 1); //this will iterate through 1.3.4.6 1.3.5.6 2.3.4.6 2.3.5.6
		testDelimitedCount("1:2,3,*:3:6:4:5,ff,7,8,99", 15); //this will iterate through 1.3.4.6 1.3.5.6 2.3.4.6 2.3.5.6
		testDelimitedCount("1:0,1-2,3,5:3:6:4:5,ff,7,8,99", 30); //this will iterate through 1.3.4.6 1.3.5.6 2.3.4.6 2.3.5.6
		
		testLongShort("ff:ff:ff:ff:ff:*:ff:1-ff", "ff:ff:ff:*:ff:1-ff", true);
		testLongShort("12-cd-cc-dd-ee-ff-*", "12-cd-cc-*", true);
		testLongShort("12CD.CCdd.*.a", "12CD.*.a", true);
		testLongShort("*-0D0E0F0A0B", "0A0B0C-*", true);
		testLongShort("*-0D0E0F0A0B", "*-0A0B0C");
		testLongShort("*-0D0E0F0A0B", "*-*", true);
		testLongShort("ee:ff:aa:*:dd:ee:ff", "ee:ff:a-b:bb:cc:dd");
		testLongShort("ee:ff:aa:*:dd:ee:ff", "ee:ff:a-b:*:dd", true);
		testLongShort("e:f:a:b:c:d:e:e-f", "e:*", true);
		
		testMatches(true, "aa:-1:cc:d:ee:f", "aa:0-1:cc:d:ee:f");
		testMatches(true, "aa:-:cc:d:ee:f", "aa:*:cc:d:ee:f");
		testMatches(true, "-:-:cc:d:ee:f", "*:cc:d:ee:f");
		testMatches(true, "aa:-dd:cc:d:ee:f", "aa:0-dd:cc:d:ee:f");
		testMatches(true, "aa:1-:cc:d:ee:f", "aa:1-ff:cc:d:ee:f");
		testMatches(true, "-1:aa:cc:d:ee:f", "0-1:aa:cc:d:ee:f");
		testMatches(true, "1-:aa:cc:d:ee:f", "1-ff:aa:cc:d:ee:f");
		testMatches(true, "aa:cc:d:ee:f:1-", "aa:cc:d:ee:f:1-ff");
		testMatches(true, "aa-|1-cc-d-ee-f", "aa-0|1-cc-d-ee-f");
		testMatches(true, "|1-aa-cc-d-ee-f", "0|1-aa-cc-d-ee-f");
		testMatches(true, "aa-1|-cc-d-ee-f", "aa-1|ff-cc-d-ee-f");
		testMatches(true, "1|-aa-cc-d-ee-f", "1|ff-aa-cc-d-ee-f");
		testMatches(true, "|-aa-cc-d-ee-f", "*-aa-cc-d-ee-f");
		testMatches(true, "|-|-cc-d-ee-f", "*-cc-d-ee-f");
		testMatches(true, "|-|-cc-d-ee-|", "*-*-cc-d-ee-*");
		testMatches(true, "|-|-cc-d-ee-2|", "*-*-cc-d-ee-2|ff");
		testMatches(true, "|-|-cc-d-ee-|2", "*-*-cc-d-ee-0|2");
		testMatches(true, "*-|-*", "*-*");
		testMatches(true, "*-|-|", "*-*");
		testMatches(true, "|-|-*", "*:*");
		testMatches(true, "*:*:*:*:*:*", "*:*");
		testMatches(true, "1:*:*:*:*:*", "1:*");
		testMatches(true, "*:*:*:*:*:1", "*:1");
		testMatches(true, "*:*:*:12:34:56", "*-123456");
		testMatches(true, "12:34:56:*:*:*", "123456-*");
		testMatches(true, "1:*:*:*:*:*", "1-*");
		testMatches(true, "*:*:*:*:*:1", "*-1");
		testMatches(true, "*-*-*", "*:*:*");
		testMatches(true, "*-*", "*:*:*");
		testMatches(true, "bbaacc0dee0f", "bb:aa:cc:d:ee:f");
		testMatches(true, "bbaacc0dee0faab0", "bb:aa:cc:d:ee:f:aa:b0");
		
		mactest(false, "*|1");
		mactest(false, "1|*");
		mactest(true, "*-1");
		mactest(true, "1-*");
		mactest(true, "*-*");
		mactest(true, "*:1");
		mactest(true, "1:*");
		mactest(true, "*:*");
		mactest(false, "1:1");
		mactest(false, "1-1");
		mactest(true, "0xaabbccddeeee-0xaabbccddeeff");
		mactest(true, "0xaabbccddeeee-aabbccddeeff");
		mactest(true, "aabbccddeeee-0xaabbccddeeff");
		mactest(true, "aabbccddeeee-aabbccddeeff");
		
		mactest(allowsRange(), "aa-|1-*-d-ee-f");
		mactest(allowsRange(), "|1-aa-cc-*-ee-f");
		mactest(allowsRange(), "aa-1|-cc-d-*-f");
		mactest(allowsRange(), "1|-aa-cc-d-*");
		mactest(allowsRange(), "aa-0|1-cc-*");
		mactest(allowsRange(), "aa-1|ff-*");
		mactest(allowsRange(), "*-1|ff-*");
		
		mactest(true, "aa0000|abffff-ddeeff");
		mactest(true, "aa0000|abffff-*");
		mactest(false, "aabbcc|ddeeff-ddeefff");
		mactest(false, "aabbcc|aabbcd-ddeefffff");
		mactest(true, "aabbcc|aabbcd-ddeeffffff");
		mactest(false, "aabbcc|aabbcd-ddeefffffff");
		mactest(true, "aabbcc|aabbcd-*");
		mactest(false, "aabbcc|aabbcd-ddeefffffff");
		
		mactest(true, "ddeeff-aa0000|afffff");
		mactest(true, "*-aa0000|afffff");
		mactest(false, "ddeefff-aabbcc|ddeeff");
		mactest(true, "ddeeff-aabbffffcc|aabbffffdd");
		mactest(false, "ddeeff-aabbffffccc|aabbffffddd");
		mactest(false, "ddeeff-aabbffffc|aabbffffd");
		mactest(false, "ddeefffffff-aabbcc|aabbcd");
		
		testMACIPv6("aaaa:bbbb:cccc:dddd:0221:2fff:fe00-feff:6e10", "00:21:2f:*:6e:10");
		testMACIPv6("*:*:*:*:200-2ff:FF:FE00-FEFF:*", "0:*:0:*:*:*");
		testMACIPv6("*:*:*:*:200-3ff:abFF:FE01-FE03:*", "0-1:*:ab:1-3:*:*");
		testMACIPv6("*:*:*:*:a200-a3ff:abFF:FE01-FE03:*", "a0-a1:*:ab:1-3:*:*");
		testMACIPv6("*:2:*:*:a388-a399:abFF:FE01-FE03:*", "a1:88-99:ab:1-3:*:*");
		testMACIPv6("*:2:*:*:a388-a399:abFF:FE01-FE03:*", "a1:88-99:ab:1-3:*:*");
		testMACIPv6("1:0:0:0:8a0:bbff:fe00-feff:*", "0a:a0:bb:*:*:*");//[1:0:0:0:aa0:bbff:fe00-feff:*, 1:0:0:0:8a0:bbff:fe00-feff:*]
		testMACIPv6("1:0:0:0:200:bbff:fe00:b00-cff", "00:00:bb:00:0b-0c:*");
		testMACIPv6("1:0:0:0:200:bbff:fe00:b00-cff", "00:00:bb:00:0b-0c:*");
		testMACIPv6("1:0:0:0:c200:aaff:fec0:b00-cff", "c0:00:aa:c0:0b-0c:*");
		testMACIPv6("1:0:0:0:200:aaff:fe00:b00", "00:00:aa:00:0b:00");
		testMACIPv6("1:0:0:0:200:bbff:fe00:b00-cff","00:00:bb:00:0b-0c:*");
		testMACIPv6("1:0:0:0:200:bbff:fe00-feff:*", "00:00:bb:*:*:*");
	
		
		testNotContains("*.*", "1.2.3.4");
		testContains("*.*.*.*", "1.2.3.4", false);
		testContains("*.*.*", "1.2.3", false);
		testContains("*.*.1.aa00-ffff", "1.2.1.bbbb", false);
		testContains("*.*.1.aa00-ffff", "0-ffff.*.1.aa00-ffff", true);
		testContains("0-1ff.*.*.*", "127.2.3.4", false);
		testContains("0-1ff.*.*.*", "128.2.3.4", false);
		testNotContains("0-1ff.*", "200.2.3.4");
		testNotContains("0-1ff.*", "128.2.3.4");
		testContains("0-1ff.*", "128.2.3", false);
		testContains("0-ff.*.*.*", "15.2.3.4", false);
		testContains("0-ff.*", "15.2.3", false);
		testContains("9.129.*.*", "9.129.237.26", false);
		testContains("9.129.*", "9.129.237", false);
		testNotContains("9.129.*.25", "9.129.237.26");
		testContains("9.129.*.26", "9.129.237.26", false);
		testContains("9.129.*.26", "9.129.*.26", true);
		
		testContains("9.a0-ae.1.226-254", "9.ad.1.227", false);
		testNotContains("9.a0-ac.1.226-254", "9.ad.1.227");
		testNotContains("9.a0-ae.2.226-254", "9.ad.1.227");
		testContains("9.a0-ae.1.226-254", "9.a0-ae.1.226-254", true);
		
		testContains("8-9:a0-ae:1-3:20-26:0:1", "9:ad:1:20:0:1", false);
		testContains("8-9:a0-ae:1-3:20-26:0:1", "9:ad:1:23-25:0:1", false);
		testNotContains("8-9:a0-ae:1-3:20-26:0:1", "9:ad:1:23-27:0:1");
		testNotContains("8-9:a0-ae:1-3:20-26:0:1", "9:ad:1:18-25:0:1");
		testContains("*:*:*:*:ab:*:*:*", "*:*:*:*:ab:*:*:*", true);
		testContains("*:*:*:*:*:*:*:*", "*:*:*:*:*:*:*:*", true);
		testContains("*:*:*:*:*:*:*:*", "a:b:c:d:e:f:a:b", false);
		testContains("*:*:*:*:*:*", "a:b:c:d:a:b", false);
		testContains("80-8f:*:*:*:*:*", "8a:d:e:f:a:b", false);
		testContains("*:*:*:*:*:80-8f", "d:e:f:a:b:8a", false);
		testContains("*:*:*:*:*:*:*:*", "a:*:c:d:e:1-ff:a:b", false);
		testContains("8a-8d:*:*:*:*:*:*:*", "8c:b:c:d:e:f:*:b", false);
		testNotContains("80:0:0:0:0:0:0:0-1", "7f-8f:b:c:d:e:f:*:b");
		testContains("ff:0-3:*:*:*:*:*:*", "ff:0-3:c:d:e:f:a:b", false);
		testNotContains("ff:0-3:*:*:*:*:*:*", "ff:0-4:c:d:e:f:a:b");
		testContains("ff:0:*:*:*:*:*:*", "ff:0:ff:1-d:e:f:*:b", false);
		testContains("*:*:ff:0:*:*:*:*", "*:b:ff:0:ff:1-d:e:f", false);
		testNotContains("ff:0:*:*:*:*:*:*", "ff:0-1:ff:d:e:f:a:b");
		testContains("ff:0:0:0:0:4-ff:0:fc-ff", "ff:0:0:0:0:4-ff:0:fd-ff", false);
		testContains("ff:0:0:0:0:4-ff:0:fc-ff", "ff:0:0:0:0:4-ff:0:fc-ff", true);
		testContains("ff:0:*:0:0:4-ff:0:ff", "ff:0:*:0:0:4-ff:0:ff", true);
		testContains("*:*:*:*:*:*:*:*", "*:*:*:*:*:*:*:*", true);
		testContains("80-8f:*:*:*:*:80-8f", "83-8e:*:*:*:a-b:80-8f", false);
		testContains("80-8f:*:*:*:*:80-8f", "83-8e:*:*:*:a-b:80-8f", false);
		testNotContains("80-8f:*:*:*:*:80-8f", "7f-8e:*:*:*:a-b:80-8f");

		testSections("00-1:21-ff:*:10");
		testSections("00-1:21-ff:2f:*:10");
		testSections("*-A7-94-07-CB-*");
		testSections("aa-*");
		testSections("aa-bb-*");
		testSections("aa-bb-cc-*");
		testSections("8-9:a0-ae:1-3:20-26:0:1");
		testSections("fe-ef-39-*-94-07-b|C-D0");
		testSections("5634-5678.*.7feb.6b40");
		testSections("ff:0:1:*");
		testSections("ff:0:1:*:*:*:*:*");
		
		
		testRadices("11:10:*:1-7f:f3:2", "10001:10000:*:1-1111111:11110011:10", 2);
		testRadices("0:1:0:1:0-1:1:0:1", "0:1:0:1:0-1:1:0:1", 2);
		
		testRadices("f3-ff:7f:fe:*:7_:fe", "f3-ff:7f:fe:*:70-7f:fe", 16);
		testRadices("*:1:0:1:0-1:1:0:1", "*:1:0:1:0-1:1:0:1", 16);
		
		testRadices("ff:7f:*:2:7_:fe", "255:127:*:2:112-127:254", 10);
		testRadices("*:1:0:1:0-1:1:0:1", "*:1:0:1:0-1:1:0:1", 10);
		
		testRadices("ff:*:fe:2:7d-7f:fe", "513:*:512:2:236-241:512", 7);
		testRadices("1:0:0-1:0:1:*", "1:0:0-1:0:1:*", 7);
		
		testRadices("ff:70-7f:fe:2:*:fe", "377:160-177:376:2:*:376", 8);
		testRadices("1:0:0-1:0:1:*", "1:0:0-1:0:1:*", 8);
		
		testRadices("ff:7f:fa-fe:2:7f:*", "120:87:11a-11e:2:87:*", 15);
		testRadices("1:0:0-1:0:1:*", "1:0:0-1:0:1:*", 15);
		
		
		testCount("11:22:33:44:55:ff", 1);
		testCount("11:22:*:0-2:55:ff", 3 * 0x100);
		testCount("11:22:2:0-2:55:*", 3 * 0x100);
		testCount("11:2-4:1:0-2:55:ff", 9);
		testCount("112-114.1.0-2.55ff", 9);
		testCount("*.1.0-2.55ff", 3 * 0x10000);
		testCount("1-2.1-2.1-2.2-3", 16);
		testCount("1-2.1.*.2-3", 4 * 0x10000);
		testCount("11:*:*:0-2:55:ff", 3 * 0x100 * 0x100);
		
		testPrefixCount("11:22:*:0-2:55:ff", 3 * 0x100);
		testPrefixCount("11:22:*:0-2:55:*", 3 * 0x100);
		testPrefixCount("11:22:1:2:55:*", 1);
		
		testMatches(true, "1-02.03-4.05-06.07", "1-2.3-4.5-6.7");
		testMatches(true, "1-002.003-4.005-006.007", "1-2.3-4.5-6.7");
		testMatches(true, "1-002.003-4.0005-006.0007", "1-2.3-4.5-6.7");
		testMatches(true, "1100-22ff.003-4.0005-006.0007", "1100-22ff.3-4.5-6.7");
		testMatches(true, "1-2.0-0.00-00.00-0", "1-2.0.0.0");	
		testMatches(true, "00-0.0-0.00-00.00-0", "0.0.0.0");
		testMatches(true, "0-00:0-0:00-00:00-0:0-00:00-00:00-00:00-0", "0:0:0:0:0:0:0:0");
		testMatches(true, "1-2:0-0:00-00:00-0:0-00:00-00:00-00:00-0", "1-2:0:0:0:0:0:0:0");
		
		mactest(1,"11:11:11:ff:_:0");
		mactest(1,"_:11:11:11:1:1");
		mactest(1,"1:2:3:4:_:6:7:8");
		mactest(1,"1:2:_:4:5:6:8:7");
		mactest(1,"1:3:4:5:6:_");
		mactest(1,"1:2:3:_:5:6:8:7");
		mactest(1,"_:2:3:5:ff:8");
		mactest(1,"1:11:11:11:1:_");
		mactest(1,"_:2:3:4:5:6:7:7");
		mactest(1,"_:2:3:4:5:6");
		mactest(1,"1:5:2:3:4:_");

		
		mactest(1,"11:11:11:ff:__:0");
		mactest(1,"__:11:11:11:1:1");
		mactest(1,"1:2:3:4:__:6:7:8");
		mactest(1,"1:2:__:4:5:6:7:8");
		mactest(1,"1:2:3:4:5:__");
		mactest(1,"1:2:3:__:5:8");
		mactest(1,"__:2:3:4:5:8");
		mactest(1,"1:2:3:4:5:__");
		mactest(1,"__:2:3:4:5:6:7:8");
		mactest(1,"__:2:3:4:5:6");
		mactest(1,"1:2:3:3:4:__");
		
		mactest(0,"11:11:11:ff:___:0");
		mactest(0,"___:11:11:11:1:1");
		mactest(0,"1:2:3:4:___:6:7:8");
		mactest(0,"1:2:___:4:5:6:7:8");
		mactest(0,"1:2:3:4:5:___");
		mactest(0,"1:2:3:___:5:8");
		mactest(0,"___:2:3:4:5:8");
		mactest(0,"1:2:3:4:5:___");
		mactest(0,"___:2:3:4:5:6:7:8");
		mactest(0,"___:2:3:4:5:6");
		mactest(0,"1:2:3:4:5:___");

		mactest(0,"11:11:11:ff:_2_:0");
		mactest(0,"_2_:11:11:11:1:1");
		mactest(0,"1:2:3:4:_2_:6:7:8");
		mactest(0,"1:2:_2_:4:5:6:7:8");
		mactest(0,"1:2:3:4:5:_2_");
		mactest(0,"1:2:3:_2_:5:8");
		mactest(0,"_2_:2:3:4:5:8");
		mactest(0,"1:2:3:4:5:_2_");
		mactest(0,"_2_:2:3:4:5:6:7");
		mactest(0,"_2_:2:3:4:5:6");
		
		mactest(0,"11:11:11:ff:_2:0");
		mactest(0,"_2:11:11:11:1:1");
		mactest(0,"1:2:3:4:_2:6:7:8");
		mactest(0,"1:2:_2:4:5:6:7:8");
		mactest(0,"1:2:3:4:5:_2");
		mactest(0,"1:2:3:_2:5:8");
		mactest(0,"_2:2:3:4:5:8");
		mactest(0,"1:2:3:4:5:_2");
		mactest(0,"_2:2:3:4:5:6:7:8");
		mactest(0,"_2:2:3:4:5:6");
		
		mactest(1,"11:11:11:ff:2_:0");
		mactest(1,"2_:11:11:11:1:1");
		mactest(1,"1:2:3:4:2_:6:7:8");
		mactest(1,"1:2:2_:4:5:6:7:8");
		mactest(1,"1:2:3:4:5:2_");
		mactest(1,"1:2:3:2_:5:8");
		mactest(1,"2_:2:3:4:5:8");
		mactest(1,"1:2:3:4:5:2_");
		mactest(1,"2_:2:3:4:5:6:7:8");
		mactest(1,"2_:2:3:4:5:6");
		
		
		testMatches(true, "11:11:11:ff:20-2f:0","11:11:11:ff:2_:0");
		testMatches(true, "20-2f:11:11:11:1:1","2_:11:11:11:1:1");
		testMatches(true, "1:2:3:4:20-2f:6:7:8","1:2:3:4:2_:6:7:8");
		testMatches(true, "1:2:20-2f:4:5:6:7:8","1:2:2_:4:5:6:7:8");
		testMatches(true, "1:2:3:4:5:20-2f","1:2:3:4:5:2_");
		testMatches(true, "1:2:3:20-2f:5:8","1:2:3:2_:5:8");
		testMatches(true, "20-2f:2:3:4:5:8","2_:2:3:4:5:8");
		testMatches(true, "1:2:3:4:5:20-2f","1:2:3:4:5:2_");
		testMatches(true, "20-2f:2:3:4:5:6:7:8","2_:2:3:4:5:6:7:8");
		testMatches(true, "20-2f:2:3:4:5:6","2_:2:3:4:5:6");
		testMatches(true, "11:11:11:ff:0-f:0","11:11:11:ff:_:0");
		testMatches(true, "0-f:11:11:11:1:1","_:11:11:11:1:1");
		testMatches(true, "1:2:3:4:0-f:6:7:8","1:2:3:4:_:6:7:8");
		testMatches(true, "1:2:0-f:4:5:6:7:8","1:2:_:4:5:6:7:8");
		testMatches(true, "1:2:3:4:6:0-f","1:2:3:4:6:_");
		testMatches(true, "1:2:3:0-f:5:6:8:8","1:2:3:_:5:6:8:8");
		testMatches(true, "0-f:2:3:5:ff:8","_:2:3:5:ff:8");
		testMatches(true, "1:11:11:11:1:0-f","1:11:11:11:1:_");
		testMatches(true, "0-f:2:3:4:5:6:7:8","_:2:3:4:5:6:7:8");
		testMatches(true, "0-f:2:3:4:5:6","_:2:3:4:5:6");
		testMatches(true, "1:5:2:3:4:0-f","1:5:2:3:4:_");
		testMatches(true, "11:11:11:ff:*:0","11:11:11:ff:__:0");
		testMatches(true, "*:11:11:11:1:1","__:11:11:11:1:1");
		testMatches(true, "1:2:3:4:*:6:7:8","1:2:3:4:__:6:7:8");
		testMatches(true, "1:2:*:4:5:6:7:8","1:2:__:4:5:6:7:8");
		testMatches(true, "1:2:3:4:5:*","1:2:3:4:5:__");
		testMatches(true, "1:2:3:*:5:8","1:2:3:__:5:8");
		testMatches(true, "*:2:3:4:5:8","__:2:3:4:5:8");
		testMatches(true, "1:2:3:4:5:*","1:2:3:4:5:__");
		testMatches(true, "*:2:3:4:5:6:7:8","__:2:3:4:5:6:7:8");
		testMatches(true, "*:2:3:4:5:6","__:2:3:4:5:6");
		testMatches(true, "1:2:3:4:4:*","1:2:3:4:4:__");
		
		testMatches(true, "0-ff.2.3.4","__.2.3.4");
		testMatches(true, "1.2.3.0-ff","1.2.3.__");
		testMatches(true, "0-f.2.3.4","_.2.3.4");
		testMatches(true, "1.2.3.0-f","1.2.3._");
		testMatches(true, "1.0-fff.3.4","1.___.3.4");
		testMatches(true, "1.2.0-fff.0-f","1.2.___._");
		testMatches(true, "1.*.3.4","1.____.3.4");
		testMatches(true, "1.2.*.0-f","1.2.____._");
		testMatches(true, "*.2.3.4","____.2.3.4");
		testMatches(true, "1.2.3.*","1.2.3.____");
	
		testInsertAndAppend("*:*:*:*:*:*:*:*", "*:*:*:*:*:*:*:*", new int[] {0, 0, 0, 0, 0, 0, 0, 0, 0});
		testInsertAndAppend("a:b:c:d:e:f:aa:bb", "*:*:*:*:*:*:*:*", new int[] {0, 8, 16, 24, 32, 40, 48, 56, 64});
		testInsertAndAppend("*:*:*:*:*:*:*:*", "1:2:3:4:5:6:7:8", new int[] {0, 0, 0, 0, 0, 0, 0, 0, 0});
		
		testInsertAndAppend("a:b:c:d:*:*:*:*", "1:2:3:4:*:*:*:*", new int[] {32, 32, 32, 32, 32, 32, 32, 32, 32});
		testInsertAndAppend("a:b:c:d:e:f:aa:bb", "1:2:3:4:*:*:*:*", new int[] {32, 32, 32, 32, 32, 40, 48, 56, 64});
		testInsertAndAppend("a:b:c:0-1:*:*:*:*", "1:2:3:4:5:6:7:8", new Integer[] {null, null, null, null, 31, 31, 31, 31, 31});
		testInsertAndAppend("a:b:c:d:*:*:*:*", "1:2:3:4:5:6:7:8", new Integer[] {null, null, null, null, 32, 32, 32, 32, 32});
		testInsertAndAppend("a:b:c:d:0-7f:*:*:*", "1:2:3:4:5:6:7:8", new Integer[] {null, null, null, null, null, 33, 33, 33, 33});

		testInsertAndAppend("a:b:*:*:*:*:*:*", "1:2:3:4:*:*:*:*", new int[] {32, 32, 16, 16, 16, 16, 16, 16, 16});
		testInsertAndAppend("a:b:c:d:*:*:*:*", "1:2:*:*:*:*:*:*", new int[] {16, 16, 16, 24, 32, 32, 32, 32, 32});
		testInsertAndAppend("*:*:*:*:*:*:*:*", "1:2:3:4:*:*:*:*", new int[] {0, 0, 0, 0, 0, 0, 0, 0, 0});
		testInsertAndAppend("a:b:c:d:*:*:*:*", "1:2:3:4:5:6:7:8", new Integer[] {null, null, null, null, 32, 32, 32, 32, 32});
		testInsertAndAppend("a:b:c:d:e:f:aa:bb", "1:2:3:4:*:*:*:*", new Integer[] {32, 32, 32, 32, 32, 40, 48, 56, null});

		testReplace("*:*:*:*:*:*:*:*", "*:*:*:*:*:*:*:*");
		testReplace("a:b:c:d:e:f:aa:bb", "*:*:*:*:*:*:*:*");
		testReplace("*:*:*:*:*:*:*:*", "1:2:3:4:5:6:7:8");
		
		testReplace("a:b:c:d:*:*:*:*", "1:2:3:4:*:*:*:*");
		testReplace("a:b:c:d:e:f:aa:bb", "1:2:3:4:*:*:*:*");
		testReplace("a:b:c:0-1:*:*:*:*", "1:2:3:4:5:6:7:8");
		testReplace("a:b:c:d:*:*:*:*", "1:2:3:4:5:6:7:8");
		testReplace("a:b:c:d:0-7f:*:*:*", "1:2:3:4:5:6:7:8");
		
		testReplace("a:b:*:*:*:*:*:*", "1:2:3:4:*:*:*:*");
		testReplace("a:b:c:d:*:*:*:*", "1:2:*:*:*:*:*:*");
		testReplace("*:*:*:*:*:*:*:*", "1:2:3:4:*:*:*:*");
		testReplace("a:b:c:d:*:*:*:*", "1:2:3:4:5:6:7:8");
		testReplace("a:b:c:d:e:f:aa:bb", "1:2:3:4:*:*:*:*");

		testPrefixBlock("ff:*:*:*:*:*", 8);
		testPrefixBlock("ff:ff:*:*:*:*", 16);
		testPrefixBlock("ff:fe-ff:*:*:*:*", 15);
		testPrefixBlock("ff:fc-ff:*:*:*:*", 14);
		testPrefixBlock("ff:ff:80-ff:*:*:*", 17);
		testPrefixBlock("ff:ff:0-7f:*:*:*", 17);
		testPrefixBlock("ff:ff:0-3f:*:*:*", 18);
		testPrefixBlock("ff:0:0:ff:0:*", 40);
		testPrefixBlock("ff:0:0:ff:0:fe-ff", 47);
		
		testIncrement("ff:ff:ff:ff:ff:1-2:2-3:ff", 0, "ff:ff:ff:ff:ff:1:2:ff");
		testIncrement("ff:ff:ff:ff:ff:1-2:2-3:ff", 2, "ff:ff:ff:ff:ff:2:2:ff");
		testIncrement("ff:ff:ff:ff:ff:1-2:2-3:ff", 3, "ff:ff:ff:ff:ff:2:3:ff");
		testIncrement("ff:ff:ff:ff:ff:1-2:2-3:ff", 4, "ff:ff:ff:ff:ff:2:4:0");
		testIncrement("ff:ff:ff:ff:ff:fe-ff:fe-ff:ff", 4, null);
		
		testIncrement("ff:ff:ff:1-2:2-3:ff", 0, "ff:ff:ff:1:2:ff");
		testIncrement("ff:ff:ff:1-2:2-3:ff", 2, "ff:ff:ff:2:2:ff");
		testIncrement("ff:ff:ff:1-2:2-3:ff", 3, "ff:ff:ff:2:3:ff");
		testIncrement("ff:ff:ff:1-2:2-3:ff", 4, "ff:ff:ff:2:4:0");
		testIncrement("ff:ff:ff:fe-ff:fe-ff:ff", 4, null);
		
		testIncrement("ff:ff:ff:ff:ff:1-2:2-3:ff", -0x102fbL, "ff:ff:ff:ff:ff:0:0:4");
		testIncrement("ff:ff:ff:ff:ff:1-2:2-3:ff", -0x102fcL, "ff:ff:ff:ff:ff:0:0:3");
		testIncrement("ff:ff:ff:ff:ff:1-2:2-3:ff", -0x102ffL, "ff:ff:ff:ff:ff:0:0:0");
		testIncrement("ff:ff:ff:ff:ff:1-2:2-3:ff", -0x10300L, "ff:ff:ff:ff:fe:ff:ff:ff");
		testIncrement("0:0:0:0:0:1-2:2-3:ff", -0x10300L, null);
		
		testIncrement("ff:ff:ff:1-2:2-3:ff", -0x102fbL, "ff:ff:ff:0:0:4");
		testIncrement("ff:ff:ff:1-2:2-3:ff", -0x102fcL, "ff:ff:ff:0:0:3");
		testIncrement("ff:ff:ff:1-2:2-3:ff", -0x102ffL, "ff:ff:ff:0:0:0");
		testIncrement("ff:ff:ff:1-2:2-3:ff", -0x10300L, "ff:ff:fe:ff:ff:ff");
		testIncrement("0:0:0:1-2:2-3:ff", -0x10300L, null);
		
		testIncrement("ff:3-4:ff:ff:ff:1-2:2-3:0", 6, "ff:4:ff:ff:ff:2:2:0");
		testIncrement("ff:3-4:ff:ff:ff:1-2:2-3:0", 8, "ff:4:ff:ff:ff:2:3:1");
		
		testIncrement("3-4:ff:ff:1-2:2-3:0", 6, "4:ff:ff:2:2:0");
		testIncrement("3-4:ff:ff:1-2:2-3:0", 8, "4:ff:ff:2:3:1");
		
		super.runTest();
	}
	
}