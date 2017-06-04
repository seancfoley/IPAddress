package inet.ipaddr.test;

import java.util.ArrayList;

import inet.ipaddr.HostName;
import inet.ipaddr.HostNameParameters;
import inet.ipaddr.IPAddress;
import inet.ipaddr.IPAddressString;
import inet.ipaddr.IPAddressStringParameters;
import inet.ipaddr.IPAddressStringParameters.RangeParameters;
import inet.ipaddr.IPAddressTypeException;
import inet.ipaddr.ipv4.IPv4Address;
import inet.ipaddr.ipv4.IPv4AddressSection;
import inet.ipaddr.ipv6.IPv6Address;
import inet.ipaddr.ipv6.IPv6AddressSection.CompressOptions;
import inet.ipaddr.ipv6.IPv6AddressSection.IPv6StringOptions;
import inet.ipaddr.test.IPAddressTest.HostKey;
import inet.ipaddr.test.IPAddressTest.IPAddressStringKey;

public abstract class TestBase {
	
	static class Failure {
		IPAddressString addr;
		IPAddress addrValue;
		HostName host;
		String str;
		StackTraceElement[] stack;
		Class<? extends TestBase> testClass;
		
		Failure(boolean pass, IPAddressString addr) {
			this.addr = addr;
		}
		
		Failure(String str) {
			this.str = str;
		}
		
		Failure(String str, IPAddressString addr) {
			this.str = str;
			this.addr = addr;
		}
		
		Failure(String str, IPAddress addrValue) {
			this.str = str;
			this.addrValue = addrValue;
		}
	
		Failure(boolean pass, HostName addr) {
			this.host = addr;
		}
		
		Failure(String str, HostName addr) {
			this.str = str;
			this.host = addr;
		}
		
		String getObjectDescriptor() {
			if(addr != null) {
				return addr.toString();
			}
			if(addrValue != null) {
				return addrValue.toString();
			}
			if(host != null) {
				return host.toString();
			}
			return "<unknown>";
		}
	}
	
	static class Failures {
		ArrayList<Failure> failures = new ArrayList<Failure>();
		int numTested;
		
		void addFailure(Failure failure, Class<? extends TestBase> testClass) {
			failures.add(failure);
			failure.stack = new Throwable().getStackTrace();
			failure.testClass = testClass;
		}
		
		void incrementTestCount() {
			numTested++;
		}
		
		synchronized void add(Failures fails) {
			numTested += fails.numTested;
			failures.addAll(fails.failures);
		}
		
		void report() {
			String failurestr = "";
			int failurestrCount = 0;
			
			for(Failure f : failures) {
				String addrStrng = f.getObjectDescriptor(); 	
				failurestr += ' ';
				if(f.str != null && f.str.length() > 0) {
					failurestr += f.str;
					failurestr += ", ";
				}
				failurestr += addrStrng;
				failurestrCount++;
			}
			
			int numFailed = failures.size();
			showMessage("test count: " + numTested);
			showMessage("fail count: " + numFailed);
			if(failurestrCount > 0) {
				showMessage("Failed:\n" + failurestr);
			}
			
		}
	}
	
	static class Perf {
		ArrayList<Long> runTimes = new ArrayList<Long>();
		
		void addTime(long time) {
			runTimes.add(time);
		}
		
		void report() {
			if(runTimes.isEmpty()) {
				return;
			}
			String str = "";
			int count = 0;
			for(Long time : runTimes) {
				//str += "" + ++count + ". " + time + " milliseconds" + System.lineSeparator();
				str += "" + ++count + ". " + (time / 1000000) + " milliseconds" + System.lineSeparator();
			}
			showMessage("times:" + System.lineSeparator() + str);
		}
	}
	
	static void showMessage(String s) {
		System.out.println(s);
	}
	
	protected static final HostNameParameters HOST_OPTIONS = new HostNameParameters.Builder().
			allowEmpty(false).
			setEmptyAsLoopback(false).
			setNormalizeToLowercase(true).
			allowBracketedIPv6(true).
			allowBracketedIPv4(true).getAddressOptionsBuilder().
				allowPrefix(true).
				allowMask(true).
				setRangeParameters(RangeParameters.NO_RANGE).
				allow_inet_aton(false).
				allowEmpty(false).
				setEmptyAsLoopback(false).
				allowAll(false).
				allowPrefixOnly(true).
				getIPv4AddressParametersBuilder().
						allowLeadingZeros(true).
						allowUnlimitedLeadingZeros(false).
						allowPrefixLengthLeadingZeros(true).
						allowPrefixesBeyondAddressSize(false).
						allowWildcardedSeparator(true).getParentBuilder().
				getIPv6AddressParametersBuilder().
						allowLeadingZeros(true).
						allowUnlimitedLeadingZeros(false).
						allowPrefixLengthLeadingZeros(true).
						allowPrefixesBeyondAddressSize(false).
						allowWildcardedSeparator(true).
						allowMixed(true).
						allowZone(true).
						getParentBuilder().getParentBuilder().toOptions();
	
	protected static final IPAddressStringParameters ADDRESS_OPTIONS = HOST_OPTIONS.toAddressOptionsBuilder().toParams();

	protected static final HostNameParameters HOST_INET_ATON_WILDCARD_AND_RANGE_OPTIONS = new HostNameParameters.Builder().
			allowEmpty(false).
			setEmptyAsLoopback(false).
			setNormalizeToLowercase(true).
			allowBracketedIPv6(true).
			allowBracketedIPv4(true).getAddressOptionsBuilder().
				allowPrefix(true).
				allowMask(true).
				setRangeParameters(RangeParameters.WILDCARD_AND_RANGE).
				allow_inet_aton(true).
				allowEmpty(false).
				setEmptyAsLoopback(false).
				allowAll(false).
				allowPrefixOnly(false).
				getIPv4AddressParametersBuilder().
						allowPrefixLengthLeadingZeros(true).
						allowPrefixesBeyondAddressSize(false).
						allowWildcardedSeparator(true).
						getParentBuilder().getParentBuilder().toOptions();
	
	protected static final IPAddressStringParameters INET_ATON_WILDCARD_AND_RANGE_OPTIONS = HOST_INET_ATON_WILDCARD_AND_RANGE_OPTIONS.toAddressOptionsBuilder().toParams();
			
	protected static final HostNameParameters HOST_INET_ATON_OPTIONS = HOST_OPTIONS.toBuilder().getAddressOptionsBuilder().
			allow_inet_aton(true).getParentBuilder().toOptions();

	boolean fullTest = false;
	final Failures failures = new Failures();
	final Perf perf = new Perf();
	private final AddressCreator addressCreator;
	
	TestBase(AddressCreator creator) {
		this.addressCreator = creator;
	}
	
	protected HostName createHost(HostKey key) {
		return addressCreator.createHost(key);
	}
	
	protected IPAddressString createAddress(IPAddressStringKey key) {
		return addressCreator.createAddress(key);
	}
	
	protected IPAddress createAddress(byte bytes[]) {
		return addressCreator.createAddress(bytes);
	}

	protected HostName createHost_inet_aton(String x) {
		return createHost(new HostKey(x, HOST_INET_ATON_OPTIONS));
	}
	
	protected HostName createHost(String x) {
		return createHost(new HostKey(x, HOST_OPTIONS));
	}
	
	protected HostName createHost(String x, HostNameParameters options) {
		return createHost(new HostKey(x, options));
	}
	
	protected IPAddressString createInetAtonAddress(String x) {
		return createAddress(x, INET_ATON_WILDCARD_AND_RANGE_OPTIONS);
	}
	
	protected IPAddressString createAddress(String x, IPAddressStringParameters opts) {
		IPAddressStringKey key = new IPAddressStringKey(x, opts);
		return createAddress(key);
	}
	
	protected IPAddressString createAddress(String x) {
		return createAddress(new IPAddressStringKey(x, ADDRESS_OPTIONS));
	}
	
	void addFailure(Failure failure) {
		failures.addFailure(failure, getClass());
	}
	
	void incrementTestCount() {
		failures.incrementTestCount();
	}
	
	void report() {
		showMessage(getClass().getSimpleName());
		perf.report();
		failures.report();
		showMessage("Done: " + getClass().getSimpleName() + "\n");
	}
	
	abstract void runTest();
	
	void testIPv4Strings(IPAddressString w, IPAddress ipAddr, String normalizedString, String normalizedWildcardString, String sqlString, String fullString, String octalString, String hexString, String reverseDNSString) {
		testStrings(w, ipAddr, normalizedString, normalizedWildcardString, normalizedWildcardString, sqlString, fullString, normalizedString, normalizedString, normalizedWildcardString, normalizedString, normalizedWildcardString, reverseDNSString, normalizedString);
	
		//now test some IPv4-only strings
		testIPv4OnlyStrings(w, (IPv4Address) ipAddr, octalString, hexString);
		testInetAtonCombos(w, (IPv4Address) ipAddr);
	}
	
	private void testIPv4OnlyStrings(IPAddressString w, IPv4Address ipAddr, String octalString, String hexString) {
		String oct = ipAddr.toInetAtonString(IPv4Address.inet_aton_radix.OCTAL);
		String hex = ipAddr.toInetAtonString(IPv4Address.inet_aton_radix.HEX);
		
		boolean octMatch = oct.equals(octalString);
		if(!octMatch) {
			addFailure(new Failure("failed expected: " + octalString + " actual: " + oct, w));
		} else {
			boolean hexMatch = hex.equals(hexString);
			if(!hexMatch) {
				addFailure(new Failure("failed expected: " + hexString + " actual: " + hex, w));
			}
		}
		incrementTestCount();
	}
	
	void testInetAtonCombos(IPAddressString w, IPv4Address ipAddr) {
		for(IPv4Address.inet_aton_radix radix : IPv4Address.inet_aton_radix.values()) {
			for(int i = 0; i < IPv4Address.SEGMENT_COUNT; i++) {
				try {
					String str = ipAddr.toInetAtonString(radix, i);
					IPAddressString parsed = new IPAddressString(str, INET_ATON_WILDCARD_AND_RANGE_OPTIONS);
					try {
						IPAddress parsedValue = parsed.getAddress();
						if(!ipAddr.equals(parsedValue)) {
							addFailure(new Failure("failed expected: " + ipAddr + " actual: " + parsedValue, w));
						} else {
							int pos;
							int count = 0;
							while ((pos = str.indexOf(IPv4Address.SEGMENT_SEPARATOR)) >= 0) {
								str = str.substring(pos + 1);
								count++;
							}
							if(IPv4Address.SEGMENT_COUNT - 1 - i != count) {
								addFailure(new Failure("failed expected separator count: " + (IPv4Address.SEGMENT_COUNT - 1 - i) + " actual separator count: " + count, w));
							}
						}
					} catch(IPAddressTypeException e) {
						addFailure(new Failure("failed expected: " + ipAddr + " actual: " + e.getMessage(), w));
					}
				} catch(IPAddressTypeException e) {
					//verify this case: joining segments results in a joined segment that is not a contiguous range
					IPv4AddressSection section =  ipAddr.getSection();
					boolean verifiedIllegalJoin = false;
					for(int j = section.getSegmentCount() - i - 1; j < section.getSegmentCount() - 1; j++) {
						if(section.getSegment(j).isMultiple()) {
							for(j++; j < section.getSegmentCount(); j++) {
								if(!section.getSegment(j).isFullRange()) {
									verifiedIllegalJoin = true;
									break;
								}
							}
						}
					}
					if(!verifiedIllegalJoin) {
						addFailure(new Failure("failed expected: " + ipAddr + " actual: " + e.getMessage(), w));
					}
				}
				incrementTestCount();
			}
		}
	}
	
	void testIPv6Strings(IPAddressString w, IPAddress ipAddr,  
			String normalizedString,
			String normalizedWildcardString,
			String canonicalWildcardString,
			String sqlString, 
			String fullString,
			String compressedString,
			String canonicalString,
			String subnetString,
			String compressedWildcardString,
			String mixedStringNoCompressMixed,
			String mixedStringNoCompressHost,
			String mixedStringCompressCoveredHost,
			String mixedString,
			String reverseDNSString,
			String uncHostString) {
		
		testStrings(w, ipAddr, normalizedString, normalizedWildcardString, canonicalWildcardString, sqlString, fullString, compressedString, canonicalString, subnetString, subnetString, compressedWildcardString, reverseDNSString, uncHostString);
		
		//now test some IPv6-only strings
		testIPv6OnlyStrings(w, (IPv6Address) ipAddr, mixedStringNoCompressMixed,
				mixedStringNoCompressHost, mixedStringCompressCoveredHost, mixedString);
	}

	private void testIPv6OnlyStrings(IPAddressString w, IPv6Address ipAddr,
			String mixedStringNoCompressMixed,
			String mixedStringNoCompressHost,
			String mixedStringCompressCoveredHost,
			String mixedString) {
		
		String m = ipAddr.toMixedString();
		boolean nMatch = m.equals(mixedString);
		if(!nMatch) {
			addFailure(new Failure("failed expected: " + mixedString + " actual: " + m, w));
		} else {
			CompressOptions compressOpts = new CompressOptions(true, CompressOptions.CompressionChoiceOptions.ZEROS_OR_HOST, CompressOptions.MixedCompressionOptions.COVERED_BY_HOST);
			IPv6StringOptions mixedParams = new IPv6StringOptions.Builder().setMakeMixed(true).setCompressOptions(compressOpts).toParams();
			String mixedCompressCoveredHost = ipAddr.toNormalizedString(mixedParams);
			boolean mccMatch = mixedCompressCoveredHost.equals(mixedStringCompressCoveredHost);
			if(!mccMatch) {
				addFailure(new Failure("failed expected: " + mixedStringCompressCoveredHost + " actual: " + mixedCompressCoveredHost, w));
			} else {
				compressOpts = new CompressOptions(true, CompressOptions.CompressionChoiceOptions.ZEROS_OR_HOST, CompressOptions.MixedCompressionOptions.NO_HOST);
				mixedParams = new IPv6StringOptions.Builder().setMakeMixed(true).setCompressOptions(compressOpts).toParams();
				String mixedNoCompressHost = ipAddr.toNormalizedString(mixedParams);
				boolean msMatch = mixedNoCompressHost.equals(mixedStringNoCompressHost);
				if(!msMatch) {
					addFailure(new Failure("failed expected: " + mixedStringNoCompressHost + " actual: " + mixedNoCompressHost, w));
				} else {
					compressOpts = new CompressOptions(true, CompressOptions.CompressionChoiceOptions.ZEROS_OR_HOST, CompressOptions.MixedCompressionOptions.NO);
					mixedParams = new IPv6StringOptions.Builder().setMakeMixed(true).setCompressOptions(compressOpts).toParams();
					String mixedNoCompressMixed = ipAddr.toNormalizedString(mixedParams);
					boolean mncmMatch = mixedNoCompressMixed.equals(mixedStringNoCompressMixed);
					if(!mncmMatch) {
						addFailure(new Failure("failed expected: " + mixedStringNoCompressMixed + " actual: " + mixedNoCompressMixed, w));
					}
				}
			}
		}
		
		
		incrementTestCount();
	}
	
	void testHostAddress(String addressStr) {
		IPAddressString str = createAddress(addressStr);
		IPAddress address = str.getAddress();
		if(address != null) {
			IPAddress hostAddress = str.getHostAddress();
			int prefixIndex = addressStr.indexOf(IPAddress.PREFIX_LEN_SEPARATOR);
			if(prefixIndex < 0) {
				if(!address.contains(hostAddress)) {
					addFailure(new Failure("failed host address: " + hostAddress + " expected: " + address, str));
				}
			} else {
				String substr = addressStr.substring(0, prefixIndex);
				IPAddressString str2 = createAddress(substr);
				IPAddress address2 = str2.getAddress();
				if(!address2.equals(hostAddress)) {
					addFailure(new Failure("failed host address: " + hostAddress + " expected: " + address, str));
				}
			}
		}
	}
	
	void testStrings(IPAddressString w,
			IPAddress ipAddr,
			String normalizedString,
			String normalizedWildcardString,
			String canonicalWildcardString,
			String sqlString,
			String fullString,
			String compressedString,
			String canonicalString,
			String subnetString,
			String cidrString,
			String compressedWildcardString,
			String reverseDNSString,
			String uncHostString) {
		testHostAddress(w.toString());
		
		String c = ipAddr.toCompressedString();
		String canonical = ipAddr.toCanonicalString();
		String s = ipAddr.toSubnetString();
		String cidr = ipAddr.toNetworkPrefixLengthString();
		String n = ipAddr.toNormalizedString();
		String nw = ipAddr.toNormalizedWildcardString();
		String caw = ipAddr.toCanonicalWildcardString();
		String cw = ipAddr.toCompressedWildcardString();
		String sql = ipAddr.toSQLWildcardString();
		String full = ipAddr.toFullString();
		String rDNS = ipAddr.toReverseDNSLookupString();
		String unc = ipAddr.toUNCHostName();
		
//		System.out.print("\"" + n + "\", \"" + nw + "\", \"" + sql + "\", \"" + full + "\", \"" + c + "\", \"" + 
//				canonical + "\", \"" + s + "\", \"" +
//				//cidr + "\", " +
//				"\"" + cw);
		
		
//		try {
//			if(ipAddr.isIPv6()) {
//			String hex = ipAddr.toHexString(true);
//			String hex2 = ipAddr.toHexString(false);
//			System.out.println("" + hex + " " + hex2);
//			}
//		} catch(IPAddressTypeException e) {
//			System.out.println("not hexable: " + caw);
//		}
		
		boolean nMatch = normalizedString.equals(n);
		if(!nMatch) {
			addFailure(new Failure("failed expected: " + normalizedString + " actual: " + n, w));
		} else {
			boolean nwMatch = normalizedWildcardString.equals(nw);
			if(!nwMatch) {
				addFailure(new Failure("failed expected: " + normalizedWildcardString + " actual: " + nw, w));
			}  else {
				boolean cawMatch = canonicalWildcardString.equals(caw);
				if(!cawMatch) {
					addFailure(new Failure("failed expected: " + canonicalWildcardString + " actual: " + caw, w));
				} else {
					boolean cMatch = compressedString.equals(c);
					if(!cMatch) {
						addFailure(new Failure("failed expected: " + compressedString + " actual: " + c, w));
					} else {
						boolean sMatch = subnetString.equals(s);
						if(!sMatch) {
							addFailure(new Failure("failed expected: " + subnetString + " actual: " + s, w));
						} else {
							boolean cwMatch = compressedWildcardString.equals(cw);
							if(!cwMatch) {
								addFailure(new Failure("failed expected: " + compressedWildcardString + " actual: " + cw, w));
							} else {
								boolean wMatch = sqlString.equals(sql);
								if(!wMatch) {
									addFailure(new Failure("failed expected: " + sqlString + " actual: " + sql, w));
								} else {
									boolean cidrMatch = cidrString.equals(cidr);
									if(!cidrMatch) {
										addFailure(new Failure("failed expected: " + cidrString + " actual: " + cidr, w));
									} else {
										boolean canonicalMatch = canonicalString.equals(canonical);
										if(!canonicalMatch) {
											addFailure(new Failure("failed expected: " + canonicalString + " actual: " + canonical, w));
										} else {
											boolean fullMatch = fullString.equals(full);
											if(!fullMatch) {
												addFailure(new Failure("failed expected: " + fullString + " actual: " + full, w));
											} else {
												boolean rdnsMatch = reverseDNSString.equals(rDNS);
												if(!rdnsMatch) {
													addFailure(new Failure("failed expected: " + reverseDNSString + " actual: " + rDNS, w));
												} else {
													boolean uncMatch = uncHostString.equals(unc);
													if(!uncMatch) {
														addFailure(new Failure("failed expected: " + uncHostString + " actual: " + unc, w));
													}
												}
											}
										}
									}
								}
							}
						}
					}
				}
			}
		}
		incrementTestCount();
	}
	void hostLabelsTest(String x, String labels[]) {
		HostName host = createHost(x);
		hostLabelsTest(host, labels);
	}
	
	void hostLabelsTest(HostName host, String labels[]) {
		if(host.getNormalizedLabels().length != labels.length) {
			addFailure(new Failure("normalization length " + host.getNormalizedLabels().length, host));
		} else {
			for(int i = 0; i < labels.length; i++) {
				if(!labels[i].equals(host.getNormalizedLabels()[i])) {
					addFailure(new Failure("normalization label " + host.getNormalizedLabels()[i] + " not expected label " + labels[i], host));
					break;
				}
			}
		}
		incrementTestCount();
	}
}
