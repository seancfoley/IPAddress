/*
 * Copyright 2018 Sean C Foley
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
package inet.ipaddr.format.validate;

import java.io.Serializable;
import java.math.BigInteger;
import java.util.Objects;

import inet.ipaddr.Address;
import inet.ipaddr.AddressNetwork.AddressSegmentCreator;
import inet.ipaddr.AddressNetwork.PrefixConfiguration;
import inet.ipaddr.HostIdentifierString;
import inet.ipaddr.IPAddress;
import inet.ipaddr.IPAddress.IPVersion;
import inet.ipaddr.IPAddressNetwork;
import inet.ipaddr.IPAddressSection;
import inet.ipaddr.IPAddressSegment;
import inet.ipaddr.IPAddressSeqRange;
import inet.ipaddr.IPAddressStringParameters;
import inet.ipaddr.IncompatibleAddressException;
import inet.ipaddr.format.AddressItem;
import inet.ipaddr.format.IPAddressDivisionSeries;
import inet.ipaddr.format.large.IPAddressLargeDivision;
import inet.ipaddr.format.large.IPAddressLargeDivisionGrouping;
import inet.ipaddr.format.standard.IPAddressBitsDivision;
import inet.ipaddr.format.standard.IPAddressDivisionGrouping;
import inet.ipaddr.ipv4.IPv4Address;
import inet.ipaddr.ipv4.IPv4AddressNetwork.IPv4AddressCreator;
import inet.ipaddr.ipv4.IPv4AddressSection;
import inet.ipaddr.ipv4.IPv4AddressSegment;
import inet.ipaddr.ipv4.IPv4AddressSeqRange;
import inet.ipaddr.ipv6.IPv6Address;
import inet.ipaddr.ipv6.IPv6AddressNetwork.IPv6AddressCreator;
import inet.ipaddr.ipv6.IPv6AddressSection;
import inet.ipaddr.ipv6.IPv6AddressSegment;

/**
 * The result from parsing a valid address string.  This can be converted into an {@link IPv4Address} or {@link IPv6Address} instance.
 * 
 * @author sfoley
 *
 */
public class ParsedIPAddress extends IPAddressParseData implements IPAddressProvider {

	private static final long serialVersionUID = 4L;
	private static final ExtendedMasker DEFAULT_MASKER = new ExtendedMasker(true);
	private static final ExtendedMasker DEFAULT_NON_SEQUENTIAL_MASKER = new ExtendedMasker(false);
	
	private static final ExtendedFullRangeMasker EXTENDED_FULL_RANGE_MASKERS[] = new ExtendedFullRangeMasker[(Long.SIZE << 1) + 1];
	private static final ExtendedFullRangeMasker EXTENDED_SEQUENTIAL_FULL_RANGE_MASKERS[] = new ExtendedFullRangeMasker[(Long.SIZE << 1) + 1];
	
	private static final WrappedMasker WRAPPED_FULL_RANGE_MASKERS[] = new WrappedMasker[Long.SIZE + 1];
	private static final WrappedMasker WRAPPED_SEQUENTIAL_FULL_RANGE_MASKERS[] = new WrappedMasker[Long.SIZE + 1];
	
	private static final FullRangeMasker FULL_RANGE_MASKERS[] = new FullRangeMasker[Long.SIZE + 1];
	private static final FullRangeMasker SEQUENTIAL_FULL_RANGE_MASKERS[] = new FullRangeMasker[Long.SIZE + 1];
	
	private static final BitwiseOrer DEFAULT_OR_MASKER = new BitwiseOrer(true);
	private static final BitwiseOrer DEFAULT_NON_SEQUENTIAL_OR_MASKER = new BitwiseOrer(false);
	private static final FullRangeBitwiseOrer FULL_RANGE_OR_MASKERS[] = new FullRangeBitwiseOrer[Long.SIZE + 1];
	private static final FullRangeBitwiseOrer SEQUENTIAL_FULL_RANGE_OR_MASKERS[] = new FullRangeBitwiseOrer[Long.SIZE + 1];

	private static final BigInteger ONE_EXTENDED = new BigInteger(1, new byte[] {1, 0, 0, 0, 0, 0, 0, 0, 0});
	private static final BigInteger HIGH_BIT = new BigInteger(1, new byte[] {(byte) 0x80, 0, 0, 0, 0, 0, 0, 0});
	private static final BigInteger ONE_SHIFTED[] = new BigInteger[64];
	private static final BigInteger ONE_SHIFTED_EXTENDED[] = new BigInteger[64];
	private static final BigInteger NETWORK_MASK_EXTENDED[] = new BigInteger[64];
	private static final BigInteger HOST_MASK_EXTENDED[] = new BigInteger[64];
	
	static class CachedIPAddresses<T extends IPAddress> implements Serializable {
		
		private static final long serialVersionUID = 4L;
		
		//address is 1.2.0.0/16 and hostAddress is 1.2.3.4 for the string 1.2.3.4/16
		protected T address, hostAddress;
		
		CachedIPAddresses() {}

		public CachedIPAddresses(T address) {
			this(address, address);
		}
		
		public CachedIPAddresses(T address, T hostAddress) {
			this.address = address;
			this.hostAddress = hostAddress;
		}
		
		public T getAddress() {
			return address;
		}
		
		public T getHostAddress() {
			return hostAddress;
		}
	}
	
	abstract class TranslatedResult<T extends IPAddress, R extends IPAddressSection> extends CachedIPAddresses<T> {

		private static final long serialVersionUID = 4L;
		
		private R section, hostSection, lowerSection, upperSection;
		
		private IncompatibleAddressException joinHostException, joinAddressException /* inet_aton, single seg */, mixedException, maskException;

		private IPAddressSeqRange range;
		private T rangeLower, rangeUpper;

		private IPAddressDivisionSeries series;

		abstract ParsedAddressCreator<T, R, ?, ?> getCreator();
		
		@Override
		public T getAddress() {
			if(address == null) {
				// If an address is present we use it to construct the range.
				// So we need only share the boundaries when they were constructed first.
				if(range == null) {
					address = getCreator().createAddressInternal(section, getZone(), originator);
				} else {
					address = getCreator().createAddressInternal(section, getZone(), originator, rangeLower, rangeUpper);
				}
			}
			return address;
		}
		
		boolean hasLowerSection() {
			return lowerSection != null;
		}
		
		boolean hasHostAddress() {
			return hostAddress != null;
		}
		
		boolean hasAddress() {
			return address != null;
		}

		@Override
		public T getHostAddress() {
			if(hostSection == null) {
				return getAddress();
			}
			if(hostAddress == null) {
				hostAddress = getCreator().createAddressInternal(hostSection, getZone(), null);
			}
			return hostAddress;
		}
		
		R getSection() {
			return section;
		}
		
		private CharSequence getZone() {
			return getQualifier().getZone();
		}
		
		boolean withoutSections() {
			return section == null;
		}
		
		boolean withoutAddressException() {
			return joinAddressException == null && mixedException == null && maskException == null;
		}
		
		boolean withoutRange() {
			return range == null;
		}
		
		boolean withoutGrouping() {
			return series == null;
		}
		
		IPAddressSeqRange createRange() {
			//we need to add zone in order to reuse the lower and upper
			rangeLower = getCreator().createAddressInternal(lowerSection, getZone(), null);
			rangeUpper = upperSection == null ? rangeLower : getCreator().createAddressInternal(upperSection, getZone(), null);
			return range = rangeLower.spanWithRange(rangeUpper);
		}
		
		// when this is used, the host address, regular address, and range boundaries are not used
		IPAddress getValForMask() {
			return getCreator().createAddressInternal(lowerSection, null, null);
		}
	}
	
	private final IPAddressStringParameters options;
	private final HostIdentifierString originator;
	
	private TranslatedResult<?,?> values;
	private Masker maskers[];
	private Masker mixedMaskers[];

	ParsedIPAddress(
			HostIdentifierString from, 
			CharSequence addressString,
			IPAddressStringParameters options) {
		super(addressString);
		this.options = options;
		this.originator = from;
	}
	
	private IPv6AddressCreator getIPv6AddressCreator() {
		return getParameters().getIPv6Parameters().getNetwork().getAddressCreator();
	}
	
	private IPv4AddressCreator getIPv4AddressCreator() {
		return getParameters().getIPv4Parameters().getNetwork().getAddressCreator();
	}
	
	@Override
	public boolean isProvidingIPAddress() {
		return true;
	}
	
	@Override
	public IPAddressProvider.IPType getType() {
		return IPType.from(getProviderIPVersion());
	}
	
	@Override
	public IPAddressStringParameters getParameters() {
		return options;
	}

	void createSections(boolean doAddress, boolean doRangeBoundaries, boolean withUpper) {
		IPVersion version = getProviderIPVersion();
		if(version.isIPv4()) {
			createIPv4Sections(doAddress, doRangeBoundaries, withUpper);
		} else if(version.isIPv6()) {
			createIPv6Sections(doAddress, doRangeBoundaries, withUpper);
		}
	}

	@Override
	public IPAddressSeqRange getProviderSeqRange() {
		TranslatedResult<?,?> val = values;
		if(val == null || val.range == null) {
			synchronized(this) {
				val = values;
				if(val == null || val.range == null) {
					if(val != null && !val.withoutSections() && val.withoutAddressException()) {
						val.range = val.getAddress().toSequentialRange();
					} else {
						createSections(false, true, true);
						val = values;
						// creates lower, upper, then range from the two
						val.createRange();
						if(isDoneTranslating()) {
							releaseSegmentData();
						}
					}
				}
			}
		}
		return val.range;
	}

	// This is for parsed addresses which are masks in and of themselves.
	// With masks, only the lower value matters.
	IPAddress getValForMask() {
		TranslatedResult<?,?> val = values;
		if(val == null || !val.hasLowerSection()) {
			synchronized(this) {
				val = values;
				if(val == null || !val.hasLowerSection()) {
					createSections(false, true, false);
					val = values;
					releaseSegmentData(); // As a mask value, we can release our data sooner, there will be no request for address or division grouping
				}
			}
		}
		// requests for masks are single-threaded, so locking no longer required
		return val.getValForMask();
	}
	
	// this is for parsed addresses which have associated masks
	@Override
	public IPAddress getProviderMask() {
		return getQualifier().getMaskLower();
	}

	boolean isDoneTranslating() {
		TranslatedResult<?,?> val = values;
		return !val.withoutSections() /* address sections created */ && 
				(val.withoutAddressException() /* range can be created from sections */
						|| !val.withoutRange() /* range already created (from sections or boundaries) */) &&
				!val.withoutGrouping();
	}

	TranslatedResult<?,?> getCachedAddresses(boolean forHostAddr)  {
		TranslatedResult<?,?> val = values;
		if(val == null || val.withoutSections()) {
			synchronized(this) {
				val = values;
				if(val == null || val.withoutSections()) {
					createSections(true, false, false);
					val = values;
					if(isDoneTranslating()) {
						releaseSegmentData();
					}
				} 
				if(forHostAddr) {
					val.getHostAddress();
				} else {
					val.getAddress();
				}
			}
		} else {
			if(forHostAddr ? !val.hasHostAddress() : !val.hasAddress()) {
				synchronized(this) {
					if(forHostAddr) {
						val.getHostAddress();
					} else {
						val.getAddress();
					}
				}
			}
		}
		return val;
	}

	@Override
	public IPAddress getProviderHostAddress() throws IncompatibleAddressException {
		TranslatedResult<?,?> addrs = getCachedAddresses(true);
		if(addrs.mixedException != null) {
			throw addrs.mixedException;
		} else if(addrs.joinHostException != null) {
			throw addrs.joinHostException;
		}
		return addrs.getHostAddress();
	}
	
	@Override
	public IPAddress getProviderAddress() throws IncompatibleAddressException {
		TranslatedResult<?,?> addrs = getCachedAddresses(false);
		if(addrs.mixedException != null) {
			throw addrs.mixedException;
		} else if(addrs.maskException != null) {
			throw addrs.maskException;
		} else if(addrs.joinAddressException != null) {
			throw addrs.joinAddressException;
		}
		return addrs.getAddress();
	}
	
	@Override
	public IPAddress getProviderAddress(IPVersion version) throws IncompatibleAddressException {
		IPVersion thisVersion = getProviderIPVersion();
		if(!version.equals(thisVersion)) {
			return null;
		}
		return getProviderAddress();
	}
	
	@Override
	public IPAddressDivisionSeries getDivisionGrouping() throws IncompatibleAddressException {
		TranslatedResult<?,?> val = values;
		IPAddressDivisionSeries grouping = null;
		if(val != null) {
			grouping = val.series;
			if(grouping != null) {
				return grouping;
			}
		}		
		if(val == null || (val.withoutSections() && val.withoutRange())) {
			// we need the bit lengths and maskers that are calculated when constructing,
			// so we construct here since not done already
			synchronized(this) {
				val = values;
				if(val == null || (val.withoutSections() && val.withoutRange())) {
					createSections(true, false, false); // create addresses
				}
			}
		}
		// at this point values is not null
		val = values;
		grouping = val.series;
		if(grouping == null) {
			synchronized(val) {
				grouping = val.series;
				if(grouping == null) {
					ParsedHostIdentifierStringQualifier qualifier = getQualifier();
					IPVersion version = getProviderIPVersion();
					int defaultRadix;
					IPAddressNetwork<?, ?, ?, ?, ?> network;
					if(version.isIPv4()) {
						defaultRadix = IPv4Address.DEFAULT_TEXTUAL_RADIX;
						network = getParameters().getIPv4Parameters().getNetwork();
					} else {
						defaultRadix = IPv6Address.DEFAULT_TEXTUAL_RADIX;
						network = getParameters().getIPv6Parameters().getNetwork();
					}
					PrefixConfiguration prefixConfiguration = network.getPrefixConfiguration();
					boolean mixed = isProvidingMixedIPv6();
					AddressParseData addrParseData = getAddressParseData();
					int segmentCount = addrParseData.getSegmentCount();
					int totalCount = segmentCount;
					if(mixed) {
						totalCount += mixedParsedAddress.getSegmentCount();
					}
					Integer prefLength = getPrefixLength(qualifier);
					IPAddress mask = getProviderMask();
					if(mask != null && mask.getBlockMaskPrefixLength(true) != null) {
						mask = null;//we don't do any masking if the mask is a subnet mask, instead we just map it to the corresponding prefix length
					}
					boolean hasMask = mask != null;
					boolean isPrefixSubnet = false;
					if(prefLength != null) {
						if(prefixConfiguration.allPrefixedAddressesAreSubnets()) {
							isPrefixSubnet = true;
						} else if(prefixConfiguration.zeroHostsAreSubnets()) {
							// Note: the mask is not needed for this check
							// This is because you can only have a prefix length with network mask
							// In such cases we convert the mask to the prefix length and do not apply the mask.
							// So here we do not apply the mask either.
							if(mixed) {
								int k = segmentCount;
								isPrefixSubnet = ParsedAddressGrouping.isPrefixSubnet(
										i -> (i < k ? addrParseData.getValue(i, AddressParseData.KEY_LOWER) : mixedParsedAddress.getValue(i - k, AddressParseData.KEY_LOWER)),
										i -> (i < k ? addrParseData.getValue(i, AddressParseData.KEY_EXTENDED_LOWER) : mixedParsedAddress.getValue(i - k, AddressParseData.KEY_EXTENDED_LOWER)),
										i -> (i < k ? addrParseData.getValue(i, AddressParseData.KEY_UPPER) : mixedParsedAddress.getValue(i - k, AddressParseData.KEY_UPPER)),
										i -> (i < k ? addrParseData.getValue(i, AddressParseData.KEY_EXTENDED_UPPER) : mixedParsedAddress.getValue(i - k, AddressParseData.KEY_EXTENDED_UPPER)),
										i -> (i < k ? addrParseData.getBitLength(i) : mixedParsedAddress.getBitLength(i - k)),
										totalCount,
										prefLength,
										prefixConfiguration,
										false);
							} else {
								isPrefixSubnet = ParsedAddressGrouping.isPrefixSubnet(
										i -> addrParseData.getValue(i, AddressParseData.KEY_LOWER),
										i -> addrParseData.getValue(i, AddressParseData.KEY_EXTENDED_LOWER),
										i -> addrParseData.getValue(i, AddressParseData.KEY_UPPER),
										i -> addrParseData.getValue(i, AddressParseData.KEY_EXTENDED_UPPER),
										i -> addrParseData.getBitLength(i),
										totalCount,
										prefLength,
										prefixConfiguration,
										false);
							}
						} else {
							isPrefixSubnet = false;
						}
					}
					boolean isLarge = false;
					for(int i = 0; i < segmentCount; i++) {
						int bitLength = addrParseData.getBitLength(i);
						if(bitLength >= Long.SIZE) {
							isLarge = true;
							break;
						}
					}
					boolean isMergedMixed;
					if(mixed && (isMergedMixed = addrParseData.isMergedMixed(segmentCount - 1))) {
						totalCount--;
						segmentCount--;
						if(!isLarge && addrParseData.getBitLength(segmentCount) + mixedParsedAddress.getBitLength(0) >= Long.SIZE) {
							isLarge = true;
						}
					} else {
						isMergedMixed = false;
					}
					long maskVal = 0, extendedMaskVal = 0;
					int maskBits = 0;
					if(hasMask) {
						// using the mask as an address allows us to line up the segments into two longs
						int bitsPerSegment = mask.getBitsPerSegment();
						for(int i = 0; i < IPv4Address.SEGMENT_COUNT; i++) {
							maskVal = (maskVal << bitsPerSegment) | mask.getSegment(i).getSegmentValue();
						}
						if(mask.isIPv6()) {
							extendedMaskVal = maskVal; maskVal = 0;
							int remainingSegs = IPv6Address.SEGMENT_COUNT >> 1;
							for(int i = 0; i < remainingSegs; i++) {
								maskVal = (maskVal << bitsPerSegment) | mask.getSegment(i + IPv4Address.SEGMENT_COUNT).getSegmentValue();
							}
							maskBits = bitsPerSegment * IPv6Address.SEGMENT_COUNT;
						} else {
							maskBits = bitsPerSegment * IPv4Address.SEGMENT_COUNT;
						}
					}
					int bitsSoFar = 0;
					int divRadix;
					if(isLarge) {
						IPAddressLargeDivision divs[] = new IPAddressLargeDivision[totalCount];
						for(int i = 0; i < totalCount; i++) {
							long lower, upper, extendedLower, extendedUpper;
							int bitLength;
							boolean isExtended;
							boolean isNotMixed = i < segmentCount;
							if(isNotMixed) {
								bitLength = addrParseData.getBitLength(i);
								isExtended = bitLength > Long.SIZE;
								if(addrParseData.isWildcard(i)) {
									extendedLower = lower = 0;
									if(isExtended) {
										upper = 0xffffffffffffffffL;
										int shift = bitLength - Long.SIZE;
										// shift must be 6 bits at most for this shift to work per the java spec (so it must be less than 2^6 = 64)
										extendedUpper = shift == Long.SIZE ? 0xffffffffffffffffL : ~(~0L << shift);
									} else {
										extendedUpper = 0;
										// bitLength must be 6 bits at most for this shift to work per the java spec (so it must be less than 2^6 = 64)
										upper = bitLength == Long.SIZE ? 0xffffffffffffffffL : ~(~0L << bitLength);
									}
								} else {
									lower = addrParseData.getValue(i, AddressParseData.KEY_LOWER);
									upper = addrParseData.getValue(i, AddressParseData.KEY_UPPER);
									extendedLower = addrParseData.getValue(i, AddressParseData.KEY_EXTENDED_LOWER);
									extendedUpper = addrParseData.getValue(i, AddressParseData.KEY_EXTENDED_UPPER);
								}
								divRadix = defaultRadix;
							} else if(isMergedMixed && i == segmentCount) {
								isNotMixed = true;
								// merge the last IPv6 segment with the first IPv4 segment
								bitLength = addrParseData.getBitLength(i) + mixedParsedAddress.getBitLength(0);
								extendedLower = lower = 0;
								isExtended = bitLength > Long.SIZE;
								if(isExtended) {
									upper = 0xffffffffffffffffL;
									// shift must be 6 bits at most for this shift to work per the java spec (so it must be less than 2^6 = 64)
									int shift = bitLength - Long.SIZE;
									extendedUpper = shift == Long.SIZE ? 0xffffffffffffffffL : ~(~0L << shift);
								} else {
									// bitLength must be 6 bits at most for this shift to work per the java spec (so it must be less than 2^6 = 64)
									upper = bitLength == Long.SIZE ? 0xffffffffffffffffL : ~(~0L << bitLength);
									extendedUpper = 0;
								}
								divRadix = defaultRadix;
							} else {
								int adjusted = i - segmentCount;
								bitLength = mixedParsedAddress.getBitLength(adjusted);
								isExtended = false;
								extendedLower = extendedUpper = 0;
								if(mixedParsedAddress.isWildcard(adjusted)) {
									lower = 0;
									upper =  ~(~0L << bitLength);
								} else {
									lower = mixedParsedAddress.getValue(adjusted, AddressParseData.KEY_LOWER);
									upper = mixedParsedAddress.getValue(adjusted, AddressParseData.KEY_UPPER);
								}
								divRadix = IPv4Address.DEFAULT_TEXTUAL_RADIX;
							}
							Integer divPrefixLength;
							if(prefLength == null) {
								divPrefixLength = null;
								if(hasMask) {
									ExtendedMasker masker = (ExtendedMasker) (isNotMixed ? maskers[i] : mixedParsedAddress.maskers[i]);
									if(!masker.isSequential()) {
										throw new IncompatibleAddressException(lower, upper, (extendedMaskVal << 64) | maskVal, "ipaddress.error.maskMismatch");
									}
									long divMask;
									if(isExtended) {
										// adjust the extended mask by shrinking it downwards
										// adjust lower mask by the same amount, copy in the upper mask too
										int extraMaskBits = maskBits - bitLength;
										long extendedDivMask = extendedMaskVal >>> extraMaskBits;
										divMask = (maskVal >>> extraMaskBits) | (extendedMaskVal << (Long.SIZE - extraMaskBits));
										extendedLower = masker.getExtendedMaskedLower(extendedLower, extendedDivMask);
										extendedUpper = masker.getExtendedMaskedUpper(extendedUpper, extendedDivMask);
										lower = masker.getMaskedLower(lower, divMask);
										upper = masker.getMaskedUpper(upper, divMask);
									} else {
										// same as below
										if(maskBits > Long.SIZE) {
											int extendedBits = maskBits - Long.SIZE;
											if(extendedBits >= bitLength) {
												divMask = extendedMaskVal >>> (extendedBits - bitLength);
											} else {
												int shortBits = bitLength - extendedBits;
												divMask = (extendedMaskVal << (shortBits)) | (maskVal >> (Long.SIZE - shortBits));
											}
										} else {
											divMask = maskVal >>> (maskBits - bitLength);
										}
										lower = masker.getMaskedLower(lower, divMask);
										upper = masker.getMaskedUpper(upper, divMask);
									}
									maskBits -= bitLength;
								}
							} else {
								divPrefixLength = ParsedAddressGrouping.getDivisionPrefixLength(bitLength, prefLength - bitsSoFar);
								if(isPrefixSubnet && divPrefixLength != null && divPrefixLength < bitLength) {
									// for values larger than 64 bits, the "extended" values are the upper (aka most significant, leftmost) bits
									int unextendedBitLength, unextendedDivPrefixLength;
									if(isExtended) {
										int extendedDivBitLength = bitLength - Long.SIZE;
										unextendedBitLength = Long.SIZE;
										if(divPrefixLength > extendedDivBitLength) {
											unextendedDivPrefixLength = divPrefixLength - extendedDivBitLength;
										} else {
											unextendedDivPrefixLength = 0;
											int shift = extendedDivBitLength - divPrefixLength;
											if(shift == Long.SIZE) {
												extendedLower = 0;
												extendedUpper = 0xffffffffffffffffL;
											} else {
												long networkMask = ~0L << shift;
												extendedLower = extendedLower & networkMask;
												extendedUpper = extendedUpper | ~networkMask;
											}
										}
									} else {
										unextendedBitLength = bitLength;
										unextendedDivPrefixLength = divPrefixLength;
									}
									int shift = unextendedBitLength - unextendedDivPrefixLength;
									if(shift == Long.SIZE) {
										lower = 0;
										upper = 0xffffffffffffffffL;
									} else {
										long networkMask = ~0L << shift;
										lower = lower & networkMask;
										upper = upper | ~networkMask;
									}
								}
							}
							int numBytes = (bitLength + 7) / Byte.SIZE;
							byte lowerBytes[] = toBytes(lower, extendedLower, numBytes);
							byte upperBytes[] = toBytes(upper, extendedUpper, numBytes);
							divs[i] = new IPAddressLargeDivision(lowerBytes, upperBytes, bitLength, divRadix, network, divPrefixLength);
							bitsSoFar += bitLength;
						}
						grouping = new IPAddressLargeDivisionGrouping(divs, network);
					} else {
						IPAddressBitsDivision divs[] = new IPAddressBitsDivision[totalCount];
						for(int i = 0; i < totalCount; i++) {
							long lower, upper;
							int bitLength;
							if(i < segmentCount) {
								bitLength = addrParseData.getBitLength(i);
								if(addrParseData.isWildcard(i)) {
									lower = 0;
									upper = ~(~0L << bitLength);
								} else {
									lower = addrParseData.getValue(i, AddressParseData.KEY_LOWER);
									upper = addrParseData.getValue(i, AddressParseData.KEY_UPPER);
								}
								divRadix = defaultRadix;
							} else if(isMergedMixed && i == segmentCount) {
								// merge the last IPv6 segment with the first IPv4 segment
								bitLength = addrParseData.getBitLength(i) + mixedParsedAddress.getBitLength(0);
								lower = 0;
								upper = ~(~0L << bitLength);
								divRadix = defaultRadix;
							} else {
								int adjusted = i - segmentCount;
								bitLength = mixedParsedAddress.getBitLength(adjusted);
								if(mixedParsedAddress.isWildcard(adjusted)) {
									lower = 0;
									upper =  ~(~0L << bitLength);
								} else {
									lower = mixedParsedAddress.getValue(adjusted, AddressParseData.KEY_LOWER);
									upper = mixedParsedAddress.getValue(adjusted, AddressParseData.KEY_UPPER);
								}
								divRadix = IPv4Address.DEFAULT_TEXTUAL_RADIX;
							}
							Integer divPrefixLength;
							if(prefLength == null) {
								divPrefixLength = null;
								if(hasMask) {
									Masker masker = maskers[i];
									if(!masker.isSequential()) {
										throw new IncompatibleAddressException(lower, upper, maskVal, "ipaddress.error.maskMismatch");
									}
									long divMask;
									if(maskBits > Long.SIZE) {
										int extendedBits = maskBits - Long.SIZE;
										if(extendedBits >= bitLength) {
											divMask = extendedMaskVal >>> (extendedBits - bitLength);
										} else {
											int shortBits = bitLength - extendedBits;
											divMask = (extendedMaskVal << (shortBits)) | (maskVal >> (Long.SIZE - shortBits));
										}
									} else {
										divMask = maskVal >>> (maskBits - bitLength);
									}	
									maskBits -= bitLength;
									lower = masker.getMaskedLower(lower, divMask);
									upper = masker.getMaskedUpper(upper, divMask);
								}
							} else {
								divPrefixLength = ParsedAddressGrouping.getDivisionPrefixLength(bitLength, prefLength - bitsSoFar);
								if(isPrefixSubnet && divPrefixLength != null) {
									long networkMask = ~0L << (bitLength - divPrefixLength);
									lower = lower & networkMask;
									upper = upper | ~networkMask;
		
								}
							}
							divs[i] = new IPAddressBitsDivision(lower, upper, bitLength, divRadix, network, divPrefixLength);
							bitsSoFar += bitLength;
						}
						grouping = new IPAddressDivisionGrouping(divs, network);
					}
					val.series = grouping;
					if(isDoneTranslating()) {
						releaseSegmentData();
					}
				}
			}
		}
		return grouping;
	}

	public static class BitwiseOrer implements Serializable {
		private static final long serialVersionUID = 1L;
		private final boolean isSequential;

		public BitwiseOrer(boolean isSequential) {
			this.isSequential = isSequential;
		}

		public long getOredLower(long value, long maskValue) {
			return value | maskValue;
		}

		public long getOredUpper(long upperValue, long maskValue) {
			return upperValue | maskValue;
		}

		public boolean isSequential() {
			return isSequential;
		}
	}
	
	// These can be cached by the int used to construct
	public static class FullRangeBitwiseOrer extends BitwiseOrer {
		private static final long serialVersionUID = 1L;
		private final long upperMask;
		public final int fullRangeBit;

		public FullRangeBitwiseOrer(int fullRangeBit, boolean isSequential) {
			super(isSequential);
			this.fullRangeBit = fullRangeBit;
			upperMask = ~0L >>> fullRangeBit;
		}
		
		@Override
		public long getOredLower(long value, long maskValue) {
			return super.getOredLower(value & ~upperMask, maskValue);
		}
		
		@Override
		public long getOredUpper(long upperValue, long maskValue) {
			return super.getOredUpper(upperValue | upperMask, maskValue);
		}
	}
	
	/**
	 * The analog to SpecificValueMasker for oring
	 * @author seancfoley
	 *
	 */
	public static class SpecificValueBitwiseOrer extends BitwiseOrer {
		private static final long serialVersionUID = 1L;
		private final long lower, upper;
		
		public SpecificValueBitwiseOrer(long lower, long upper) {
			super(false);
			this.lower = lower;
			this.upper = upper;
		}
		
		@Override
		public long getOredLower(long value, long maskValue) {
			return super.getOredLower(lower, maskValue);
		}
		
		@Override
		public long getOredUpper(long upperValue, long maskValue) {
			return super.getOredUpper(upper, maskValue);
		}
	}

	public static abstract class Masker implements Serializable {
		private static final long serialVersionUID = 1L;
		private final boolean isSequential;
		
		public Masker(boolean isSequential) {
			this.isSequential = isSequential;
		}
		
		/**
		 * The lowest masked value, which is not necessarily the lowest value masked
		 * @param upperValue
		 * @param maskValue
		 * @return
		 */
		public long getMaskedLower(long value, long maskValue) {
			return value & maskValue;
		}
		
		/**
		 * The highest masked value, which is not necessarily the highest value masked
		 * @param upperValue
		 * @param maskValue
		 * @return
		 */
		public long getMaskedUpper(long upperValue, long maskValue) {
			return upperValue & maskValue;
		}
		
		/**
		 * Whether masking all values in the range results in a sequential set of values
		 * @return
		 */
		public boolean isSequential() {
			return isSequential;
		}
	}

	// These can be cached by the int used to construct
	public static class FullRangeMasker extends Masker {
		private static final long serialVersionUID = 1L;
		private final long upperMask;
		public final int fullRangeBit;
		
		public FullRangeMasker(int fullRangeBit, boolean isSequential) {
			super(isSequential);
			this.fullRangeBit = fullRangeBit;
			upperMask = ~0L >>> fullRangeBit;
		}
		
		@Override
		public long getMaskedLower(long value, long maskValue) {
			return super.getMaskedLower(value & ~upperMask, maskValue);
		}
		
		@Override
		public long getMaskedUpper(long upperValue, long maskValue) {
			return super.getMaskedUpper(upperValue | upperMask, maskValue);
		}
	}

	/**
	 * When the part of a mask covering a range of values is a mix of ones and zeros,
	 * then there may be an intermediate value in the range that when masked, produces the new
	 * upper and lower values.  
	 * 
	 * For instance, consider the simple range 2 to 5 with mask of 2.
	 * The value when masked to give the lowest masked value is not the lowest in the range 2, it is 5.  Masking 5 with 2 gives 0.
	 * The value when masked to give the highest masked value is not the highest in the range 5, it is 2.  Masking 2 with 2 gives 2.
	 * 
	 * When the mask has a 0 in the highest bit in the range of values, then the two values that give the highest and lowest are
	 * 0000... and 1111....  This is because in any range 0xxxx to 1xxxx, the values 01111 and 10000 are in the range (they must be there
	 * to get from 0xxxx to 1xxxx.  And so if you ignore the top bit, the values 0000 and 1111 always give you the lowest and highest.
	 * In this case, FullRangeMasker can be used instead of this class.  For instance, you can use the values 011 to 100 (ie 3 and 4)
	 * to get the ranged values 2 and 0 in the example above.
	 * 
	 * However, when the mask has a 1 bit to match the highest bit in the range of values, you cannot use 01111... and 10000...
	 * In such cases, there are other values that when masked produce the new lowest and highest.
	 * For example, with the range 1 (001) to 6 (110) and the mask of 5 (101), 
	 * the lowest value when masked is 2 (010) to give 0,
	 * and the highest value when masked is 5 (101), to give masked value of 5.
	 * Neither of these values are the range boundaries 1 or 6.  Neither of these values is all ones or all zeros.
	 * This situation can occur when the mask itself is not all ones or all zeros, and when the highest bit in the range (the 3rd bit, ie 100 in the example)
	 * has a corresponding value of 1 in the given mask (101 in the example).
	 * 
	 * 
	 * @author seancfoley
	 *
	 */
	public static class SpecificValueMasker extends Masker {
		private static final long serialVersionUID = 1L;
		private final long lower, upper;
		
		public SpecificValueMasker(long lower, long upper) {
			super(false);
			this.lower = lower;
			this.upper = upper;
		}
		
		@Override
		public long getMaskedLower(long value, long maskValue) {
			return super.getMaskedLower(lower, maskValue);
		}
		
		@Override
		public long getMaskedUpper(long upperValue, long maskValue) {
			return super.getMaskedUpper(upper, maskValue);
		}
	}

	public static class ExtendedMasker extends Masker {
		private static final long serialVersionUID = 1L;

		public ExtendedMasker(boolean isSequential) {
			super(isSequential);
		}
		
		@Deprecated
		public long getExtendedLowerMasked(long extendedValue, long extendedMaskValue) {
			return getExtendedMaskedLower(extendedValue, extendedMaskValue);
		}
		
		@Deprecated
		public long getExtendedUpperMasked(long extendedUpperValue, long extendedMaskValue) {
			return getExtendedMaskedUpper(extendedUpperValue, extendedMaskValue);
		}
		
		public long getExtendedMaskedLower(long extendedValue, long extendedMaskValue) {
			return extendedValue & extendedMaskValue;
		}
		
		public long getExtendedMaskedUpper(long extendedUpperValue, long extendedMaskValue) {
			return extendedUpperValue & extendedMaskValue;
		}
	}

	// These can be cached by the int used to construct
	public static class ExtendedFullRangeMasker extends ExtendedMasker {
		private static final long serialVersionUID = 1L;
		private final long upperMask, extendedUpperMask;

		ExtendedFullRangeMasker(int fullRangeBit, boolean isSequential) {
			super(isSequential);
			if(fullRangeBit >= Long.SIZE) {
				extendedUpperMask = 0;
				upperMask = ~0L >>> (fullRangeBit - Long.SIZE);
			} else {
				extendedUpperMask = ~0L >>> fullRangeBit;
				upperMask = 0xffffffffffffffffL;
			}
		}
		
		@Override
		public long getMaskedLower(long value, long maskValue) {
			return super.getMaskedLower(value & ~upperMask, maskValue);
		}
		
		@Override
		public long getMaskedUpper(long upperValue, long maskValue) {
			return super.getMaskedUpper(upperValue | upperMask, maskValue);
		}
		
		@Override
		public long getExtendedMaskedLower(long extendedValue, long extendedMaskValue) {
			return super.getExtendedMaskedLower(extendedValue & ~extendedUpperMask, extendedMaskValue);
		}
		
		@Override
		public long getExtendedMaskedUpper(long extendedUpperValue, long extendedMaskValue) {
			return super.getMaskedUpper(extendedUpperValue | extendedUpperMask, extendedMaskValue);
		}
	}
	
	public static class ExtendedSpecificValueMasker extends ExtendedMasker {
		/**
		 * 
		 */
		private static final long serialVersionUID = 1L;
		private final long extendedLower, lower, extendedUpper, upper;
		
		public ExtendedSpecificValueMasker(long extendedLower, long lower, long extendedUpper, long upper) {
			super(false);
			this.lower = lower;
			this.upper = upper;
			this.extendedLower = extendedLower;
			this.extendedUpper = extendedUpper;
		}
		
		@Override
		public long getMaskedLower(long value, long maskValue) {
			return super.getMaskedLower(lower, maskValue);
		}
		
		@Override
		public long getMaskedUpper(long upperValue, long maskValue) {
			return super.getMaskedUpper(upper, maskValue);
		}
		
		@Override
		public long getExtendedMaskedLower(long extendedValue, long extendedMaskValue) {
			return super.getExtendedMaskedLower(extendedLower, extendedMaskValue);
		}
		
		@Override
		public long getExtendedMaskedUpper(long extendedUpperValue, long extendedMaskValue) {
			return super.getExtendedMaskedUpper(extendedUpper, extendedMaskValue);
		}
	}
	
	public static class WrappedMasker extends ExtendedMasker {
		/**
		 * 
		 */
		private static final long serialVersionUID = 1L;
		private final Masker masker;
		
		WrappedMasker(Masker masker) {
			super(masker.isSequential());
			this.masker = masker;
		}
		
		@Override
		public long getMaskedLower(long value, long maskValue) {
			return masker.getMaskedLower(value, maskValue);
		}
		
		@Override
		public long getMaskedUpper(long upperValue, long maskValue) {
			return masker.getMaskedUpper(upperValue, maskValue);
		}
	}
	
	/**
	 * @deprecated use maskExtendedRange
	 * 
	 * @param value
	 * @param extendedValue
	 * @param upperValue
	 * @param extendedUpperValue
	 * @param maskValue
	 * @param extendedMaskValue
	 * @param maxValue
	 * @param extendedMaxValue
	 * @return
	 */
	@Deprecated
	public static ExtendedMasker maskRange(
			long value, long extendedValue, 
			long upperValue, long extendedUpperValue, 
			long maskValue, long extendedMaskValue, 
			long maxValue, long extendedMaxValue) {
		return maskExtendedRange(value, extendedValue, 
				upperValue, extendedUpperValue, 
				maskValue, extendedMaskValue, 
				maxValue, extendedMaxValue);
	}
			

	public static ExtendedMasker maskExtendedRange(
			long value, long extendedValue, 
			long upperValue, long extendedUpperValue, 
			long maskValue, long extendedMaskValue, 
			long maxValue, long extendedMaxValue) {
		
		//algorithm:
		//here we find the highest bit that is part of the range, highestDifferingBitInRange (ie changes from lower to upper)
		//then we find the highest bit in the mask that is 1 that is the same or below highestDifferingBitInRange (if such a bit exists)
		
		//this gives us the highest bit that is part of the masked range (ie changes from lower to upper after applying the mask)
		//if this latter bit exists, then any bit below it in the mask must be 1 to include the entire range.
		
		long extendedDiffering = extendedValue ^ extendedUpperValue;
		if(extendedDiffering == 0) {
			// the top is single-valued so just need to check the lower part
			Masker masker = maskRange(value, upperValue, maskValue, maxValue);
			if(masker == DEFAULT_MASKER) {
				return DEFAULT_MASKER;
			}
			if(masker instanceof FullRangeMasker) {
				int fullRangeBit = ((FullRangeMasker) masker).fullRangeBit;
				WrappedMasker cache[] = masker.isSequential() ? WRAPPED_SEQUENTIAL_FULL_RANGE_MASKERS : WRAPPED_FULL_RANGE_MASKERS;
				WrappedMasker result = cache[fullRangeBit];
				if(result == null) {
					cache[fullRangeBit] = result = new WrappedMasker(masker);
				}
				return result;
			}
			return new WrappedMasker(masker);
		}
		if(extendedValue > extendedUpperValue) {
			throw new IllegalArgumentException("value > upper value");
		}
		if((maskValue == maxValue && extendedMaskValue == extendedMaxValue /* all ones mask */) ||
				(maskValue == 0 && extendedMaskValue == 0 /* all zeros mask */)) {
			return DEFAULT_MASKER;
		}
		int highestDifferingBitInRange = Long.numberOfLeadingZeros(extendedDiffering);
		long extendedDifferingMasked = extendedMaskValue & (~0L >>> highestDifferingBitInRange);
		int highestDifferingBitMasked;
		if(extendedDifferingMasked != 0) {
			boolean differingIsLowestBit = (extendedDifferingMasked == 1);
			highestDifferingBitMasked = Long.numberOfLeadingZeros(extendedDifferingMasked);
			boolean maskedIsSequential;
			long hostMask = ~0L >>> (highestDifferingBitMasked + 1);
			if(!differingIsLowestBit) { // Anything below highestDifferingBitMasked in the mask must be ones.
				//for the first mask bit that is 1, all bits that follow must also be 1
				maskedIsSequential = (extendedMaskValue & hostMask) == hostMask && maskValue == maxValue; //check if all ones below
			} else {
				maskedIsSequential = maskValue == maxValue;
			}
			if(value == 0 && extendedValue == 0 && 
					upperValue == maxValue && extendedUpperValue == extendedMaxValue) {
				// full range
				if(maskedIsSequential) {
					return DEFAULT_MASKER;
				} else {
					return DEFAULT_NON_SEQUENTIAL_MASKER;
				}
			}
			if(highestDifferingBitMasked > highestDifferingBitInRange) {
				if(maskedIsSequential) {
					// We need to check that the range is larger enough that when chopping off the top it remains sequential
					
					// Note: a count of 2 in the extended could equate to a count of 2 total!
					// upper: xxxxxxx1 00000000
					// lower: xxxxxxx0 11111111
					// Or, it could be everything:
					// upper: xxxxxxx1 11111111
					// lower: xxxxxxx0 00000000
					// So for that reason, we need to check the full count here and not just extended
					
					int shift = Long.SIZE - highestDifferingBitMasked; // highestDifferingBitMasked > 0 so shift < 64 which is required for long left shift
					BigInteger countRequiredForSequential = ONE_SHIFTED_EXTENDED[shift];
					if(countRequiredForSequential == null) {
						countRequiredForSequential = ONE_SHIFTED_EXTENDED[shift] = BigInteger.valueOf(1L << shift).shiftLeft(Long.SIZE);
					}
					BigInteger upperBig = new BigInteger(1, toBytesSizeAdjusted(upperValue, extendedUpperValue, 16));
					BigInteger lowerBig = new BigInteger(1, toBytesSizeAdjusted(value, extendedValue, 16));
					BigInteger count = upperBig.subtract(lowerBig).add(BigInteger.ONE);
					maskedIsSequential = count.compareTo(countRequiredForSequential) >= 0;
				}
				ExtendedFullRangeMasker cache[] = maskedIsSequential ? EXTENDED_SEQUENTIAL_FULL_RANGE_MASKERS : EXTENDED_FULL_RANGE_MASKERS;
				ExtendedFullRangeMasker result = cache[highestDifferingBitMasked];
				if(result == null) {
					cache[highestDifferingBitMasked] = result = new ExtendedFullRangeMasker(highestDifferingBitMasked, maskedIsSequential);
				}
				return result;
			} else if(!maskedIsSequential) {
				BigInteger bigHostMask = HOST_MASK_EXTENDED[highestDifferingBitMasked];
				if(bigHostMask == null) {
					bigHostMask = BigInteger.valueOf(hostMask);
					bigHostMask = bigHostMask.shiftLeft(Long.SIZE);
					byte b = (byte) 0xff;
					bigHostMask = bigHostMask.or(new BigInteger(1, new byte[] {b, b, b, b, b, b, b, b}));
					HOST_MASK_EXTENDED[highestDifferingBitMasked] = bigHostMask;
				}
				BigInteger bigHostZeroed = NETWORK_MASK_EXTENDED[highestDifferingBitMasked];
				if(bigHostZeroed == null) {
					bigHostZeroed = NETWORK_MASK_EXTENDED[highestDifferingBitMasked] = bigHostMask.not();
				}
				BigInteger upperBig = new BigInteger(1, toBytesSizeAdjusted(upperValue, extendedUpperValue, 16));
				BigInteger lowerBig = new BigInteger(1, toBytesSizeAdjusted(value, extendedValue, 16));
				BigInteger upperToBeMaskedBig = upperBig.and(bigHostZeroed);
				BigInteger lowerToBeMaskedBig = lowerBig.or(bigHostMask);
				BigInteger maskBig = new BigInteger(1, toBytesSizeAdjusted(maskValue, extendedMaskValue, 16));
				for(int nextBit = 128 - (highestDifferingBitMasked + 1) - 1; nextBit >= 0; nextBit--) {
					if(maskBig.testBit(nextBit)) {
						BigInteger candidate = upperToBeMaskedBig.setBit(nextBit);
						if(candidate.compareTo(upperBig) <= 0) {
							upperToBeMaskedBig = candidate;
						}
						candidate = lowerToBeMaskedBig.clearBit(nextBit);
						if(candidate.compareTo(lowerBig) >= 0) {
							lowerToBeMaskedBig = candidate;
						}
					} //else
					// keep our upperToBeMaskedBig bit as 0
					// keep our lowerToBeMaskedBig bit as 1
				}
				return new ExtendedSpecificValueMasker(
						lowerToBeMaskedBig.shiftRight(Long.SIZE).longValue(), 
						lowerToBeMaskedBig.longValue(), 
						upperToBeMaskedBig.shiftRight(Long.SIZE).longValue(), 
						upperToBeMaskedBig.longValue());
			}
			return DEFAULT_MASKER;
			
		}
		// When masking, the top becomes single-valued.
		
		// We go to the lower values to find highestDifferingBitMasked.
		
		// At this point, the highest differing bit in the lower range is 0
		// and the highestDifferingBitMasked is the first 1 bit in the lower mask
		
		if(maskValue == 0) {
			// the mask zeroes out everything,
			return DEFAULT_MASKER;
		}
		boolean maskedIsSequential = true;
		int highestDifferingBitMaskedLow = Long.numberOfLeadingZeros(maskValue);
		if(maskValue != maxValue && highestDifferingBitMaskedLow < Long.SIZE - 1) {
			//for the first mask bit that is 1, all bits that follow must also be 1
			long hostMask = ~0L >>> (highestDifferingBitMaskedLow + 1); // this shift of since case of highestDifferingBitMaskedLow of 64 and 63 taken care of, so the shift is < 64
			maskedIsSequential = (maskValue & hostMask) == hostMask; //check if all ones below
		}
		if(maskedIsSequential) {
			// Note: a count of 2 in the lower values could equate to a count of everything in the full range:
			// upper: xxxxxx10 00000000
			// lower: xxxxxxx0 11111111
			// Another example:
			// upper: xxxxxxx1 00000001
			// lower: xxxxxxx0 00000000
			// So for that reason, we need to check the full count here and not just lower values
			
			// We need to check that the range is larger enough that when chopping off the top it remains sequential
			BigInteger countRequiredForSequential;
			if(highestDifferingBitMaskedLow == 0) {
				countRequiredForSequential = ONE_EXTENDED;
			} else if(highestDifferingBitMaskedLow == 1) { // need this case because 1 << 63 is a negative number
				countRequiredForSequential = HIGH_BIT;
			} else {
				int shift = Long.SIZE - highestDifferingBitMaskedLow;
				countRequiredForSequential = ONE_SHIFTED[shift];
				if(countRequiredForSequential == null) {
					countRequiredForSequential = ONE_SHIFTED[shift] = BigInteger.valueOf(1L << shift);
				}
			}
			BigInteger upperBig = new BigInteger(1, toBytesSizeAdjusted(upperValue, extendedUpperValue, 16));
			BigInteger lowerBig = new BigInteger(1, toBytesSizeAdjusted(value, extendedValue, 16));
			BigInteger count = upperBig.subtract(lowerBig).add(BigInteger.ONE);
			maskedIsSequential = count.compareTo(countRequiredForSequential) >= 0;
		}
		highestDifferingBitMasked = highestDifferingBitMaskedLow + Long.SIZE;
		ExtendedFullRangeMasker cache[] = maskedIsSequential ? EXTENDED_SEQUENTIAL_FULL_RANGE_MASKERS : EXTENDED_FULL_RANGE_MASKERS;
		ExtendedFullRangeMasker result = cache[highestDifferingBitMasked];
		if(result == null) {
			cache[highestDifferingBitMasked] = result = new ExtendedFullRangeMasker(highestDifferingBitMasked, maskedIsSequential);
		}
		return result;
	}

	/**
	 * 
	 * @param value
	 * @param upperValue
	 * @param maskValue
	 * @return an instance what will produce the result of masking the values
	 * -1 if not compatible and x where x >= 0 if compatible.
	 *  If x is 0, then the resulting masked range is (value & maskValue) to (upperValue & maskValue).
	 *  If x > 0, then the resulting masked range is (value & maskValue & lowerMask) to ((upperValue & maskValue) | upperMask)
	 *  	where upperMask is ~0 >>> x and lowerMask = ~upperMask.
	 */
	public static Masker maskRange(long value, long upperValue, long maskValue) {
		return maskRange(value, upperValue, maskValue, -1);
	}
	
	public static Masker maskRange(long value, long upperValue, long maskValue, long maxValue) {
		if(value == upperValue) {
			return DEFAULT_MASKER;
		}
		if(value > upperValue) {
			throw new IllegalArgumentException("value > upper value");
		}
		if(maskValue == 0 || maskValue == maxValue) {
			return DEFAULT_MASKER;
		}
		
		//algorithm:
		//here we find the highest bit that is part of the range, highestDifferingBitInRange (ie changes from lower to upper)
		//then we find the highest bit in the mask that is 1 that is the same or below highestDifferingBitInRange (if such a bit exists)
		
		//this gives us the highest bit that is part of the masked range (ie changes from lower to upper after applying the mask)
		//if this latter bit exists, then any bit below it in the mask must be 1 to remain sequential.
		
		long differing = value ^ upperValue;
		if(differing != 1) {
			int highestDifferingBitInRange = Long.numberOfLeadingZeros(differing);
			long maskMask = ~0L >>> highestDifferingBitInRange;
			long differingMasked = maskValue & maskMask;
			boolean foundDiffering = (differingMasked != 0);
			if(foundDiffering) {
				// Anything below highestDifferingBitMasked in the mask must be ones.
				// Also, if we have masked out any 1 bit in the original, then anything that we do not mask out that follows must be all 1s
				int highestDifferingBitMasked = Long.numberOfLeadingZeros(differingMasked); // first one bit in the mask covering the range
				long hostMask = (highestDifferingBitMasked == Long.SIZE - 1) ? 0 : ~0L >>> (highestDifferingBitMasked + 1);//for the first mask bit that is 1, all bits that follow must also be 1
				boolean maskedIsSequential = (maskValue & hostMask) == hostMask;
				if(maxValue == -1 && 
						(!maskedIsSequential || highestDifferingBitMasked > highestDifferingBitInRange)) {
					int highestOneBit = Long.numberOfLeadingZeros(upperValue);
					// note we know highestOneBit < 64, otherwise differing would be 1 or 0
					maxValue = ~0L >>> highestOneBit;
				}
				if(value == 0 && upperValue == maxValue) {
					// full range
					if(maskedIsSequential) {
						return DEFAULT_MASKER;
					} else {
						return DEFAULT_NON_SEQUENTIAL_MASKER;
					}
				}
				if(highestDifferingBitMasked > highestDifferingBitInRange) {
					if(maskedIsSequential) {
						// the count will determine if the masked range is sequential
						if(highestDifferingBitMasked < Long.SIZE - 1) {
							long count = upperValue - value + 1;
							
							// if original range is 0xxxx to 1xxxx and our mask starts with a single 0 so the mask is 01111, 
							// then our new range covers 4 bits at most (could be less).
							// If the range covers 4 bits, we need to know if that range covers the same count of values as 0000 to 1111.
							// If so, the resulting range is not disjoint.
							// How do we know the range is disjoint otherwise?  We know because it has the values 1111 and 0000.
							// In order to go from 0xxxx to 1xxxx you must cross the consecutive values 01111 and 10000.
							// These values are consecutive in the original range (ie 01111 is followed by 10000) but in the new range
							// they are farthest apart and we need the entire range to fill the gap between them.
							// That count of values for the entire range is 1111 - 0000 + 1 = 10000
							// So in this example, the first bit in the original range is bit 0, highestDifferingBitMasked is 1,
							// and the range must cover 2 to the power of (5 - 1),
							// or 2 to the power of bit count - highestDifferingBitMasked, or 1 shifted by that much. 
							
							long countRequiredForSequential = 1L << (Long.SIZE - highestDifferingBitMasked);
							if(count < countRequiredForSequential) {
								// the resulting masked values are disjoint, not sequential
								maskedIsSequential = false;
							}
						} // else count of 2 is good enough, even if the masked range does not cover both values, then the result is a single value, which is also sequential
						// another way of looking at it: when the range is just two, we do not need to see if the masked range covers all values in between, as there is no values in between
					}
					// The range part of the values will go from 0 to the mask itself.
					// This is because we know that if the range is 0xxxx... to 1yyyy..., then 01111... and 10000... are also in the range,
					// since that is the only way to transition from 0xxxx... to 1yyyy...
					// Because the mask has no 1 bit at the top bit, then we know that when masking with those two values 01111... and 10000...
					// we get the mask itself and 00000 as the result.
					FullRangeMasker cache[] = maskedIsSequential ? SEQUENTIAL_FULL_RANGE_MASKERS : FULL_RANGE_MASKERS;
					FullRangeMasker result = cache[highestDifferingBitMasked];
					if(result == null) {
						cache[highestDifferingBitMasked] = result = new FullRangeMasker(highestDifferingBitMasked, maskedIsSequential);
					}
					return result;
				} else if(!maskedIsSequential) {
					long hostZeroed = ~hostMask;
					long upperToBeMasked = upperValue & hostZeroed;
					long lowerToBeMasked = value | hostMask;
					// we find a value in the range that will produce the highest and lowest values when masked
					for(long nextBit = (1 << (Long.SIZE - (highestDifferingBitMasked + 1) - 1)); nextBit != 0; nextBit >>>= 1) {
						// check if the bit in the mask is 1
						if((maskValue & nextBit) != 0) {
							long candidate = upperToBeMasked | nextBit;
							if(candidate <= upperValue) {
								upperToBeMasked = candidate;
							}
							candidate = lowerToBeMasked & ~nextBit;
							if(candidate >= value) {
								lowerToBeMasked = candidate;
							}
						} //else
							// keep our upperToBeMasked bit as 0
							// keep our lowerToBeMasked bit as 1
					}
					return new SpecificValueMasker(lowerToBeMasked, upperToBeMasked);
				} // else fall through to default masker
			} 
		} 
		return DEFAULT_MASKER;
	}

	public static BitwiseOrer bitwiseOrRange(long value, long upperValue, long maskValue) {
		return bitwiseOrRange(value, upperValue, maskValue, -1);
	}
		
	public static BitwiseOrer bitwiseOrRange(long value, long upperValue, long maskValue, long maxValue) {
		if(value == upperValue) {
			return DEFAULT_OR_MASKER;
		}
		if(value > upperValue) {
			throw new IllegalArgumentException("value > upper value");
		}
		if(maskValue == 0 || maskValue == maxValue) {
			return DEFAULT_OR_MASKER;
		}
		
		//algorithm:
		//here we find the highest bit that is part of the range, highestDifferingBitInRange (ie changes from lower to upper)
		//then we find the highest bit in the mask that is 0 that is the same or below highestDifferingBitInRange (if such a bit exists)
		
		//this gives us the highest bit that is part of the masked range (ie changes from lower to upper after applying the mask)
		//if this latter bit exists, then any bit below it in the mask must be 0 to include the entire range.
		
		long differing = value ^ upperValue;
		if(differing != 1) {
			int highestDifferingBitInRange = Long.numberOfLeadingZeros(differing);
			long maskMask = ~0L >>> highestDifferingBitInRange;
			long differingMasked = maskValue & maskMask;
			boolean foundDiffering = (differingMasked != maskMask);// mask not all ones
			if(foundDiffering) {
				int highestDifferingBitMasked = Long.numberOfLeadingZeros(~differingMasked & maskMask); // first 0 bit in the part of the mask covering the range
				long hostMask = (highestDifferingBitMasked == Long.SIZE - 1) ? 0 : ~0L >>> (highestDifferingBitMasked + 1); // after that first 0 bit, all bits that follow must also be 0
				boolean maskedIsSequential = (maskValue & hostMask) == 0;
				if(maxValue == -1 && 
						(!maskedIsSequential || highestDifferingBitMasked > highestDifferingBitInRange)) {
					int highestOneBit = Long.numberOfLeadingZeros(upperValue);
					// note we know highestOneBit < 64, otherwise differing would be 1 or 0, so shift is OK
					maxValue = ~0L >>> highestOneBit;
				}
				if(value == 0 && upperValue == maxValue) {
					// full range
					if(maskedIsSequential) {
						return DEFAULT_OR_MASKER;
					} else {
						return DEFAULT_NON_SEQUENTIAL_OR_MASKER;
					}
				}
				if(highestDifferingBitMasked > highestDifferingBitInRange) {
					if(maskedIsSequential) {
						// the count will determine if the ored range is sequential
						if(highestDifferingBitMasked < Long.SIZE - 1) {
							long count = upperValue - value + 1;
							long countRequiredForSequential = 1L << (Long.SIZE - highestDifferingBitMasked);
							if(count < countRequiredForSequential) {
								// the resulting ored values are disjoint, not sequential
								maskedIsSequential = false;
							}
						}
					}
					FullRangeBitwiseOrer cache[] = maskedIsSequential ? SEQUENTIAL_FULL_RANGE_OR_MASKERS : FULL_RANGE_OR_MASKERS;
					FullRangeBitwiseOrer result = cache[highestDifferingBitMasked];
					if(result == null) {
						cache[highestDifferingBitMasked] = result = new FullRangeBitwiseOrer(highestDifferingBitMasked, maskedIsSequential);
					}
					return result;
				} else if(!maskedIsSequential) {
					long hostZeroed = ~hostMask;
					long upperToBeMasked = upperValue & hostZeroed;
					long lowerToBeMasked = value | hostMask;
					for(long nextBit = (1L << (Long.SIZE - (highestDifferingBitMasked + 1) - 1)); nextBit != 0; nextBit >>>= 1) {
						// check if the bit in the mask is 0
						if((maskValue & nextBit) == 0) {
							long candidate = upperToBeMasked | nextBit;
							if(candidate <= upperValue) {
								upperToBeMasked = candidate;
							}
							candidate = lowerToBeMasked & ~nextBit;
							if(candidate >= value) {
								lowerToBeMasked = candidate;
							}
						} //else
							// keep our upperToBeMasked bit as 0
							// keep our lowerToBeMasked bit as 1
					}
					return new SpecificValueBitwiseOrer(lowerToBeMasked, upperToBeMasked);
				}
			}
		}
		return DEFAULT_OR_MASKER;
	}

	// converts to a byte array but strips leading zero bytes
	static byte[] toBytesSizeAdjusted(long val, long extended, int numBytes) {
		// Find first nonzero byte
		int adjustedNumBytes = numBytes;
		for(int j = 1, boundary = numBytes - 8, adj = numBytes + boundary; j <= numBytes; j++) {
			byte b;
			if(j <= boundary) {
				b = (byte) (extended >>> ((numBytes - j) << 3));
			} else {
				b = (byte) (val >>> ((adj - j) << 3));
			}
			if(b != 0) {
				break;
			}
			adjustedNumBytes--;
		}
		return toBytes(val, extended, adjustedNumBytes);
	}

	static byte[] toBytes(long val, long extended, int numBytes) {
		byte bytes[] = new byte[numBytes];
		for(int j = numBytes - 1, boundary = numBytes - 8; j >= 0; j--) {
			if(j >= boundary) {
				bytes[j] = (byte) (val & 0xff);
				val >>>= Byte.SIZE;
			} else {
				bytes[j] = (byte) (extended & 0xff);
				extended >>>= Byte.SIZE;
			}
		}
		return bytes;
	}
	
	private boolean groupingIsSequential() {
		try {
			return getDivisionGrouping().isSequential();
		} catch(IncompatibleAddressException e) {
			// division groupings avoid all IncompatibleAddressException caused by regrouping the values into segments of different size
			// that takes care of two of the sources of IncompatibleAddressException: joining mixed segs, and expanding inet_aton ipv4 or single-segment ipv6 into the standard number of ipv4 or ipv6 segments
			
			// Those remaining are the IncompatibleAddressException caused by masks, which are the result of individual divisions becoming non-sequential
			// So in such cases, you know we are not sequential.  So we return false.
			// the usual caveat is that this cannot happen with standard network or host masks
			return false;
		}
	}
	
	@Override
	public boolean isSequential() {
		TranslatedResult<?,?> val = values;
		if(val != null) {
			// check address first
			if(!val.withoutSections()) {
				// address already there, use it if we can
				if(val.withoutAddressException()) {
					return val.getAddress().isSequential();
				}
				return groupingIsSequential();
			}
			if(!val.withoutGrouping()) {
				return groupingIsSequential();
			}
		}
		// neither address nor grouping is there, create the address
		val = getCachedAddresses(false);
		if(val.withoutAddressException()) {
			return val.getAddress().isSequential();
		}
		return groupingIsSequential();
	}
	
	// skips contains checking for addresses already parsed - 
	// so this is not a case of unusual string formatting, because this is not for comparing strings,
	// but more a case of whether the parsing data structures are easy to use or not
	private boolean skipContains(boolean skipMixed) {
		AddressParseData parseData = getAddressParseData();
		int segmentCount = parseData.getSegmentCount();
		
		// first we must excluded cases where the segments line up differently than standard, although we do not exclude ipv6 compressed
		if(isProvidingIPv4()) {
			if(segmentCount != IPv4Address.SEGMENT_COUNT) { // accounts for is_inet_aton_joined, singleSegment and wildcard segments
				return true;
			}
		} else {
			int expectedSegmentCount;
			if(isProvidingMixedIPv6()) {
				if(skipMixed) {
					return true;
				}
				expectedSegmentCount = IPv6Address.SEGMENT_COUNT - 2;
			} else {
				expectedSegmentCount = IPv6Address.SEGMENT_COUNT;
			}
			if(segmentCount != expectedSegmentCount && !isCompressed()) { // accounts for single segment and wildcard segments
				return true;
			}
		}
		// exclude non-standard masks which will modify segment values from their parsed values
		IPAddress mask = getProviderMask();
		if(mask != null && mask.getBlockMaskPrefixLength(true) == null) { // handles non-standard masks
			return true;
		}
		return false;
	}

	@Override
	public Boolean contains(String other) {
		AddressParseData parseData = getAddressParseData();
		int segmentData[] = parseData.getSegmentData(); //grab this field for thread safety, other threads can make it disappear
		if(segmentData == null) {
			return null;
		}
		if(skipContains(true)) {
			return null;
		}
		if(has_inet_aton_value || hasIPv4LeadingZeros || isBinary) {
			//you need to skip inet_aton completely because it can screw up where prefix matches up with digits
			//you need to skip ipv4 leading zeros because addresses like 01.02.03.04 can change value depending on the validation options (octal or decimal)
			return null;
		}
		Integer pref = getProviderNetworkPrefixLength();
		IPAddressStringParameters options = getParameters();
		IPAddressNetwork<? extends IPAddress, ?, ?, ?, ?> network = (isProvidingIPv4() ? options.getIPv4Parameters() : options.getIPv6Parameters()).getNetwork();
		if(pref != null && !isPrefixSubnet(pref, network, segmentData)) {
			// this algorithm only works to check that the non-prefix host portion is valid,
			// it does not attempt to check containment of the host or match the host,
			// it depends on the host being full range in the containing address
			return null;
		}
		return matchesPrefix(other, segmentData);
	}
	
	@Override
	public Boolean prefixContains(String other) {
		Boolean b = prefixEquals(other);
		if(b != null && b.booleanValue()) {
			return b;
		}
		return null;
	}
	
	@Override
	public Boolean prefixEquals(String other) {
		AddressParseData parseData = getAddressParseData();
		int segmentData[] = parseData.getSegmentData(); //grab this field for thread safety, other threads can make it disappear
		if(segmentData == null) {
			return null;
		}
		if(skipContains(true)) {
			return null;
		}
		if(has_inet_aton_value || hasIPv4LeadingZeros || isBinary) {
			//you need to skip inet_aton completely because it can screw up where prefix matches up with digits
			//you need to skip ipv4 leading zeros because addresses like 01.02.03.04 can change value depending on the validation options (octal or decimal)
			return null;
		}
		return matchesPrefix(other, segmentData);
	}
	
	private Boolean matchesPrefix(String other, int segmentData[]) {
		int otherLen = other.length();
		// If other has a prefix length, then we end up returning false when we look at the end of the other string to ensure the other string is valid
		// Checking for prefix subnets in here is too expensive
		// Also, we don't want to start validating prefix strings as well, too expensive
		// A prefix can only change a "true" result to "false", so all the places we return false below are still fine
		// However, we only give up at the very end, so here we do a quick check first
		boolean isIPv4 = isProvidingIPv4();
		if(otherLen >= 4)	{
			char prefixLenSep = IPAddress.PREFIX_LEN_SEPARATOR;
			if(other.charAt(otherLen - 2) == prefixLenSep || other.charAt(otherLen - 3) == prefixLenSep) {
				return null;
			}
			if(!isIPv4) {
				if(other.charAt(otherLen - 4) == prefixLenSep) {
					return null;
				}
			}
		}
		AddressParseData parseData = getAddressParseData();
		Integer pref = getProviderNetworkPrefixLength();
		int expectedCount;
		boolean compressedAlready = false;
		boolean networkSegIsCompressed = false;
		boolean prefixIsMidSegment;
		int prefixEndCharIndex, remainingSegsCharIndex, networkSegIndex, networkSegCharIndex, networkSegsCount, adjustment; // prefixEndCharIndex points to separator following prefixed seg if whole seg is prefixed, remainingSegsCharIndex points to next digit
		remainingSegsCharIndex = networkSegCharIndex = networkSegIndex = networkSegsCount = adjustment = 0;

		if(pref == null) {
			expectedCount = isIPv4 ? IPv4Address.SEGMENT_COUNT : IPv6Address.SEGMENT_COUNT;
			networkSegIndex = expectedCount - 1;
			prefixEndCharIndex = getIndex(networkSegIndex, AddressParseData.KEY_UPPER_STR_END_INDEX, segmentData);
			if(otherLen > prefixEndCharIndex) {
				return null;
			}
			prefixIsMidSegment = false;
		} else if(pref == 0) {
			prefixIsMidSegment = false;
			expectedCount = isIPv4 ? IPv4Address.SEGMENT_COUNT : IPv6Address.SEGMENT_COUNT;
			prefixEndCharIndex = 0;
		} else {
			if(isIPv4) {
				expectedCount = IPv4Address.SEGMENT_COUNT;
				int bitsPerSegment = IPv4Address.BITS_PER_SEGMENT;
				int bytesPerSegment = IPv4Address.BYTES_PER_SEGMENT;
				networkSegIndex = ParsedAddressGrouping.getNetworkSegmentIndex(pref, bytesPerSegment, bitsPerSegment);
				prefixEndCharIndex = getIndex(networkSegIndex, AddressParseData.KEY_UPPER_STR_END_INDEX, segmentData);
				Integer segPrefLength = ParsedAddressGrouping.getPrefixedSegmentPrefixLength(bitsPerSegment, pref, networkSegIndex);
				prefixIsMidSegment = segPrefLength != bitsPerSegment;
				networkSegsCount = networkSegIndex + 1;
				remainingSegsCharIndex = prefixEndCharIndex + 1;
				if(prefixIsMidSegment) {
					networkSegCharIndex = getIndex(networkSegIndex, AddressParseData.KEY_LOWER_STR_START_INDEX, segmentData);
				}
			} else {
				expectedCount = IPv6Address.SEGMENT_COUNT;
				int bitsPerSegment = IPv6Address.BITS_PER_SEGMENT;
				int bytesPerSegment = IPv6Address.BYTES_PER_SEGMENT;
				networkSegIndex = ParsedAddressGrouping.getNetworkSegmentIndex(pref, bytesPerSegment, bitsPerSegment);
				int missingSegmentCount = IPv6Address.SEGMENT_COUNT - parseData.getSegmentCount();
				int compressedSegIndex = getConsecutiveSeparatorSegmentIndex();
				compressedAlready = compressedSegIndex <= networkSegIndex;//any part of network prefix is compressed
				networkSegIsCompressed = compressedAlready && compressedSegIndex + missingSegmentCount >= networkSegIndex;//the segment with the prefix boundary is compressed		
				Integer segPrefLength = ParsedAddressGrouping.getPrefixedSegmentPrefixLength(bitsPerSegment, pref, networkSegIndex);
				if(networkSegIsCompressed) {
					prefixIsMidSegment = segPrefLength != bitsPerSegment;
					networkSegsCount = networkSegIndex + 1;
					prefixEndCharIndex = getIndex(compressedSegIndex, AddressParseData.KEY_UPPER_STR_END_INDEX, segmentData) + 1; //to include all zeros in prefix we must include both seps, in other cases we include no seps at alls
					if (prefixIsMidSegment && compressedSegIndex > 0) {
						networkSegCharIndex = getIndex(compressedSegIndex, AddressParseData.KEY_LOWER_STR_START_INDEX, segmentData);
					}
					remainingSegsCharIndex = prefixEndCharIndex + 1;
				} else {
					int actualNetworkSegIndex;
					if(compressedSegIndex < networkSegIndex) {
						actualNetworkSegIndex = networkSegIndex - missingSegmentCount;
					} else {
						actualNetworkSegIndex = networkSegIndex;
					}
					prefixEndCharIndex = getIndex(actualNetworkSegIndex, AddressParseData.KEY_UPPER_STR_END_INDEX, segmentData);
					adjustment = IPv6AddressSegment.MAX_CHARS - ((segPrefLength + 3) >> 2); // divide by IPv6AddressSegment.BITS_PER_CHAR
					if(adjustment > 0) {
						prefixIsMidSegment = true;
						remainingSegsCharIndex = getIndex(actualNetworkSegIndex, AddressParseData.KEY_UPPER_STR_START_INDEX, segmentData);
						if(remainingSegsCharIndex + adjustment > prefixEndCharIndex) {
							adjustment = prefixEndCharIndex - remainingSegsCharIndex;
						}
						prefixEndCharIndex -= adjustment;
						networkSegsCount = networkSegIndex;
						networkSegCharIndex = getIndex(actualNetworkSegIndex, AddressParseData.KEY_LOWER_STR_START_INDEX, segmentData);
					} else {
						prefixIsMidSegment = segPrefLength != bitsPerSegment;
						networkSegsCount = actualNetworkSegIndex + 1;
						remainingSegsCharIndex = prefixEndCharIndex + 1;
						if(prefixIsMidSegment) {
							networkSegCharIndex = getIndex(actualNetworkSegIndex, AddressParseData.KEY_LOWER_STR_START_INDEX, segmentData);
						}
					}
				}
			}
		}
		CharSequence str = this.str;
		int otherSegmentCount = 0;
		boolean currentSegHasNonZeroDigits = false;
		for(int i = 0; i < prefixEndCharIndex; i++) {
			char c = str.charAt(i);
			char otherChar;
			if(i < otherLen) {
				otherChar = other.charAt(i);
			} else {
				otherChar = 0;
			}
			if(c != otherChar) {
				if(c >= '1' && c <= '9') {
				} else if(c >= 'a' && c <= 'f') {
				} else if(c >= 'A' && c <= 'F') {
					char adjustedChar = (char) (c - ('A' - 'a'));
					if(c == adjustedChar) {
						continue;
					}
				} else if(c <= Address.RANGE_SEPARATOR && c >= Address.SEGMENT_SQL_WILDCARD) {
					if(c == Address.SEGMENT_WILDCARD || c == Address.RANGE_SEPARATOR || c == Address.SEGMENT_SQL_WILDCARD) {
						return null;
					}
				} else if(c == Address.SEGMENT_SQL_SINGLE_WILDCARD) {
					return null;
				}
				
				if(otherChar >= 'A' && otherChar <= 'F') {
					char adjustedChar = (char) (otherChar - ('A' - 'a'));
					if(otherChar == adjustedChar) {
						continue;
					}
				} 
				
				if(prefixIsMidSegment && (i >= networkSegCharIndex || networkSegCharIndex == 1)) { //networkSegCharIndex == 1 accounts for :: start to address
					// when prefix is not on seg boundary, we can have the same prefix without matching digits
					// the host part can change the digits of the network part, particularly for ipv4
					// this is true for ipv6 too when you consider host and network part of each digit
					// this is also true when the digit count in the segments do not match,
					// also note that f: and fabc: match prefix of 4 by string chars, but prefix does not match due to difference in digits in each segment
					// So, in general, when mismatch of prefix chars we cannot conclude mismatch of prefix unless we are comparing entire segments (ie prefix is on seg boundary)
					return null;
				}
				
				if(hasRange(otherSegmentCount)) {
					return null;
				}

				if(otherChar >= '1' && otherChar <= '9') {
				} else if(otherChar >= 'a' && otherChar <= 'f') {
				} else {
					if(otherChar <= Address.RANGE_SEPARATOR && otherChar >= Address.SEGMENT_SQL_WILDCARD) {
						if(otherChar == Address.SEGMENT_WILDCARD || otherChar == Address.RANGE_SEPARATOR || otherChar == Address.SEGMENT_SQL_WILDCARD) {
							return null;
						}
					} else if(otherChar == Address.SEGMENT_SQL_SINGLE_WILDCARD) {
						return null;
					}
					
					if(!currentSegHasNonZeroDigits) {
						//we know that this address has no ipv4 leading zeros, we abort this method in such cases.
						//However, we do want to handle all the following cases and return null for each.
						//We do not handle differing numbers of leading zeros
						//We do not handle ipv6 compression in different places
						//So we want to handle segments that start like all of these cases:
						
						//other 01
						//this  1
						
						//other 00
						//this  1
						
						//other 00
						//this  :
						
						//other 0:
						//this  :
						
						//other 00
						//this  0:
						
						//other :
						//this  0
						
						//Those should all return null since they might in fact represent matching segments.
						//However, the following should return FALSE when there are no leading zeros and no compression:
						
						//other 0.
						//this  1
						
						//other 1
						//this  0.
						
						//other 0:
						//this  1
						
						//other 1
						//this  0:
						
						//So in summary, we first check that we have not matched non-zero values first (ie digitCount must be 0)
						//All the null cases involve one or the other starting with 0.
						//If the other is an ipv6 segment separator, return null.
						//Otherwise, if the zero is not the end of segment, we have leading zeros which we do not handle here, so we return null.
						//Otherwise, return false.  This is because we have a zero segment, and the other is not (it is neither compressed nor 0).
						//Actually, we return false only if the 0 segment is the other string, because if the 0 segment is this it is only one segment while the other may be multi-segment.
						//If the other might be multi-segment, we defer to the segment check that will tell us if we must have matching segments here.
						if(c == '0') {
							if(otherChar == IPv6Address.SEGMENT_SEPARATOR || otherChar == 0) {
								return null;
							}
							int k = i + 1;
							if(k < str.length()) {
								char nextChar = str.charAt(k);
								if(nextChar != IPv4Address.SEGMENT_SEPARATOR  && nextChar != IPv6Address.SEGMENT_SEPARATOR) {
									return null;
								}
							}
							//defer to the segment check
						} else if(otherChar == '0') {
							if(c == IPv6Address.SEGMENT_SEPARATOR) {
								return null;
							}
							int k = i + 1;
							if(k < otherLen) {
								char nextChar = other.charAt(k);
								if(nextChar != IPv4Address.SEGMENT_SEPARATOR  && nextChar != IPv6Address.SEGMENT_SEPARATOR) {
									return null;
								}
							}
							return Boolean.FALSE;
						}
					}
					if(otherChar == IPv6Address.SEGMENT_SEPARATOR) {
						return Boolean.FALSE; // we've alreqdy accounted for the case of container address 0 segment, so it is non-zero, so ending matching segment here is false match
					} else if(otherChar == IPv4Address.SEGMENT_SEPARATOR) {
						if(!isIPv4) {
							return null; //mixed address
						}
						otherSegmentCount++;
					}
				}
				
				//if other is a range like 3-3 must return null
				for(int k = i + 1; k < otherLen; k++) {
					otherChar = other.charAt(k);
					if(otherChar == IPv6Address.SEGMENT_SEPARATOR) {
						return Boolean.FALSE;
					} else if(otherChar <= IPAddress.PREFIX_LEN_SEPARATOR && otherChar >= Address.SEGMENT_SQL_WILDCARD) {
						if(otherChar == IPv4Address.SEGMENT_SEPARATOR) {
							if(!isIPv4) {
								return null; //mixed address
							}
							otherSegmentCount++;
						} else {
							if(otherChar == IPAddress.PREFIX_LEN_SEPARATOR || otherChar == Address.SEGMENT_WILDCARD || 
									otherChar == Address.RANGE_SEPARATOR || otherChar == Address.SEGMENT_SQL_WILDCARD ||
									otherChar == Address.SEGMENT_SQL_SINGLE_WILDCARD) {
								return null;
							}
						}
					}
				}
				if(isIPv4) {
					// if we match ipv4 seg count and we see no wildcards or other special chars, we can conclude non-containment
					if(otherSegmentCount + 1 == IPv4Address.SEGMENT_COUNT) {
						return Boolean.FALSE;
					}
				} else {
					// for ipv6 we have already checked for compression and special chars.  If we are not single segment, then we can conclude non-containment
					if(otherSegmentCount > 0) {
						return Boolean.FALSE;
					}
				}
				return null;
			}
			if(c != '0') {
				boolean isSegmentEnd = c == IPv6Address.SEGMENT_SEPARATOR || c == IPv4Address.SEGMENT_SEPARATOR;
				if(isSegmentEnd) {
					otherSegmentCount++;
					currentSegHasNonZeroDigits = false;
				} else {
					currentSegHasNonZeroDigits = true;
				}
			}
		}

		// At this point we know the prefix matches, so we need to prove that the provided string is indeed a valid ip address
		if(pref != null) {
			if(prefixEndCharIndex == otherLen) {  
				if(networkSegsCount != expectedCount) {
					// we are ok if compressed and networkSegsCount <= expectedCount which is 8 for ipv6, for example 1::/64 matching 1::, there are only 4 network segs
					if(!compressedAlready || networkSegsCount > expectedCount) {
						return null;
					}
				}
			} else {
				if(isIPv4) {
					if(pref != 0) {
						//we must match the same number of chars til end of segment, otherwise we might not have matched that last segment at all
						//we also cannot make conclusions when not matching due to '-' or '_' characters or matching leading zeros
						int segmentEndIndex = prefixEndCharIndex + adjustment;
						if(otherLen < segmentEndIndex) {
							return null;
						}
						if(otherLen != segmentEndIndex && other.charAt(segmentEndIndex) != IPv4Address.SEGMENT_SEPARATOR) {
							return null;
						}
						for(int n = prefixEndCharIndex; n < segmentEndIndex; n++) {
							char otherChar = other.charAt(n);
							if(otherChar == IPv4Address.SEGMENT_SEPARATOR) {
								return null;
							}
						}
					}
					
					//now count the remaining segments and check those chars
					int digitCount = 0;
					int remainingSegCount = 0;
					boolean firstIsHighIPv4 = false;
					int i = remainingSegsCharIndex;
					for(; i < otherLen; i++) {
						char otherChar = other.charAt(i);
						if(otherChar <= '9' && otherChar >= '0') {
							if(digitCount == 0 && otherChar >= '3') {
								firstIsHighIPv4 = true;
							}
							++digitCount;
						} else if(otherChar == IPv4Address.SEGMENT_SEPARATOR) {
							if(digitCount == 0) {
								return Boolean.FALSE;
							}
							if(firstIsHighIPv4) {
								if(digitCount >= IPv4AddressSegment.MAX_CHARS) {
									return Boolean.FALSE;
								}
							} else if(digitCount > IPv4AddressSegment.MAX_CHARS) {
								return null;//leading zeros or inet_aton formats
							}
							digitCount = 0;
							remainingSegCount++;
							firstIsHighIPv4 = false;
						} else { 
							return null; //some other character, possibly base 85, also '/' or wildcards
						}
					} // end for
					if(digitCount == 0) {
						return Boolean.FALSE;
					}
					if(digitCount > IPv4AddressSegment.MAX_CHARS) {
						return null;
					} else if(firstIsHighIPv4 && digitCount == IPv4AddressSegment.MAX_CHARS) {
						return null;
					}
					int totalSegCount = networkSegsCount + remainingSegCount + 1;
					if(totalSegCount != expectedCount) {
						return null;
					}
				} else {
					if(pref != 0) {
						// we must match the same number of chars til end of segment, otherwise we might not have matched that last segment at all
						// we also cannot make conclusions when not matching due to '-' or '_' characters or matching leading zeros
						// end of prefixed segment must be followed by separator eg 1:2 is prefix and must be followed by :
						// also note this handles 1:2:: as prefix
						int segmentEndIndex = prefixEndCharIndex + adjustment;
						if(otherLen < segmentEndIndex) {
							return null;
						}
						if(otherLen != segmentEndIndex && other.charAt(segmentEndIndex) != IPv6Address.SEGMENT_SEPARATOR) {
							return null;
						}
						for(int n = prefixEndCharIndex; n < segmentEndIndex; n++) {
							char otherChar = other.charAt(n);
							if(otherChar == IPv6Address.SEGMENT_SEPARATOR) {
								return null;
							}
						}
					}
					
					//now count the remaining segments and check those chars
					int digitCount = 0;
					int remainingSegCount = 0;
					int i = remainingSegsCharIndex;
					for(; i < otherLen; i++) {
						char otherChar = other.charAt(i);		
						if(otherChar <= '9' && otherChar >= '0') {
							++digitCount;
						} else if((otherChar >= 'a' && otherChar <= 'f') || (otherChar >= 'A' && otherChar <= 'F')) {
							++digitCount;
						} else if(otherChar == IPv4Address.SEGMENT_SEPARATOR) {
							return null; // could be ipv6/ipv4 mixed
						} else if(otherChar == IPv6Address.SEGMENT_SEPARATOR) {
							if(digitCount > IPv6AddressSegment.MAX_CHARS) {
								return null;//possibly leading zeros or ranges
							}
							if(digitCount == 0) {
								if(compressedAlready) {
									return Boolean.FALSE;
								}
								compressedAlready = true;
							} else {
								digitCount = 0;
							}
							remainingSegCount++;
						} else { 
							return null; //some other character, possibly base 85, also '/' or wildcards
						}
					} // end for
					if(digitCount == 0) {
						int prevIndex = i - 1;
						if(prevIndex < 0) {
							return Boolean.FALSE;
						}
						char prevChar = other.charAt(prevIndex);
						if(prevChar != IPv6Address.SEGMENT_SEPARATOR) { // cannot end with empty segment unless prev segment also empty
							return Boolean.FALSE;
						}
					} else if(digitCount > IPv6AddressSegment.MAX_CHARS) {
						return null;
					}
					int totalSegCount = networkSegsCount + remainingSegCount + 1;
					if(totalSegCount > expectedCount || (totalSegCount < expectedCount && !compressedAlready)) {
						return null;
					}
					if(networkSegIsCompressed && expectedCount - remainingSegCount <= networkSegIndex) {
						//consider 1:: and you are looking at segment 7
						//So we look at the front and we see it matches 1::
						//But what if the end is 1::3:4:5?
						return null;
					}
				}
			}
		}
		return Boolean.TRUE;
	}

	@Override
	public Boolean contains(IPAddressProvider other) {
		if(other instanceof ParsedIPAddress) {
			CachedIPAddresses<?> vals = values;
			CachedIPAddresses<?> otherVals = values;
			if(vals == null || otherVals == null) {
				// one or the other value not yet created, so take the shortcut that provides an answer most (but not all) of the time
				// An answer is provided for all normalized, conventional or canonical addresses
				return contains((ParsedIPAddress) other, false, false);
			} // else we defer to the values-based containment check (in the caller), which is best since it is ready to go
		}
		return null;
	}

	@Override
	public Boolean parsedEquals(IPAddressProvider other) {
		if(other instanceof ParsedIPAddress) {
			CachedIPAddresses<?> vals = values;
			CachedIPAddresses<?> otherVals = values;
			if(vals == null || otherVals == null) {
				// one or the other value not yet created, so take the shortcut that provides an answer most (but not all) of the time
				// An answer is provided for all normalized, conventional or canonical addresses
				ParsedIPAddress parsedOther = (ParsedIPAddress) other;
				Boolean result = contains(parsedOther, false, true);
				if(result != null) {
					return result && Objects.equals(getQualifier().getZone(), parsedOther.getQualifier().getZone());
				} // else we defer to the values-based equality check (in the caller), which is best since it is ready to go.
			}
		}
		return null;
	}

	@Override
	public Boolean prefixContains(IPAddressProvider other) {
		if(other instanceof ParsedIPAddress) {
			CachedIPAddresses<?> vals = values;
			CachedIPAddresses<?> otherVals = values;
			if(vals == null || otherVals == null) {
				// one or the other value not yet created, so take the shortcut that provides an answer most (but not all) of the time
				// An answer is provided for all normalized, conventional or canonical addresses
				return contains((ParsedIPAddress) other, true, false);
			} // else we defer to the values-based containment check (in the caller), which is best since it is ready to go.
		}
		return null;
	}
	
	@Override
	public Boolean prefixEquals(IPAddressProvider other) {
		if(other instanceof ParsedIPAddress) {
			CachedIPAddresses<?> vals = values;
			CachedIPAddresses<?> otherVals = values;
			if(vals == null || otherVals == null) {
				// one or the other value not yet created, so take the shortcut that provides an answer most (but not all) of the time
				// An answer is provided for all normalized, conventional or canonical addresses
				return contains((ParsedIPAddress) other, true, true);
			} // else we defer to the values-based containment check (in the caller), which is best since it is ready to go.
		}
		return null;
	}

	//not used for invalid, or cases where parseData.isEmpty or parseData.isAll
	private Boolean contains(ParsedIPAddress other, boolean networkOnly, boolean equals) {
		AddressParseData parseData = getAddressParseData();
		AddressParseData otherParseData = other.getAddressParseData();
		int segmentData[] = parseData.getSegmentData(); //grab this field for thread safety, other threads can make it disappear
		int otherSegmentData[] = otherParseData.getSegmentData(); //grab this field for thread safety, other threads can make it disappear
		if(segmentData == null || otherSegmentData == null) {
			return null;
		}
		Integer pref = getProviderNetworkPrefixLength();
		boolean skipMixed = !networkOnly || pref == null || pref > (IPv6Address.MIXED_ORIGINAL_SEGMENT_COUNT << 4);
		if(skipContains(skipMixed) || other.skipContains(skipMixed)) { // this excludes mixed addresses, amongst others
			return null;
		}
		IPVersion ipVersion = getProviderIPVersion();
		if(!ipVersion.equals(other.getProviderIPVersion())) {
			return Boolean.FALSE;
		}
		int max;
		IPAddressNetwork<? extends IPAddress, ?, ?, ?, ?> network;
		boolean compressedAlready, otherCompressedAlready;
		int expectedSegCount, expectedOtherSegCount, bitsPerSegment, bytesPerSegment;
		IPAddressStringParameters options = getParameters();
		int segmentCount = parseData.getSegmentCount();
		int otherSegmentCount = otherParseData.getSegmentCount();
		if(isProvidingIPv4()) {
			max = IPv4Address.MAX_VALUE_PER_SEGMENT;
			expectedSegCount = expectedOtherSegCount = IPv4Address.SEGMENT_COUNT;
			bitsPerSegment = IPv4Address.BITS_PER_SEGMENT;
			bytesPerSegment = IPv4Address.BYTES_PER_SEGMENT;
			network = options.getIPv4Parameters().getNetwork();
			compressedAlready = true;
			otherCompressedAlready = true;
		} else {
			max = IPv6Address.MAX_VALUE_PER_SEGMENT;
			expectedSegCount = expectedOtherSegCount = IPv6Address.SEGMENT_COUNT;
			if(isProvidingMixedIPv6()) {
				expectedSegCount -= 2;
			}
			if(other.isProvidingMixedIPv6()) {
				expectedOtherSegCount -= 2;
			}
			bitsPerSegment = IPv6Address.BITS_PER_SEGMENT;
			bytesPerSegment = IPv6Address.BYTES_PER_SEGMENT;
			network = options.getIPv6Parameters().getNetwork();
			compressedAlready = expectedSegCount == segmentCount;
			otherCompressedAlready = expectedOtherSegCount == otherSegmentCount;
		}
		PrefixConfiguration prefConf = network.getPrefixConfiguration();
		boolean zeroHostsAreSubnets = prefConf.zeroHostsAreSubnets();
		boolean allPrefixedAddressesAreSubnets = prefConf.allPrefixedAddressesAreSubnets();
		Integer otherPref = other.getProviderNetworkPrefixLength();
		int networkSegIndex, hostSegIndex, endIndex, otherHostAllSegIndex, hostAllSegIndex;
		endIndex = segmentCount;
		
		// determine what indexes to use for network, host, and prefix block adjustments (hostAllSegIndex and otherHostAllSegIndex)
		Integer adjustedOtherPref = null;
		if(pref == null) {
			networkOnly = false;
			hostAllSegIndex = hostSegIndex = expectedSegCount;
			otherHostAllSegIndex = expectedOtherSegCount;
			networkSegIndex = hostSegIndex - 1;
		} else if(networkOnly) {
			hostAllSegIndex = otherHostAllSegIndex = hostSegIndex = ParsedAddressGrouping.getHostSegmentIndex(pref, bytesPerSegment, bitsPerSegment);
			networkSegIndex = ParsedAddressGrouping.getNetworkSegmentIndex(pref, bytesPerSegment, bitsPerSegment);
			// we treat the other as if it were a prefix block of the same prefix length
			// this allows us to compare entire segments for prefixEquals, ignoring the host values
			adjustedOtherPref = pref;
		} else {
			otherHostAllSegIndex = expectedOtherSegCount;
			hostSegIndex = ParsedAddressGrouping.getHostSegmentIndex(pref, bytesPerSegment, bitsPerSegment);
			networkSegIndex = ParsedAddressGrouping.getNetworkSegmentIndex(pref, bytesPerSegment, bitsPerSegment);
			if(allPrefixedAddressesAreSubnets || 
					(zeroHostsAreSubnets && isPrefixSubnet(pref, network, segmentData))) {
				hostAllSegIndex = hostSegIndex;
				if(!equals) {
					// no need to look at host for containment when a prefix subnet
					networkOnly = true;
				}
			} else {
				hostAllSegIndex = expectedSegCount;
			}
		}
		// Now determine if the other is a prefix block subnet, and if so, adjust otherHostAllSegIndex
		if(otherPref != null) {
			int otherPrefLen = otherPref.intValue();
			if (adjustedOtherPref == null || otherPrefLen < adjustedOtherPref) {
				int otherHostIndex = ParsedAddressGrouping.getHostSegmentIndex(otherPrefLen, bytesPerSegment, bitsPerSegment);
				if(otherHostIndex < otherHostAllSegIndex &&
						(allPrefixedAddressesAreSubnets || (zeroHostsAreSubnets && other.isPrefixSubnet(otherPrefLen, network, otherSegmentData)))) {
					otherHostAllSegIndex = otherHostIndex;
				}
			} else {
				otherPref = adjustedOtherPref;
			}
		} else {
			otherPref = adjustedOtherPref;
		}
		
		int i = 0, j = 0, normalizedCount = 0;
		int compressedCount, otherCompressedCount;
		compressedCount = otherCompressedCount = 0;
		while(i < endIndex || compressedCount > 0) {
			if(networkOnly && normalizedCount > networkSegIndex) {
				break;
			}		
			long lower, upper;
		    if(compressedCount > 0) {
		    	lower = upper = 0;
		    } else {
		    	lower = getValue(i, AddressParseData.KEY_LOWER, segmentData);
		    	upper = getValue(i, AddressParseData.KEY_UPPER, segmentData);
		    }
		    if(normalizedCount >= hostAllSegIndex) { // we've reached the prefixed segment
			   	Integer segPrefLength = ParsedAddressGrouping.getSegmentPrefixLength(bitsPerSegment, pref, normalizedCount);
				lower &= network.getSegmentNetworkMask(segPrefLength);
				upper |= network.getSegmentHostMask(segPrefLength);
			}
			long otherLower, otherUpper;
			if(normalizedCount > otherHostAllSegIndex) {
				otherLower = 0;
				otherUpper = max;
			} else {
				if(otherCompressedCount > 0) {
					otherLower = otherUpper = 0;
				} else {
					otherLower = getValue(j, AddressParseData.KEY_LOWER, otherSegmentData);
					otherUpper = getValue(j, AddressParseData.KEY_UPPER, otherSegmentData);
				}
				if(normalizedCount == otherHostAllSegIndex) { // we've reached the prefixed segment
					Integer segPrefLength = ParsedAddressGrouping.getSegmentPrefixLength(bitsPerSegment, otherPref, normalizedCount);
					otherLower &= network.getSegmentNetworkMask(segPrefLength);
					otherUpper |= network.getSegmentHostMask(segPrefLength);
				}
			}
			if(equals ? (lower != otherLower || upper != otherUpper) : (lower > otherLower || upper < otherUpper)) {
				return Boolean.FALSE;
			}
			if(!compressedAlready) {
				if(compressedCount > 0) {
					if(--compressedCount == 0) {
						compressedAlready = true;
					}
				} else if(isCompressed(i, segmentData)) {
					i++;
					compressedCount = expectedSegCount - segmentCount;
				} else {
					i++;
				}
			} else {
				i++;
			}
			if(!otherCompressedAlready) {
				if(otherCompressedCount > 0) {
					if(--otherCompressedCount == 0) {
						otherCompressedAlready = true;
					}
				} else if(other.isCompressed(j, otherSegmentData)) {
					j++;
					otherCompressedCount = expectedOtherSegCount - otherSegmentCount;
				} else {
					j++;
				}
			} else {
				j++;
			}
			normalizedCount++;
		}
		return Boolean.TRUE;
	}

	//we do not call this method with parse data from inet_aton or single segment strings, so the cast to int is fine.
	//this is only for addresses with standard segment counts, although we do allow compressed.
	protected boolean isPrefixSubnet(Integer networkPrefixLength, IPAddressNetwork<?, ?, ?, ?, ?> network, int segmentData[]) {
		IPVersion version = network.getIPVersion();
		int bytesPerSegment = IPAddressSection.bytesPerSegment(version);
		int bitsPerSegment = IPAddressSection.bitsPerSegment(version);
		int max = IPAddressSegment.getMaxSegmentValue(version);
		PrefixConfiguration prefConf = network.getPrefixConfiguration();
		AddressParseData addressParseData = getAddressParseData();
		int segmentCount = addressParseData.getSegmentCount();
		if(isCompressed()) {
			int compressedCount = IPv6Address.SEGMENT_COUNT - segmentCount;
			int compressedIndex = addressParseData.getConsecutiveSeparatorSegmentIndex();
			return ParsedAddressGrouping.isPrefixSubnet(
					segmentIndex -> {
						if(segmentIndex >= compressedIndex) {
							if(segmentIndex - compressedIndex < compressedCount) {
								return 0;
							}
							segmentIndex -= compressedCount;
						}
						return (int) getValue(segmentIndex, AddressParseData.KEY_LOWER, segmentData);
					},
					segmentIndex -> {
						if(segmentIndex >= compressedIndex) {
							if(segmentIndex - compressedIndex < compressedCount) {
								return 0;
							}
							segmentIndex -= compressedCount;
						}
						return (int) getValue(segmentIndex, AddressParseData.KEY_UPPER, segmentData);
					},
					segmentCount + compressedCount,
					bytesPerSegment,
					bitsPerSegment,
					max,
					networkPrefixLength,
					prefConf,
					false);
		}
		//we do not enter this method with parse data from inet_aton or single segment strings, so the cast to int is fine
		return ParsedAddressGrouping.isPrefixSubnet(
				segmentIndex -> (int) getValue(segmentIndex, AddressParseData.KEY_LOWER, segmentData),
				segmentIndex -> (int) getValue(segmentIndex, AddressParseData.KEY_UPPER, segmentData),
				segmentCount,
				bytesPerSegment,
				bitsPerSegment,
				max,
				networkPrefixLength,
				prefConf,
				false);
	}

	@Override 
	public Integer getProviderNetworkPrefixLength() {
		return getQualifier().getEquivalentPrefixLength();
	}

	private static <S extends IPAddressSegment> S[] allocateSegments(
			S segments[],
			S originalSegments[],
			AddressSegmentCreator<S> creator,
			int segmentCount,
			int originalCount) {
		if(segments == null) {
			segments = creator.createSegmentArray(segmentCount);
			if(originalCount > 0) {
				System.arraycopy(originalSegments, 0, segments, 0, originalCount);
			}
		}
		return segments;
	}

	private void createIPv4Sections(boolean doAddress, boolean doRangeBoundaries, boolean withUpper) {
		ParsedHostIdentifierStringQualifier qualifier = getQualifier();
		IPAddress mask = getProviderMask();
		if(mask != null && mask.getBlockMaskPrefixLength(true) != null) {
			mask = null; // we don't do any masking if the mask is a subnet mask, instead we just map it to the corresponding prefix length
		}
		boolean hasMask = mask != null;
		AddressParseData addrParseData = getAddressParseData();
		int segmentCount = addrParseData.getSegmentCount();
		if(hasMask && maskers == null) {
			maskers = new Masker[segmentCount];
		}
		IPv4AddressCreator creator = getIPv4AddressCreator();
		int ipv4SegmentCount = IPv4Address.SEGMENT_COUNT;
		int missingCount = ipv4SegmentCount - segmentCount;
		
		IPv4AddressSegment[] hostSegments, segments, lowerSegments, upperSegments = null;
		hostSegments = upperSegments = null;
		if(doAddress) {
			segments = creator.createSegmentArray(ipv4SegmentCount);
			lowerSegments = null;
		} else if(doRangeBoundaries) {
			lowerSegments = creator.createSegmentArray(ipv4SegmentCount);
			segments = null;
		} else {
			return;
		}
		@SuppressWarnings("unchecked")
		TranslatedResult<IPv4Address, IPv4AddressSection> finalResult = 
				(TranslatedResult<IPv4Address, IPv4AddressSection>) values;
		if(values == null) {
			values = finalResult = new TranslatedResult<IPv4Address, IPv4AddressSection>() {
				/**
				 * 
				 */
				private static final long serialVersionUID = 1L;

				@Override
				ParsedAddressCreator<IPv4Address, IPv4AddressSection, ?, ?> getCreator() {
					return getIPv4AddressCreator();
				}
			};
		}
		boolean expandedSegments = (missingCount <= 0);
		int expandedStart, expandedEnd;
		expandedStart = expandedEnd = -1;
		CharSequence addressString = str;
		boolean maskedIsDifferent = false;
		for(int i = 0, normalizedSegmentIndex = 0; i < segmentCount; i++) {
			long lower = addrParseData.getValue(i, AddressParseData.KEY_LOWER);
			long upper = addrParseData.getValue(i, AddressParseData.KEY_UPPER);
			if(!expandedSegments) {
				//check for any missing segments that we should account for here
				boolean isLastSegment = i == segmentCount - 1;
				boolean isWildcard = addrParseData.isWildcard(i);
				expandedSegments = isLastSegment;
				if(!expandedSegments) {
					// if we are inet_aton, we must wait for last segment
					// otherwise, we check if we are wildcard and no other wildcard further down
					expandedSegments = !is_inet_aton_joined() && isWildcard;
					if(expandedSegments) {
						for(int j = i + 1; j < segmentCount; j++) {
							if(addrParseData.isWildcard(j)) {//another wildcard further down
								expandedSegments = false;
								break;
							}
						}
					}
				} 
				if(expandedSegments) {
					if(isWildcard) {
						upper = 0xffffffff >>> ((3 - missingCount) << 3);
					} else {
						expandedStart = i;
						expandedEnd = i + missingCount;
					}
					int bits = IPv4Address.BITS_PER_SEGMENT * (missingCount + 1);
					long maskedLower, maskedUpper;
					if(hasMask) {
						long divMask = 0;
						for(int k = 0; k <= missingCount; k++) {
							divMask = (divMask << IPv4Address.BITS_PER_SEGMENT) | mask.getSegment(normalizedSegmentIndex + k).getSegmentValue();
						}
						Masker masker = maskers[i];
						if(masker == null) {
							long maxValue = (bits == Integer.SIZE) ? 0xffffffffL : ~(~0 << bits);
							maskers[i] = masker = maskRange(lower, upper, divMask, maxValue);
						}
						if(!masker.isSequential() && finalResult.maskException == null) {
							finalResult.maskException = new IncompatibleAddressException(lower, upper, divMask, "ipaddress.error.maskMismatch");
						}
						maskedLower = masker.getMaskedLower(lower, divMask);
						maskedUpper = masker.getMaskedUpper(upper, divMask);
						maskedIsDifferent = maskedIsDifferent || maskedLower != lower || maskedUpper != upper;
					} else {
						maskedLower = lower;
						maskedUpper = upper;
					}
					int shift = bits;
					int count = missingCount;
					while(count >= 0) { //add the missing segments
						shift -= IPv4Address.BITS_PER_SEGMENT;
						Integer currentPrefix = getSegmentPrefixLength(normalizedSegmentIndex, IPv4Address.BITS_PER_SEGMENT, qualifier);
						int segmentBitsMask = IPv4Address.MAX_VALUE_PER_SEGMENT;
						int hostSegLower = (int) (lower >>> shift) & segmentBitsMask;
						int hostSegUpper = (lower == upper) ? hostSegLower : (int) (upper >>> shift) & segmentBitsMask;
						int maskedSegLower, maskedSegUpper;
						if(hasMask) {
							maskedSegLower = (int) (maskedLower >>> shift) & segmentBitsMask;
							maskedSegUpper = (maskedLower == maskedUpper) ? maskedSegLower : (int) (maskedUpper >>> shift) & segmentBitsMask;
						} else {
							maskedSegLower = hostSegLower;
							maskedSegUpper = hostSegUpper;
						}
						if(doAddress) {
							if(maskedIsDifferent || currentPrefix != null) {
								hostSegments = allocateSegments(hostSegments, segments, creator, ipv4SegmentCount, normalizedSegmentIndex);
								hostSegments[normalizedSegmentIndex] = createSegment(
										addressString,
										IPVersion.IPV4,
										hostSegLower,
										hostSegUpper,
										false,
										i,
										null,
										creator);
							}
							segments[normalizedSegmentIndex] = createSegment(
								addressString,
								IPVersion.IPV4,
								maskedSegLower,
								maskedSegUpper,
								false,
								i,
								currentPrefix,
								creator);
						}
						if(doRangeBoundaries) {
							boolean isRange = maskedSegLower != maskedSegUpper;
							if(!doAddress || isRange) {
								if(doAddress) {
									lowerSegments = allocateSegments(lowerSegments, segments, creator, ipv4SegmentCount, normalizedSegmentIndex);
								} // else segments already allocated
								lowerSegments[normalizedSegmentIndex] = createSegment(
										addressString,
										IPVersion.IPV4,
										maskedSegLower,
										maskedSegLower,
										false,
										i,
										currentPrefix,
										creator);
							} else if(lowerSegments != null) {
								lowerSegments[normalizedSegmentIndex] = segments[normalizedSegmentIndex];
							}
							if(withUpper) {
								if(isRange) {
									upperSegments = allocateSegments(upperSegments, lowerSegments, creator, ipv4SegmentCount, normalizedSegmentIndex);
									upperSegments[normalizedSegmentIndex] = createSegment(
											addressString,
											IPVersion.IPV4,
											maskedSegUpper,
											maskedSegUpper,
											false,
											i,
											currentPrefix,
											creator);
								} else if(upperSegments != null) {
									upperSegments[normalizedSegmentIndex] = lowerSegments[normalizedSegmentIndex];
								}
							}
						}
						++normalizedSegmentIndex;
						count--;
					}
					addrParseData.setBitLength(i, bits);
					continue;
				} //end handle inet_aton joined segments
			}
			long hostLower = lower, hostUpper = upper;
			Masker masker = null;
			boolean unmasked = true;
			if(hasMask) {
				masker = maskers[i];
				int maskInt = mask.getSegment(normalizedSegmentIndex).getSegmentValue();
				if(masker == null) {
					maskers[i] = masker = maskRange(lower, upper, maskInt, creator.getMaxValuePerSegment());
				}
				if(!masker.isSequential() && finalResult.maskException == null) {
					finalResult.maskException = new IncompatibleAddressException(lower, upper, maskInt, "ipaddress.error.maskMismatch");
				}
				lower = (int) masker.getMaskedLower(lower, maskInt);
				upper = (int) masker.getMaskedUpper(upper, maskInt);
				unmasked = hostLower == lower && hostUpper == upper;
				maskedIsDifferent = maskedIsDifferent || !unmasked;
			}
			Integer segmentPrefixLength = getSegmentPrefixLength(normalizedSegmentIndex, IPv4Address.BITS_PER_SEGMENT, qualifier);
			if(doAddress) {
				if(maskedIsDifferent || segmentPrefixLength != null) {
					hostSegments = allocateSegments(hostSegments, segments, creator, ipv4SegmentCount, normalizedSegmentIndex);
					hostSegments[normalizedSegmentIndex] = createSegment(
							addressString,
							IPVersion.IPV4,
							(int) hostLower,
							(int) hostUpper,
							true,
							i,
							null,
							creator);
				}
				segments[normalizedSegmentIndex] = createSegment(
						addressString,
						IPVersion.IPV4,
						(int) lower,
						(int) upper,
						unmasked,
						i,
						segmentPrefixLength,
						creator);
			}
			if(doRangeBoundaries) {
				boolean isRange = lower != upper;
				if(!doAddress || isRange) {
					if(doAddress) {
						lowerSegments = allocateSegments(lowerSegments, segments, creator, ipv4SegmentCount, normalizedSegmentIndex);
					} // else segments already allocated
					lowerSegments[normalizedSegmentIndex] = createSegment(
							addressString,
							IPVersion.IPV4,
							(int) lower,
							(int) lower,
							false,
							i,
							segmentPrefixLength,
							creator);
				} else if(lowerSegments != null) {
					lowerSegments[normalizedSegmentIndex] = segments[normalizedSegmentIndex];
				}
				if(withUpper) {
					if(isRange) {
						upperSegments = allocateSegments(upperSegments, lowerSegments, creator, ipv4SegmentCount, normalizedSegmentIndex);
						upperSegments[normalizedSegmentIndex] = createSegment(
								addressString,
								IPVersion.IPV4,
								(int) upper,
								(int) upper,
								false,
								i,
								segmentPrefixLength,
								creator);
					} else if(upperSegments != null) {
						upperSegments[normalizedSegmentIndex] = lowerSegments[normalizedSegmentIndex];
					}
				}
			}
			normalizedSegmentIndex++;
			addrParseData.setBitLength(i, IPv4Address.BITS_PER_SEGMENT);
		}
		ParsedAddressCreator<IPv4Address, IPv4AddressSection, ?, IPv4AddressSegment> addressCreator = creator;
		Integer prefLength = getPrefixLength(qualifier);
		IPv4AddressSection result, hostResult = null;
		if(doAddress) {
			finalResult.section = result = addressCreator.createPrefixedSectionInternal(segments, prefLength);
			if(hostSegments != null) {
				finalResult.hostSection = hostResult = addressCreator.createSectionInternal(hostSegments);
				if(checkExpandedValues(hostResult, expandedStart, expandedEnd)) {
					finalResult.joinHostException = new IncompatibleAddressException(addressString, "ipaddress.error.invalid.joined.ranges");
				}
			}

			if(checkExpandedValues(result, expandedStart, expandedEnd)) {
				finalResult.joinAddressException = new IncompatibleAddressException(addressString, "ipaddress.error.invalid.joined.ranges");
				if(hostResult == null) {
					finalResult.joinHostException = finalResult.joinAddressException;
				}
			}
		}
		if(doRangeBoundaries) {
			// if we have a prefix subnet, it is possible our lower and upper boundaries exceed what appears in the parsed address
			Integer prefixLength = getPrefixLength(qualifier);
			boolean isPrefixSubnet;
			if(prefixLength != null) {
				IPAddressNetwork<?, ?, ?, ?, ?> network = getParameters().getIPv4Parameters().getNetwork();
				IPv4AddressSegment[] lowerSegs, upperSegs;
				if(doAddress) {
					lowerSegs = upperSegs = segments;
				} else {
					lowerSegs = lowerSegments;
					upperSegs = (upperSegments == null) ? lowerSegments : upperSegments;
				}
				isPrefixSubnet = ParsedAddressGrouping.isPrefixSubnet(
						segmentIndex -> lowerSegs[segmentIndex].getSegmentValue(),
						segmentIndex -> upperSegs[segmentIndex].getUpperSegmentValue(),
						lowerSegs.length,
						IPv4Address.BYTES_PER_SEGMENT,
						IPv4Address.BITS_PER_SEGMENT,
						IPv4Address.MAX_VALUE_PER_SEGMENT,
						prefixLength,
						network.getPrefixConfiguration(),
						false);
				if(isPrefixSubnet) {
					if(lowerSegments == null) {
						//allocate lower segments from address segments
						lowerSegments = allocateSegments(lowerSegments, segments, creator, ipv4SegmentCount, ipv4SegmentCount);
					}
					if(upperSegments == null) {
						//allocate upper segments from lower segments
						upperSegments = allocateSegments(upperSegments, lowerSegments, creator, ipv4SegmentCount, ipv4SegmentCount);
					}
				}
			} else {
				isPrefixSubnet = false;
			}
			if(lowerSegments != null) {
				finalResult.lowerSection = addressCreator.createPrefixedSectionInternal(lowerSegments, prefLength, true).getLower();
			}
			if(upperSegments != null) {
				IPv4AddressSection section = addressCreator.createPrefixedSectionInternal(upperSegments, prefLength);
				if(isPrefixSubnet) {
					section = section.toPrefixBlock();
				}
				finalResult.upperSection = section.getUpper();
			}
		}
	}

	private void createIPv6Sections(boolean doAddress, boolean doRangeBoundaries, boolean withUpper) {
		ParsedHostIdentifierStringQualifier qualifier = getQualifier();
		IPAddress mask = getProviderMask();
		if(mask != null && mask.getBlockMaskPrefixLength(true) != null) {
			mask = null;//we don't do any masking if the mask is a subnet mask, instead we just map it to the corresponding prefix length
		}
		boolean hasMask = mask != null;
		AddressParseData addressParseData = getAddressParseData();
		int segmentCount = addressParseData.getSegmentCount();
		if(hasMask && maskers == null) {
			maskers = new Masker[segmentCount];
		}
		IPv6AddressCreator creator = getIPv6AddressCreator();
		int ipv6SegmentCount = IPv6Address.SEGMENT_COUNT;
		
		IPv6AddressSegment[] hostSegments, segments, lowerSegments, upperSegments = null;
		hostSegments = upperSegments = null;
		if(doAddress) {
			segments = creator.createSegmentArray(ipv6SegmentCount);
			lowerSegments = null;
		} else if(doRangeBoundaries) {
			lowerSegments = creator.createSegmentArray(ipv6SegmentCount);
			segments = null;
		} else {
			return;
		}
		@SuppressWarnings("unchecked")
		TranslatedResult<IPv6Address,IPv6AddressSection> finalResult = 
				(TranslatedResult<IPv6Address, IPv6AddressSection>) values;
		if(values == null) {
			values = finalResult = new TranslatedResult<IPv6Address,IPv6AddressSection>() {
				/**
				 * 
				 */
				private static final long serialVersionUID = 1L;

				@Override
				ParsedAddressCreator<IPv6Address, IPv6AddressSection, ?, ?> getCreator() {
					return getIPv6AddressCreator();
				}
			};
		}
		boolean mixed = isProvidingMixedIPv6();
		int normalizedSegmentIndex = 0;
		int missingSegmentCount = (mixed ? IPv6Address.MIXED_ORIGINAL_SEGMENT_COUNT : ipv6SegmentCount) - segmentCount;
		boolean expandedSegments = (missingSegmentCount <= 0);
		int expandedStart, expandedEnd;
		expandedStart = expandedEnd = -1;
		CharSequence addressString = str;
		boolean maskedIsDifferent = false;
		
		//get the segments for IPv6
		for(int i = 0; i < segmentCount; i++) {
			long lower = addressParseData.getValue(i, AddressParseData.KEY_LOWER);
			long upper = addressParseData.getValue(i, AddressParseData.KEY_UPPER);
			
			if(!expandedSegments) {
				boolean isLastSegment = i == segmentCount - 1;
				boolean isWildcard = addressParseData.isWildcard(i);
				boolean isCompressed = isCompressed(i);
				
				// figure out if this segment should be expanded
				expandedSegments = isLastSegment || isCompressed;
				if(!expandedSegments) {
					// we check if we are wildcard and no other wildcard or compressed segment further down
					if(expandedSegments = isWildcard) {
						for(int j = i + 1; j < segmentCount; j++) {
							if(addressParseData.isWildcard(j) || isCompressed(j)) {
								expandedSegments = false;
								break;
							}
						}
					}
				} 
				if(expandedSegments) {
					long lowerHighBytes, upperHighBytes;
					boolean hostIsRange;
					 if(isCompressed) {
						lower = upper = lowerHighBytes = upperHighBytes = 0;
						hostIsRange = false;
					} else if(isWildcard) {
						if(missingSegmentCount > 3) {
							upperHighBytes = 0xffffffffffffffffL >>> ((7 - missingSegmentCount) << 4);
							upper = 0xffffffffffffffffL;
						} else {
							upperHighBytes = 0;
							upper = 0xffffffffffffffffL >>> ((3 - missingSegmentCount) << 4);
						}
						lower = lowerHighBytes = 0;
						hostIsRange = true;
					} else {
						if(missingSegmentCount > 3) {
							lowerHighBytes = addressParseData.getValue(i, AddressParseData.KEY_EXTENDED_LOWER);//the high half of the lower value
							upperHighBytes = addressParseData.getValue(i, AddressParseData.KEY_EXTENDED_UPPER);//the high half of the upper value
							hostIsRange = (lower != upper) || (lowerHighBytes != upperHighBytes);
						} else {
							lowerHighBytes = upperHighBytes = 0;
							hostIsRange = (lower != upper);
						}
						expandedStart = i;
						expandedEnd = i + missingSegmentCount;
					}
					int bits = IPv6Address.BITS_PER_SEGMENT * (missingSegmentCount + 1);
					long maskedLower, maskedUpper, maskedLowerHighBytes, maskedUpperHighBytes;
					boolean maskedIsRange;
					if(hasMask) {
						// line up the mask segments into two longs
						if(isCompressed) {
							maskers[i] = DEFAULT_MASKER;
							maskedLower = maskedUpper = maskedLowerHighBytes = maskedUpperHighBytes = 0;
							maskedIsRange = false;
						} else {
							int bitsPerSegment = IPv6Address.BITS_PER_SEGMENT;
							long maskVal = 0;
							if(missingSegmentCount >= 4) {
								ExtendedMasker masker = (ExtendedMasker) maskers[i];
								long extendedMaskVal = 0;
								int extendedCount = missingSegmentCount - 3;
								for(int k = 0; k < extendedCount; k++) {
									extendedMaskVal = (extendedMaskVal << bitsPerSegment) | mask.getSegment(normalizedSegmentIndex + k).getSegmentValue();
								}
								for(int k = extendedCount; k <= missingSegmentCount; k++) {
									maskVal = (maskVal << bitsPerSegment) | mask.getSegment(normalizedSegmentIndex + k).getSegmentValue();
								}
								if(masker == null) {
									// shift must be 6 bits at most for this shift to work per the java spec (so it must be less than 2^6 = 64)
									long extendedMaxValue = bits == Long.SIZE ? 0xffffffffffffffffL : ~(~0L << (bits - Long.SIZE));
									maskers[i] = masker = maskExtendedRange(
											lower, lowerHighBytes, 
											upper, upperHighBytes, 
											maskVal, extendedMaskVal, 
											0xffffffffffffffffL, extendedMaxValue);
								}
								if(!masker.isSequential() && finalResult.maskException == null) {
									int byteCount = (missingSegmentCount + 1) * IPv6Address.BYTES_PER_SEGMENT;
									finalResult.maskException = new IncompatibleAddressException(
										new BigInteger(1, toBytesSizeAdjusted(lower, lowerHighBytes, byteCount)).toString(), 
										new BigInteger(1, toBytesSizeAdjusted(upper, upperHighBytes, byteCount)).toString(), 
										new BigInteger(1, toBytesSizeAdjusted(maskVal, extendedMaskVal, byteCount)).toString(),
										"ipaddress.error.maskMismatch");
								}
								maskedLowerHighBytes = masker.getExtendedMaskedLower(lowerHighBytes, extendedMaskVal);
								maskedUpperHighBytes = masker.getExtendedMaskedUpper(upperHighBytes, extendedMaskVal);
								maskedLower = masker.getMaskedLower(lower, maskVal);
								maskedUpper = masker.getMaskedUpper(upper, maskVal);
								maskedIsRange = (maskedLower != maskedUpper) || (maskedLowerHighBytes != maskedUpperHighBytes);
								maskedIsDifferent = maskedIsDifferent || maskedLower != lower || maskedUpper != upper|| maskedLowerHighBytes != lowerHighBytes || maskedUpperHighBytes != upperHighBytes;
							} else {
								Masker masker = maskers[i];
								for(int k = 0; k <= missingSegmentCount; k++) {
									maskVal = (maskVal << bitsPerSegment) | mask.getSegment(normalizedSegmentIndex + k).getSegmentValue();
								}
								if(masker == null) {
									// shift must be 6 bits at most for this shift to work per the java spec (so it must be less than 2^6 = 64)
									long maxValue = bits == Long.SIZE ? 0xffffffffffffffffL : ~(~0L << bits);
									maskers[i] = masker = maskRange(lower, upper, maskVal, maxValue);
								}
								if(!masker.isSequential() && finalResult.maskException == null) {
									finalResult.maskException = new IncompatibleAddressException(lower, upper, maskVal, "ipaddress.error.maskMismatch");
								}
								maskedLowerHighBytes = maskedUpperHighBytes = 0;
								maskedLower = masker.getMaskedLower(lower, maskVal);
								maskedUpper = masker.getMaskedUpper(upper, maskVal);
								maskedIsRange = maskedLower != maskedUpper;
								maskedIsDifferent = maskedIsDifferent || maskedLower != lower || maskedUpper != upper;
							}
						}
					} else {
						maskedLowerHighBytes = lowerHighBytes;
						maskedUpperHighBytes = upperHighBytes;
						maskedLower = lower;
						maskedUpper = upper;
						maskedIsRange = hostIsRange;
					}
					int shift = bits;
					int count = missingSegmentCount;
					while(count >= 0) { // add the missing segments
						Integer currentPrefix = getSegmentPrefixLength(normalizedSegmentIndex, IPv6Address.BITS_PER_SEGMENT, qualifier);
						int hostSegLower, hostSegUpper, maskedSegLower, maskedSegUpper;
						if(isCompressed) {
							hostSegLower = hostSegUpper = maskedSegLower = maskedSegUpper = 0;
						} else {
							shift -= IPv6Address.BITS_PER_SEGMENT;
							int segmentBitsMask = IPv6Address.MAX_VALUE_PER_SEGMENT;
							if(count >= 4) {
								int shorterShift = shift - (IPv6Address.BITS_PER_SEGMENT << 2);
								hostSegLower = (int) (lowerHighBytes >>> shorterShift) & segmentBitsMask;
								hostSegUpper = hostIsRange ? (int) (upperHighBytes >>> shorterShift) & segmentBitsMask : hostSegLower;
								if(hasMask) {
									maskedSegLower = (int) (maskedLowerHighBytes >>> shorterShift) & segmentBitsMask;
									maskedSegUpper = maskedIsRange ? (int) (maskedUpperHighBytes >>> shorterShift) & segmentBitsMask : maskedSegLower;
								} else {
									maskedSegLower = hostSegLower;
									maskedSegUpper = hostSegUpper;
								}
							} else {
								hostSegLower = (int) (lower >>> shift) & segmentBitsMask;
								hostSegUpper = hostIsRange ? (int) (upper >>> shift) & segmentBitsMask : hostSegLower;
								if(hasMask) {
									maskedSegLower = (int) (maskedLower >>> shift) & segmentBitsMask;
									maskedSegUpper = maskedIsRange ? (int) (maskedUpper >>> shift) & segmentBitsMask : maskedSegLower;
								} else {
									maskedSegLower = hostSegLower;
									maskedSegUpper = hostSegUpper;
								}
							}
						}
						if(doAddress) {
							if(maskedIsDifferent || currentPrefix != null) {
								hostSegments = allocateSegments(hostSegments, segments, creator, ipv6SegmentCount, normalizedSegmentIndex);
								hostSegments[normalizedSegmentIndex] = createSegment(
										addressString,
										IPVersion.IPV6,
										hostSegLower,
										hostSegUpper,
										false,
										i,
										null,
										creator);
							}
							segments[normalizedSegmentIndex] = createSegment(
								addressString,
								IPVersion.IPV6,
								maskedSegLower,
								maskedSegUpper,
								false,
								i,
								currentPrefix,
								creator);
						}
						if(doRangeBoundaries) {
							boolean isSegRange = maskedSegLower != maskedSegUpper;
							if(!doAddress || isSegRange) {
								if(doAddress) {
									lowerSegments = allocateSegments(lowerSegments, segments, creator, ipv6SegmentCount, normalizedSegmentIndex);
								} // else segments already allocated
								lowerSegments[normalizedSegmentIndex] = createSegment(
										addressString,
										IPVersion.IPV6,
										maskedSegLower,
										maskedSegLower,
										false,
										i,
										currentPrefix,
										creator);
								
							} else if(lowerSegments != null) {
								lowerSegments[normalizedSegmentIndex] = segments[normalizedSegmentIndex];
							}
							if(withUpper) {
								if(isSegRange) {
									upperSegments = allocateSegments(upperSegments, lowerSegments, creator, ipv6SegmentCount, normalizedSegmentIndex);
									upperSegments[normalizedSegmentIndex] = createSegment(
											addressString,
											IPVersion.IPV6,
											maskedSegUpper,
											maskedSegUpper,
											false,
											i,
											currentPrefix,
											creator);
								} else if(upperSegments != null) {
									upperSegments[normalizedSegmentIndex] = lowerSegments[normalizedSegmentIndex];
								}
							}
						}
						++normalizedSegmentIndex;
						count--;
					}
					addressParseData.setBitLength(i, bits);
					continue;
				} //end handle joined segments
			}

			long hostLower = lower, hostUpper = upper;
			Masker masker = null;
			boolean unmasked = true;
			if(hasMask) {
				masker = maskers[i];
				int maskInt = mask.getSegment(normalizedSegmentIndex).getSegmentValue();
				if(masker == null) {
					maskers[i] = masker = maskRange(lower, upper, maskInt, creator.getMaxValuePerSegment());
				}
				if(!masker.isSequential() && finalResult.maskException == null) {
					finalResult.maskException = new IncompatibleAddressException(lower, upper, maskInt, "ipaddress.error.maskMismatch");
				}
				lower = (int) masker.getMaskedLower(lower, maskInt);
				upper = (int) masker.getMaskedUpper(upper, maskInt);
				unmasked =  hostLower == lower && hostUpper == upper;
				maskedIsDifferent = maskedIsDifferent || !unmasked;
			}
			Integer segmentPrefixLength = getSegmentPrefixLength(normalizedSegmentIndex, IPv6Address.BITS_PER_SEGMENT, qualifier);
			if(doAddress) {
				if(maskedIsDifferent || segmentPrefixLength != null) {
					hostSegments = allocateSegments(hostSegments, segments, creator, ipv6SegmentCount, normalizedSegmentIndex);
					hostSegments[normalizedSegmentIndex] = createSegment(
							addressString,
							IPVersion.IPV6,
							(int) hostLower,
							(int) hostUpper,
							true,
							i,
							null,
							creator);
				}
				segments[normalizedSegmentIndex] = createSegment(
					addressString,
					IPVersion.IPV6,
					(int) lower,
					(int) upper,
					unmasked,
					i,
					segmentPrefixLength,
					creator);
			}
			if(doRangeBoundaries) {
				boolean isRange = lower != upper;
				if(!doAddress || isRange) {
					if(doAddress) {
						lowerSegments = allocateSegments(lowerSegments, segments, creator, ipv6SegmentCount, normalizedSegmentIndex);
					} // else segments already allocated
					lowerSegments[normalizedSegmentIndex] = createSegment(
							addressString,
							IPVersion.IPV6,
							(int) lower,
							(int) lower,
							false,
							i,
							segmentPrefixLength,
							creator);
				} else if(lowerSegments != null) {
					lowerSegments[normalizedSegmentIndex] = segments[normalizedSegmentIndex];
				}
				if(withUpper) {
					if(isRange) {
						upperSegments = allocateSegments(upperSegments, lowerSegments, creator, ipv6SegmentCount, normalizedSegmentIndex);
						upperSegments[normalizedSegmentIndex] = createSegment(
								addressString,
								IPVersion.IPV6,
								(int) upper,
								(int) upper,
								false,
								i,
								segmentPrefixLength,
								creator);
					} else if(upperSegments != null) {
						upperSegments[normalizedSegmentIndex] = lowerSegments[normalizedSegmentIndex];
					}
				}
			}
			normalizedSegmentIndex++;
			addressParseData.setBitLength(i, IPv6Address.BITS_PER_SEGMENT);
		}
		ParsedAddressCreator<?, IPv6AddressSection, IPv4AddressSection, IPv6AddressSegment> addressCreator = creator;
		Integer prefLength = getPrefixLength(qualifier);
		if(mixed) {
			IPv4AddressSeqRange ipv4Range = (IPv4AddressSeqRange) mixedParsedAddress.getProviderSeqRange();
			if(hasMask && mixedMaskers == null) {
				mixedMaskers = new Masker[IPv4Address.SEGMENT_COUNT];
			}
			for(int n = 0; n < 2; n++) {
				int m = n << 1;
				Integer segmentPrefixLength = getSegmentPrefixLength(normalizedSegmentIndex, IPv6Address.BITS_PER_SEGMENT, qualifier);
				
				IPv4AddressSegment oneLow = ipv4Range.getLower().getSegment(m);
				int o = m + 1;
				IPv4AddressSegment twoLow = ipv4Range.getLower().getSegment(o);
				IPv4AddressSegment oneUp = ipv4Range.getUpper().getSegment(m);
				IPv4AddressSegment twoUp = ipv4Range.getUpper().getSegment(o);
				int oneLower = oneLow.getSegmentValue();
				int twoLower = twoLow.getSegmentValue();
				int oneUpper = oneUp.getSegmentValue();
				int twoUpper = twoUp.getSegmentValue();
				
				int originalOneLower = oneLower;
				int originalTwoLower = twoLower;
				int originalOneUpper = oneUpper;
				int originalTwoUpper = twoUpper;
				
				if(hasMask) {
					int maskInt = mask.getSegment(normalizedSegmentIndex).getSegmentValue();
					int shift = IPv4Address.BITS_PER_SEGMENT;
					int shiftedMask = maskInt >> shift;
					Masker masker = mixedMaskers[m];
					if(masker == null) {
						mixedMaskers[m] = masker = maskRange(oneLower, oneUpper, shiftedMask, IPv4Address.MAX_VALUE_PER_SEGMENT);
					}
					if(!masker.isSequential() && finalResult.maskException == null) {
						finalResult.maskException = new IncompatibleAddressException(oneLower, oneUpper, shiftedMask, "ipaddress.error.maskMismatch");
					}
					oneLower = (int) masker.getMaskedLower(oneLower, shiftedMask);
					oneUpper = (int) masker.getMaskedUpper(oneUpper, shiftedMask);
					masker = mixedMaskers[m + 1];
					if(masker == null) {
						mixedMaskers[m + 1] = masker = maskRange(twoLower, twoUpper, maskInt, IPv4Address.MAX_VALUE_PER_SEGMENT);
					}
					if(!masker.isSequential() && finalResult.maskException == null) {
						finalResult.maskException = new IncompatibleAddressException(twoLower, twoUpper, maskInt, "ipaddress.error.maskMismatch");
					}
					twoLower = (int) masker.getMaskedLower(twoLower, maskInt);
					twoUpper = (int) masker.getMaskedUpper(twoUpper, maskInt);
					maskedIsDifferent = maskedIsDifferent || oneLower != originalOneLower || oneUpper != originalOneUpper ||
							twoLower != originalTwoLower || twoUpper != originalTwoUpper;
				}
				boolean isRange = oneLower != oneUpper || twoLower != twoUpper;
				if(doAddress) {
					boolean doHostSegment = maskedIsDifferent || segmentPrefixLength != null;
					if(doHostSegment) {
						hostSegments = allocateSegments(hostSegments, segments, creator, ipv6SegmentCount, normalizedSegmentIndex);
					}
					if(!isRange) {
						if(doHostSegment) {
							hostSegments[normalizedSegmentIndex] = createIPv6Segment(originalOneLower, originalTwoLower, null, creator);
						}
						segments[normalizedSegmentIndex] = createIPv6Segment(
								oneLower,
								twoLower,
								segmentPrefixLength,
								creator);
					} else {
						if(doHostSegment) {
							hostSegments[normalizedSegmentIndex] = createIPv6RangeSegment(
									finalResult,
									ipv4Range,
									originalOneLower,
									originalOneUpper,
									originalTwoLower,
									originalTwoUpper,
									null,
									creator);
						}
						segments[normalizedSegmentIndex] = createIPv6RangeSegment(
								finalResult,
								ipv4Range,
								oneLower,
								oneUpper,
								twoLower,
								twoUpper,
								segmentPrefixLength,
								creator);
					}
				}
				if(doRangeBoundaries) {
					if(!doAddress || isRange) {
						if(doAddress) {
							lowerSegments = allocateSegments(lowerSegments, segments, creator, ipv6SegmentCount, normalizedSegmentIndex);
						} // else segments already allocated
						lowerSegments[normalizedSegmentIndex] = createIPv6Segment(
								oneLower,
								twoLower,
								segmentPrefixLength,
								creator);
					} else if(lowerSegments != null) {
						lowerSegments[normalizedSegmentIndex] = segments[normalizedSegmentIndex];
					}
					if(withUpper) {
						if(isRange) {
							upperSegments = allocateSegments(upperSegments, lowerSegments, creator, ipv6SegmentCount, normalizedSegmentIndex);
							upperSegments[normalizedSegmentIndex] = createIPv6Segment(
									oneUpper,
									twoUpper,
									segmentPrefixLength, // we must keep prefix length for upper to get prefix subnet creation
									creator);
						} else if(upperSegments != null) {
							upperSegments[normalizedSegmentIndex] = lowerSegments[normalizedSegmentIndex];
						}
					}
				}
				normalizedSegmentIndex++;
			}
		}
		IPv6AddressSection result, hostResult = null;
		if(doAddress) {
			if(hostSegments != null) {
				finalResult.hostSection = hostResult = addressCreator.createSectionInternal(hostSegments);
				if(checkExpandedValues(hostResult, expandedStart, expandedEnd)) {
					finalResult.joinHostException = new IncompatibleAddressException(addressString, "ipaddress.error.invalid.joined.ranges");
				}
			}
			finalResult.section = result = addressCreator.createPrefixedSectionInternal(segments, prefLength);
			if(checkExpandedValues(result, expandedStart, expandedEnd)) {
				finalResult.joinAddressException = new IncompatibleAddressException(addressString, "ipaddress.error.invalid.joined.ranges");
				if(hostResult == null) {
					finalResult.joinHostException = finalResult.joinAddressException;
				}
			}
		}
		if(doRangeBoundaries) {
			Integer prefixLength = getPrefixLength(qualifier);
			boolean isPrefixSubnet;
			if(prefixLength != null) {
				IPAddressNetwork<?, ?, ?, ?, ?> network = getParameters().getIPv6Parameters().getNetwork();
				IPv6AddressSegment[] lowerSegs, upperSegs;
				if(doAddress) {
					lowerSegs = upperSegs = segments;
				} else {
					lowerSegs = lowerSegments;
					upperSegs = (upperSegments == null) ? lowerSegments : upperSegments;
				}
				isPrefixSubnet = ParsedAddressGrouping.isPrefixSubnet(
						segmentIndex -> lowerSegs[segmentIndex].getSegmentValue(),
						segmentIndex -> upperSegs[segmentIndex].getUpperSegmentValue(),
						lowerSegs.length,
						IPv6Address.BYTES_PER_SEGMENT,
						IPv6Address.BITS_PER_SEGMENT,
						IPv6Address.MAX_VALUE_PER_SEGMENT,
						prefixLength,
						network.getPrefixConfiguration(),
						false);
				if(isPrefixSubnet) {
					if(lowerSegments == null) {
						//allocate lower segments from address segments
						lowerSegments = allocateSegments(lowerSegments, segments, creator, ipv6SegmentCount, ipv6SegmentCount);
					}
					if(upperSegments == null) {
						//allocate upper segments from lower segments
						upperSegments = allocateSegments(upperSegments, lowerSegments, creator, ipv6SegmentCount, ipv6SegmentCount);
					}
				}
			} else {
				isPrefixSubnet = false;
			}
			if(lowerSegments != null) {
				finalResult.lowerSection = addressCreator.createPrefixedSectionInternal(lowerSegments, prefLength, true).getLower(); // getLower needed for all prefix subnet config
			}
			if(upperSegments != null) {
				IPv6AddressSection section = addressCreator.createPrefixedSectionInternal(upperSegments, prefLength);
				if(isPrefixSubnet) {
					section = section.toPrefixBlock();
				}
				finalResult.upperSection = section.getUpper();
			}
		}
	}
	
	/*
	 * When expanding a set of segments into multiple, it is possible that the new segments do not accurately
	 * cover the same ranges of values.  This occurs when there is a range in the upper segments and the lower
	 * segments do not cover the full range (as is the case in the original unexpanded segment).
	 * 
	 * This does not include compressed 0 segments or compressed '*' segments, as neither can have the issue.
	 * 
	 * Returns true if the expansion was invalid.
	 * 
	 */
	private static boolean checkExpandedValues(IPAddressSection section, int start, int end) {
		if(section != null && start < end) {
			IPAddressSegment seg = section.getSegment(start);
			boolean lastWasRange = seg.isMultiple();
			do {
				seg = section.getSegment(++start);
				if(lastWasRange) {
					if(!seg.isFullRange()) {
						return true;
					}
				} else {
					lastWasRange = seg.isMultiple();
				}
			} while(start < end);
		}
		return false;
	}

	private <S extends IPAddressSegment> S createSegment(
			CharSequence addressString,
			IPVersion version,
			int val,
			int upperVal,
			boolean useFlags,
			int parsedSegIndex,
			Integer segmentPrefixLength,
			ParsedAddressCreator<?, ?, ?, S> creator) {
		AddressParseData parseData = getAddressParseData();
		if(val != upperVal) {
			return createRangeSeg(addressString, version, val, upperVal,
					useFlags, parseData, parsedSegIndex,
					segmentPrefixLength, creator);
		}
		S result;
		if(!useFlags) {
			result = creator.createSegment(val, val, segmentPrefixLength);
		} else {
			result = creator.createSegmentInternal(
				val,
				segmentPrefixLength,
				addressString,
				val,
				parseData.getFlag(parsedSegIndex, AddressParseData.KEY_STANDARD_STR),
				parseData.getIndex(parsedSegIndex, AddressParseData.KEY_LOWER_STR_START_INDEX),
				parseData.getIndex(parsedSegIndex, AddressParseData.KEY_LOWER_STR_END_INDEX));
		}
		return result;
	}

	/*
	 * create an IPv6 segment by joining two IPv4 segments
	 */
	private IPv6AddressSegment createIPv6Segment(int value1, int value2, Integer segmentPrefixLength, IPv6AddressCreator creator) {
		int value = (value1 << IPv4Address.BITS_PER_SEGMENT) | value2;
		IPv6AddressSegment result = creator.createSegment(value, segmentPrefixLength);
		return result;
	}

	/*
	 * create an IPv6 segment by joining two IPv4 segments
	 */
	private static IPv6AddressSegment createIPv6RangeSegment(
			TranslatedResult<?,?> finalResult,
			AddressItem item,
			int upperRangeLower,
			int upperRangeUpper,
			int lowerRangeLower,
			int lowerRangeUpper,
			Integer segmentPrefixLength,
			IPv6AddressCreator creator) {
		int shift = IPv4Address.BITS_PER_SEGMENT;
		if(upperRangeLower != upperRangeUpper) {
			//if the high segment has a range, the low segment must match the full range, 
			//otherwise it is not possible to create an equivalent IPv6 range when joining two IPv4 ranges
			if(segmentPrefixLength != null && creator.getNetwork().getPrefixConfiguration().allPrefixedAddressesAreSubnets()) {
				if(segmentPrefixLength > shift) {
					int lowerPrefixLength = segmentPrefixLength - shift;
					
					int fullMask = ~(~0 << shift); //allBitSize must be 6 digits at most for this shift to work per the java spec (so it must be less than 2^6 = 64)
					int networkMask = fullMask & (fullMask << (shift - lowerPrefixLength));
					int hostMask = ~networkMask & fullMask;
					lowerRangeLower &= networkMask;
					lowerRangeUpper |= hostMask;
					if(finalResult.mixedException == null && lowerRangeLower != 0 || lowerRangeUpper != IPv4Address.MAX_VALUE_PER_SEGMENT) {
						finalResult.mixedException = new IncompatibleAddressException(item, "ipaddress.error.invalidMixedRange");
					}
				} else {
					lowerRangeLower = 0;
					lowerRangeUpper = IPv4Address.MAX_VALUE_PER_SEGMENT;
				}
			} else if(finalResult.mixedException == null && lowerRangeLower != 0 || lowerRangeUpper != IPv4Address.MAX_VALUE_PER_SEGMENT) {
				finalResult.mixedException = new IncompatibleAddressException(item, "ipaddress.error.invalidMixedRange");
			}
		}
		return creator.createSegment(
				(upperRangeLower << shift) | lowerRangeLower,
				(upperRangeUpper << shift) | lowerRangeUpper,
				segmentPrefixLength);
	}

	private static <S extends IPAddressSegment> S createRangeSeg(
			CharSequence addressString,
			IPVersion version,
			int stringLower,
			int stringUpper,
			boolean useFlags,
			AddressParseData parseData,
			int parsedSegIndex,
			Integer segmentPrefixLength,
			ParsedAddressCreator<?, ?, ?, S> creator) {
		int lower = stringLower, upper = stringUpper;
		S result;
		if(!useFlags) {
			result = creator.createSegment(lower, upper, segmentPrefixLength);
		} else {
			result = creator.createRangeSegmentInternal(
				lower,
				upper,
				segmentPrefixLength,
				addressString,
				stringLower,
				stringUpper,
				parseData.getFlag(parsedSegIndex, AddressParseData.KEY_STANDARD_STR),
				parseData.getFlag(parsedSegIndex, AddressParseData.KEY_STANDARD_RANGE_STR),
				parseData.getIndex(parsedSegIndex, AddressParseData.KEY_LOWER_STR_START_INDEX),
				parseData.getIndex(parsedSegIndex, AddressParseData.KEY_LOWER_STR_END_INDEX),
				parseData.getIndex(parsedSegIndex, AddressParseData.KEY_UPPER_STR_END_INDEX));
		}
		return result;
	}

	private static <S extends IPAddressSegment> S createFullRangeSegment(
			IPVersion version,
			int stringLower,
			int stringUpper,
			int parsedSegIndex,
			Integer segmentPrefixLength,
			Integer mask,
			ParsedAddressCreator<?, ?, ?, S> creator) {
		boolean hasMask = (mask != null);
		if(hasMask) {
			int maskInt = mask.intValue();
			Masker masker = maskRange(stringLower, stringUpper, maskInt, creator.getMaxValuePerSegment());
			if(!masker.isSequential()) {
				throw new IncompatibleAddressException(stringLower, stringUpper, maskInt, "ipaddress.error.maskMismatch");
			}
			stringLower = (int) masker.getMaskedLower(stringLower, maskInt);
			stringUpper = (int) masker.getMaskedUpper(stringUpper, maskInt);
		}
		S result = createRangeSeg(null, version, stringLower, stringUpper,
				false, null, parsedSegIndex, segmentPrefixLength, creator);
		return result;
	}

	static IPAddress createAllAddress(
			IPVersion version,
			ParsedHostIdentifierStringQualifier qualifier,
			HostIdentifierString originator, 
			IPAddressStringParameters options) {
		int segmentCount = IPAddress.getSegmentCount(version);
		IPAddress mask = qualifier.getMaskLower();
		if(mask != null && mask.getBlockMaskPrefixLength(true) != null) {
			mask = null;//we don't do any masking if the mask is a subnet mask, instead we just map it to the corresponding prefix length
		}
		boolean hasMask = mask != null;
		Integer prefLength = getPrefixLength(qualifier);
		if(version.isIPv4()) {
			ParsedAddressCreator<IPv4Address, IPv4AddressSection, ?, IPv4AddressSegment> creator = options.getIPv4Parameters().getNetwork().getAddressCreator();
			IPv4AddressSegment segments[] = creator.createSegmentArray(segmentCount);
			for(int i = 0; i < segmentCount; i++) {
				Integer segmentMask = hasMask ? cacheSegmentMask(mask.getSegment(i).getSegmentValue()) : null;
				segments[i] = createFullRangeSegment(
						version,
						0,
						IPv4Address.MAX_VALUE_PER_SEGMENT,
						i,
						getSegmentPrefixLength(i, version, qualifier),
						segmentMask,
						creator);
			}
			return creator.createAddressInternal(segments, originator, prefLength);
		} else {
			ParsedAddressCreator<IPv6Address, IPv6AddressSection, ?, IPv6AddressSegment> creator = options.getIPv6Parameters().getNetwork().getAddressCreator();
			IPv6AddressSegment segments[] = creator.createSegmentArray(segmentCount);
			for(int i = 0; i < segmentCount; i++) {
				Integer segmentMask = hasMask ? cacheSegmentMask(mask.getSegment(i).getSegmentValue()) : null;
				segments[i] = createFullRangeSegment(
						version,
						0,
						IPv6Address.MAX_VALUE_PER_SEGMENT,
						i,
						getSegmentPrefixLength(i, version, qualifier),
						segmentMask,
						creator);
			}
			return creator.createAddressInternal(segments, qualifier.getZone(), originator, prefLength);
		}
	}

	private static Integer getPrefixLength(ParsedHostIdentifierStringQualifier qualifier) {
		return qualifier.getEquivalentPrefixLength();
	}

	/**
	 * Across the address prefixes are:
	 * IPv6: (null):...:(null):(1 to 16):(0):...:(0)
	 * or IPv4: ...(null).(1 to 8).(0)...
	 * 
	 * @param segmentIndex
	 * @return
	 */
	private static Integer getSegmentPrefixLength(int segmentIndex, int bitsPerSegment, ParsedHostIdentifierStringQualifier qualifier) {
		Integer bits = getPrefixLength(qualifier);
		return ParsedAddressGrouping.getSegmentPrefixLength(bitsPerSegment, bits, segmentIndex);
	}
	
	/**
	 * Across the address prefixes are:
	 * IPv6: (null):...:(null):(1 to 16):(0):...:(0)
	 * or IPv4: ...(null).(1 to 8).(0)...
	 * 
	 * @param segmentIndex
	 * @param version
	 * @return
	 */
	private static Integer getSegmentPrefixLength(int segmentIndex, IPVersion version, ParsedHostIdentifierStringQualifier qualifier) {
		return getSegmentPrefixLength(segmentIndex, IPAddressSection.bitsPerSegment(version), qualifier);
	}
	
	private static Integer cacheSegmentMask(int i) {
		return ParsedAddressGrouping.cache(i);
	}
}
