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

package inet.ipaddr;

import java.math.BigInteger;
import java.util.Iterator;

import inet.ipaddr.IPAddress.IPVersion;
import inet.ipaddr.IPAddressSection.IPStringBuilderOptions;
import inet.ipaddr.IPAddressSection.IPStringOptions;
import inet.ipaddr.format.IPAddressDivisionSeries;
import inet.ipaddr.format.util.IPAddressPartStringCollection;

/**
 * Represents a series of IP address segments.
 * <p>
 * Provides methods relevant to IP addresses and IP address sections in addition to the more general methods pertaining to address and address sections in AddressSegmentSeries.
 * 
 * 
 * @author sfoley
 *
 */
public interface IPAddressSegmentSeries extends IPAddressDivisionSeries, AddressSegmentSeries {

	/**
	 * Returns the version of this segment series
	 * 
	 * @return
	 */
	IPVersion getIPVersion();
	
	/**
	 * Returns the equivalent address series with the smallest CIDR prefix possible (largest network),
	 * such that the range of values of this address includes the subnet block for that prefix.
	 * 
	 * @see #toPrefixBlock()
	 * @see #assignPrefixForSingleBlock()
	 * @return
	 */
	IPAddressSegmentSeries assignMinPrefixForBlock();
	
	/**
	 * Returns the equivalent CIDR address series with a prefix length for which the subnet block for that prefix matches the range of values in this series.
	 * In short, the returned series is a single block of address segment series.
	 * Another way of looking at it: if the range matches the range associated with some prefix length, then it returns the address series with that prefix length.
	 * <p>
	 * If no such prefix length exists, returns null.
	 * <p>
	 * If this address represents just a single address, "this" is returned.
	 * <p>
	 * The methods {@link #assignMinPrefixForBlock}, {@link #assignPrefixForSingleBlock} can be compared as follows.<p>
	 * {@link #assignMinPrefixForBlock} finds the smallest prefix length possible for this subnet and returns that subnet.<br>
	 * {@link #assignPrefixForSingleBlock} finds the smallest prefix length possible for this subnet that results in just a single prefix and returns that subnet.<br>
	 * <p>
	 * For example, given the address 1-2.2.3.* /16<br>
	 * {@link #assignMinPrefixForBlock} returns 1-2.2.3.* /24 if the prefix configuration is not ALL_PREFIXES_ARE_SUBNETS, otherwise 1-2.2.*.* /16, in order to return the subnet with the smallest prefix length <br>
	 * {@link #assignPrefixForSingleBlock} returns null because any prefix length will end up with at least two prefixes due to the first segment spanning two values: 1-2.
	 * <p>
	 * For another example, for the address 1.2.*.* /16 or the address 1.2.*.* both methods return 1.2.*.* /16.
	 * 
	 * @see #toPrefixBlock()
	 * @see #assignMinPrefixForBlock()
	 * @return
	 */
	IPAddressSegmentSeries assignPrefixForSingleBlock();

	/**
	 * If this series has a prefix length, returns the subnet block for that prefix. If this series has no prefix length, this series is returned.
	 * 
	 * @return the subnet block for the prefix length
	 */
	@Override
	IPAddressSegmentSeries toPrefixBlock();

	/** 
	 * Returns the segment series of the same length that spans all hosts.
	 * The network prefix length will be the one provided, and the network values will match the same of this series.
	 * 
	 * @param networkPrefixLength
	 * @return
	 */
	IPAddressSegmentSeries toPrefixBlock(int networkPrefixLength) throws PrefixLenException;

	/**
	 * Returns the host section of the series.  The returned section will have only as many segments as needed
	 * as determined by the existing CIDR network prefix length.  If this series has no CIDR prefix length, the returned host section will 
	 * be the full section associated with a prefix length of 0.
	 * 
	 * @return
	 */
	IPAddressSection getHostSection();

	/**
	 * Returns the host section of the address as indicated by the network prefix length provided.  The returned section will have only as many segments as needed
	 * to hold the host as indicated by the provided network prefix length.
	 * 
	 * @param networkPrefixLength
	 * @return
	 */
	IPAddressSection getHostSection(int networkPrefixLength);

	/**
	 * Returns the network section of the series if the series has a CIDR network prefix length, 
	 * otherwise it returns the entire series as a prefixed series with prefix matching the address bit length.
	 * 
	 * @return
	 */
	IPAddressSection getNetworkSection();
	
	/**
	 * Returns the network section of the series.  The returned section will have only as many segments as needed as indicated by networkPrefixLength.
	 * It will have networkPrefixLength as its associated prefix length,
	 * unless this address already has a smaller prefix length, in which case the existing prefix length is retained.
	 * 
	 * @param networkPrefixLength
	 * @return
	 */
	IPAddressSection getNetworkSection(int networkPrefixLength);
	
	/**
	 * Returns the network section of the series.  The returned section will have only as many segments as needed as indicated by networkPrefixLength.  
	 * If withPrefixLength is true, it will have networkPrefixLength as its associated prefix length,
	 * unless this series already has a smaller prefix length, in which case the existing prefix length is retained.
	 * 
	 * @param networkPrefixLength
	 * @param withPrefixLength whether the resulting section will have networkPrefixLength as the associated prefix length or not
	 * @return
	 */
	IPAddressSection getNetworkSection(int networkPrefixLength, boolean withPrefixLength);
	
	/**
	 * This produces a string with no compressed segments and all segments of full length,
	 * which is 4 characters for IPv6 segments and 3 characters for IPv4 segments.
	 */
	String toFullString();
	
	/**
	 * Returns a string with a CIDR prefix length if this section has a network prefix length.
	 * For IPv6, the host section will be compressed with ::, for IPv4 the host section will be zeros.
	 * @return
	 */
	String toPrefixLengthString();
	
	/**
	 * Produces a consistent subnet string.
	 * 
	 * In the case of IPv4, this means that wildcards are used instead of a network prefix.
	 * In the case of IPv6, a prefix will be used and the host section will be compressed with ::.
	 */
	String toSubnetString();
	
	/**
	 * This produces a string similar to the normalized string and avoids the CIDR prefix.
	 * CIDR addresses will be shown with wildcards and ranges instead of using the CIDR prefix notation.
	 */
	String toNormalizedWildcardString();
	
	/**
	 * This produces a string similar to the canonical string and avoids the CIDR prefix.
	 * Addresses with a network prefix length will be shown with wildcards and ranges instead of using the CIDR prefix length notation.
	 * IPv6 addresses will be compressed according to the canonical representation.
	 */
	String toCanonicalWildcardString();
	
	/**
	 * This is similar to toNormalizedWildcardString, avoiding the CIDR prefix, but with compression as well.
	 */
	String toCompressedWildcardString();
	
	/**
	 * This is the same as the string from toNormalizedWildcardString except that 
	 * it uses {@link IPAddress#SEGMENT_SQL_WILDCARD} instead of {@link IPAddress#SEGMENT_WILDCARD} and also uses {@link IPAddress#SEGMENT_SQL_SINGLE_WILDCARD}
	 */
	String toSQLWildcardString();

	/**
	 * Generates the reverse DNS lookup string
	 * For 8.255.4.4 it is 4.4.255.8.in-addr.arpa
	 * For 2001:db8::567:89ab it is b.a.9.8.7.6.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa
	 * 
	 *
	 * @throws IncompatibleAddressException if this address is a subnet
	 * @return
	 */
	String toReverseDNSLookupString();

	/**
	 * Writes this IP address segment series as a single binary value with always the exact same number of characters
	 * 
	 * If this section represents a range of values outside of the network prefix length, then this is printed as a range of two hex values.
	 */
	String toBinaryString();

	/**
	 * Writes this IP address segment series as a single octal value with always the exact same number of characters, with or without a preceding 0 prefix.
	 * 
	 * If this section represents a range of values outside of the network prefix length, then this is printed as a range of two hex values.
	 */
	String toOctalString(boolean with0Prefix);
	
	
	IPAddressPartStringCollection toStringCollection(IPStringBuilderOptions options);
	
	/**
	 * Creates a customized string from this series.
	 * 
	 * @param stringOptions
	 * @return
	 */
	String toNormalizedString(IPStringOptions stringOptions);
	
	@Override
	IPAddressNetwork<?,?,?,?,?> getNetwork();
	
	@Override
	IPAddressSection getSection();

	@Override
	IPAddressSection getSection(int index);
	
	@Override
	IPAddressSection getSection(int index, int endIndex);

	@Override
	IPAddressSegment getSegment(int index);
	
	@Override
	IPAddressSegment[] getSegments();

	/**
	 * Gets the count of single value series that this series may represent, but excluding series whose host is zero.
	 * The host is determined by the CIDR prefix length, if there is one.
	 * <p>
	 * If this address series has no range of values, then there is only one such address, or none if it has a zero host.
	 * <p>
	 * If this has no CIDR network prefix length, then it is equivalent to {@link #getCount()}.
	 * 
	 * @return
	 */
	BigInteger getNonZeroHostCount();

	/**
	 * Similar to {@link #getLower()}, but will not return a series that has a prefix length and whose host value is zero.
	 * If this series has no prefix length, returns the same series as {@link #getLower()}.
	 * 
	 * @return the lowest IP address series whose host is non-zero, or null if no such address section exists.
	 */
	IPAddressSegmentSeries getLowerNonZeroHost();
	
	@Override
	IPAddressSegmentSeries getLower();
	
	@Override
	IPAddressSegmentSeries getUpper();
	
	@Override
	Iterable<? extends IPAddressSegmentSeries> getIterable();
	
	@Override
	Iterator<? extends IPAddressSegmentSeries> iterator();
	
	@Override
	Iterator<? extends IPAddressSegmentSeries> prefixIterator();
	
	@Override
	Iterator<? extends IPAddressSegmentSeries> prefixBlockIterator();
	
	/**
	 * Similar to the prefix block iterator, but series with a host of zero are skipped.
	 * @return
	 */
	Iterator<? extends IPAddressSegmentSeries> nonZeroHostIterator();

	/**
	 * Iterates through series that can be obtained by iterating through all the upper segments up to the given segment count.
	 * Segments following remain the same in all iterated series.
	 * <p>
	 * For instance, given the IPv4 subnet 1-2.3-4.5-6.7, given the count argument 2, 
	 * it will iterate through 1.3.5-6.7, 1.4.5-6.7, 2.3.5-6.7, 2.4.5-6.7
	 * 
	 * @param segmentCount
	 * @return
	 */
	Iterator<? extends IPAddressSegmentSeries> blockIterator(int segmentCount);
	
	/**
	 * Iterates through the sequential series that make up this series.
	 * Generally this means finding the count of segments for which the segments that follow are not full range, and the using {@link #blockIterator(int)} with that segment count.
	 * <p>
	 * For instance, given the IPv4 subnet 1-2.3-4.5-6.7-8, it will iterate through 1.3.5.7-8, 1.3.6.7-8, 1.4.5.7-8, 1.4.6.7-8, 2.3.5.7-8, 2.3.6.7-8, 2.4.6.7-8, 2.4.6.7-8
	 * 
	 * @return
	 */
	Iterator<? extends IPAddressSegmentSeries> sequentialBlockIterator();
	
	/**
	 * provides the count of elements from the {@link #sequentialBlockIterator()}, the minimal number of sequential subseries that comprise this series
	 * @return
	 */
	BigInteger getSequentialBlockCount();
	
	@Override
	Iterator<? extends IPAddressSegment[]> segmentsIterator();
	
	/**
	 * Similar to the segments iterator, but series with a host of zero are skipped.
	 * 
	 * @return
	 */
	Iterator<? extends IPAddressSegment[]> segmentsNonZeroHostIterator();

	@Override
	IPAddressSegmentSeries increment(long increment);

	@Override
	IPAddressSegmentSeries incrementBoundary(long increment);

	/**
	 * Returns the segment series with a host of zero.
	 * If the series has no prefix length, then it returns an all-zero series.
	 * <p>
	 * The resultant series will have the same prefix length if {@link inet.ipaddr.AddressNetwork#getPrefixConfiguration()} is not {@link inet.ipaddr.AddressNetwork.PrefixConfiguration#ALL_PREFIXED_ADDRESSES_ARE_SUBNETS}, 
	 * otherwise it will no longer have a prefix length.
	 * <p>
	 * For instance, you can get the network address for a subnet as follows:
	 * <code>
	 * String addrStr = "1.2.3.4/16";
	 * IPAddress address = new IPAddressString(addrStr).getAddress();
	 * IPAddress networkAddress = address.toZeroHost(); //1.2.0.0
	 * </code>
	 * 
	 * @return
	 */
	IPAddressSegmentSeries toZeroHost();
	
	/**
	 * Produces the series with host values of 0 for the given prefix length.
	 * <p>
	 * If this series has the same prefix length, then the resulting series will too, otherwise the resulting series will have no prefix length.
	 * <p>
	 * This is nearly equivalent to doing the mask (bitwise conjunction) of this address series with the network mask for the given prefix length,
	 * but without the possibility of IncompatibleAddressException that can occur when applying a mask to a range of values.
	 * Instead, in this case, if the resulting series has a range of values, then the resulting series range boundaries will have host values of 0, but not necessarily  the intervening values.
	 * <p>
	 * For instance, you can get the network address for a subnet of prefix length 16 as follows:
	 * <code>
	 * String addrStr = "1.2.3.4";
	 * IPAddress address = new IPAddressString(addrStr).getAddress();
	 * IPAddress networkAddress = address.toZeroHost(16); //1.2.0.0
	 * </code>
	 * 
	 * @param prefixLength
	 * @return
	 */
	IPAddressSegmentSeries toZeroHost(int prefixLength);

	/**
	 * Returns whether the series has a host of zero.  If the series has no prefix length, or the prefix length matches the bit count, then returns false.
	 * 
	 * Otherwise, it checks whether all bits past the prefix are zero.
	 * 
	 * @return
	 */
	boolean includesZeroHost();
	
	/**
	 * Returns whether all bits past the given prefix length are zero.
	 * 
	 * @return
	 */
	boolean includesZeroHost(int prefixLength);

	/**
	 * Produces the series with host values of all one bits for the given prefix length.
	 * <p>
	 * If this series has the same prefix length, then the resulting series will too, otherwise the resulting series will have no prefix length.
	 * <p>
	 * This is nearly equivalent to doing the bitwise or (bitwise disjunction) of this address series with the network mask for the given prefix length,
	 * but without the possibility of IncompatibleAddressException that can occur when applying a mask to a range of values.
	 * Instead, in this case, if the resulting series has a range of values, then the resulting series range boundaries will have host values of all ones, but not necessarily  the intervening values.
	 * <p>
	 * For instance, you can get the broadcast address for a subnet of prefix length 16 as follows:
	 * <code>
	 * String addrStr = "1.2.3.4";
	 * IPAddress address = new IPAddressString(addrStr).getAddress();
	 * IPAddress broadcastAddress = address.toMaxHost(16); //1.2.255.255
	 * </code>
	 * 
	 * @param prefixLength
	 * @return
	 */
	IPAddressSegmentSeries toMaxHost(int prefixLength);
	
	/**
	 * Returns the segment series with a host of all ones.
	 * If the series has no prefix length, then it returns an all-ones series.
	 * <p>
	 * The resultant series will have the same prefix length if {@link inet.ipaddr.AddressNetwork#getPrefixConfiguration()} is not {@link inet.ipaddr.AddressNetwork.PrefixConfiguration#ALL_PREFIXED_ADDRESSES_ARE_SUBNETS}, 
	 * otherwise it will no longer have a prefix length.
	 * <p>
	 * For instance, you can get the broadcast address for a subnet as follows:
	 * <code>
	 * String addrStr = "1.2.3.4/16";
	 * IPAddress address = new IPAddressString(addrStr).getAddress();
	 * IPAddress broadcastAddress = address.toMaxHost(); //1.2.255.255
	 * </code>
	 * 
	 * @return
	 */
	IPAddressSegmentSeries toMaxHost();
	
	
	/**
	 * Returns whether the series has a host of all ones.  If the series has no prefix length, or the prefix length matches the bit count, then returns false.
	 * 
	 * Otherwise, it checks whether all bits past the prefix are ones.
	 * 
	 * @return
	 */
	boolean includesMaxHost();
	
	/**
	 * Returns whether all bits past the given prefix length are all ones.
	 * 
	 * @return
	 */
	boolean includesMaxHost(int prefixLength);
	
	@Override
	IPAddressSegmentSeries reverseSegments();
	
	/**
	 * Returns a new series which has the bits reversed.
	 * <p>
	 * If this has an associated prefix length, then the prefix length is dropped in the reversed series.
	 * <p>
	 * If this represents a range of values that cannot be reversed,
	 * because reversing the range results in a set of addresses that cannot be described by a range, then this throws {@link IncompatibleAddressException}.
	 * In such cases you can call {@link #iterator()}, {@link #getLower()}, {@link #getUpper()} or some other method to transform the address 
	 * into an address representing a single value before reversing.
	 * <p>
	 * @param perByte if true, only the bits in each byte are reversed, if false, then all bits in the address are reversed
	 * @throws IncompatibleAddressException if this is a subnet that cannot be reversed
	 * @return
	 */
	@Override
	IPAddressSegmentSeries reverseBits(boolean perByte);

	@Override
	IPAddressSegmentSeries reverseBytes();

	@Override
	IPAddressSegmentSeries reverseBytesPerSegment();
	
	/**
	 * Removes the prefix length.  The bits that were host bits become zero.
	 * 
	 * @see #removePrefixLength(boolean)
	 * @return
	 */
	@Override
	IPAddressSegmentSeries removePrefixLength();
	
	@Override
	IPAddressSegmentSeries withoutPrefixLength();
	
	/**
	 * Removes the prefix length.  If zeroed is false, the bits that were host bits do not become zero, unlike {@link #removePrefixLength()}
	 * 
	 * @deprecated use {@link #removePrefixLength()} or {@link #withoutPrefixLength()}
	 * @param zeroed whether the host bits become zero.
	 * @return
	 */
	@Override  @Deprecated
	IPAddressSegmentSeries removePrefixLength(boolean zeroed);
	
	@Override
	IPAddressSegmentSeries adjustPrefixBySegment(boolean nextSegment);
	
	@Override
	IPAddressSegmentSeries adjustPrefixBySegment(boolean nextSegment, boolean zeroed);
	
	@Override
	IPAddressSegmentSeries adjustPrefixLength(int adjustment);
	
	@Override
	IPAddressSegmentSeries adjustPrefixLength(int adjustment, boolean zeroed);
	
	@Override
	IPAddressSegmentSeries setPrefixLength(int prefixLength);
	
	@Override
	IPAddressSegmentSeries setPrefixLength(int prefixLength, boolean zeroed);

	@Override
	IPAddressSegmentSeries applyPrefixLength(int networkPrefixLength);
}
