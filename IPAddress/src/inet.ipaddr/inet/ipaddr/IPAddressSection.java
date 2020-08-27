/*
 * Copyright 2016-2020 Sean C Foley
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

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.math.BigInteger;
import java.net.InetAddress;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Comparator;
import java.util.Deque;
import java.util.Iterator;
import java.util.List;
import java.util.Objects;
import java.util.TreeMap;
import java.util.function.Function;
import java.util.function.IntFunction;
import java.util.function.IntUnaryOperator;
import java.util.function.Predicate;
import java.util.function.Supplier;
import java.util.function.ToLongFunction;
import java.util.function.UnaryOperator;
import java.util.stream.Stream;

import inet.ipaddr.AddressComparator.ValueComparator;
import inet.ipaddr.AddressNetwork.AddressSegmentCreator;
import inet.ipaddr.IPAddress.IPVersion;
import inet.ipaddr.IPAddressNetwork.IPAddressCreator;
import inet.ipaddr.IPAddressSection.WildcardOptions.WildcardOption;
import inet.ipaddr.IPAddressSeqRange.IPAddressSeqRangeSplitterSink;
import inet.ipaddr.format.AddressComponentRange;
import inet.ipaddr.format.standard.AddressCreator;
import inet.ipaddr.format.standard.AddressDivisionGrouping;
import inet.ipaddr.format.standard.AddressDivisionGrouping.StringOptions.Wildcards;
import inet.ipaddr.format.standard.IPAddressBitsDivision;
import inet.ipaddr.format.standard.IPAddressDivisionGrouping;
import inet.ipaddr.format.string.IPAddressStringDivisionSeries;
import inet.ipaddr.format.util.AddressComponentSpliterator;
import inet.ipaddr.format.util.IPAddressPartConfiguredString;
import inet.ipaddr.format.util.IPAddressPartStringCollection;
import inet.ipaddr.format.util.sql.IPAddressSQLTranslator;
import inet.ipaddr.format.util.sql.MySQLTranslator;
import inet.ipaddr.format.util.sql.SQLStringMatcher;
import inet.ipaddr.format.validate.ParsedAddressGrouping;
import inet.ipaddr.format.validate.ParsedIPAddress.BitwiseOrer;
import inet.ipaddr.format.validate.ParsedIPAddress.Masker;
import inet.ipaddr.ipv6.IPv6Address;
import inet.ipaddr.ipv6.IPv6AddressSegment;

/**
 * A section of an IPAddress. 
 * 
 * It is a series of individual address segments.
 * <p>
 * IPAddressSection objects are immutable.  Some of the derived state is created upon demand and cached.
 * 
 * This also makes them thread-safe.
 * 
 * Almost all operations that can be performed on IPAddress objects can also be performed on IPAddressSection objects and vice-versa.
 * 
 */
public abstract class IPAddressSection extends IPAddressDivisionGrouping implements IPAddressSegmentSeries, AddressSection {
	
	private static final long serialVersionUID = 4L;
	private static final IPAddressStringDivisionSeries EMPTY_PARTS[] = new IPAddressStringDivisionSeries[0];
	
	/* caches objects to avoid recomputing them */
	protected static class PrefixCache {
		/* for caching */
		private Integer networkMaskPrefixLen; //null indicates this field not initialized, -1 indicates the prefix len is null
		private Integer hostMaskPrefixLen; //null indicates this field not initialized, -1 indicates the prefix len is null
		
		/* also for caching */
		private Integer cachedMinPrefix; //null indicates this field not initialized
		private Integer cachedEquivalentPrefix; //null indicates this field not initialized, -1 indicates the prefix len is null
		private Boolean cachedIsSinglePrefixBlock; //null indicates this field not initialized
	}
	
	private transient PrefixCache prefixCache;
	private transient BigInteger cachedNonzeroHostCount;
	
	protected IPAddressSection(IPAddressSegment segments[], boolean cloneSegments, boolean checkSegs) {
		super(cloneSegments ? segments.clone() : segments, checkSegs);
		if(checkSegs) {//the segment array is populated, so we need to check the prefixes within to get the prefix length
			//we also must check the network does not change across segments
			IPAddressNetwork<?, ?, ?, ?, ?> network = getNetwork();
			Integer previousSegmentPrefix = null;
			int bitsPerSegment = getBitsPerSegment();
			for(int i = 0; i < segments.length; i++) {
				IPAddressSegment segment = segments[i];
				if(!network.isCompatible(segment.getNetwork())) {
					throw new NetworkMismatchException(segment);
				}
				/**
				 * Across an address prefixes are:
				 * IPv6: (null):...:(null):(1 to 16):(0):...:(0)
				 * or IPv4: ...(null).(1 to 8).(0)...
				 */
				Integer segPrefix = segment.getSegmentPrefixLength();
				if(previousSegmentPrefix == null) {
					if(segPrefix != null) {
						cachedPrefixLength = cacheBits(getNetworkPrefixLength(bitsPerSegment, segPrefix, i));
					}
				} else if(segPrefix == null || segPrefix != 0) {
					throw new InconsistentPrefixException(segments[i - 1], segment, segPrefix);
				}
				previousSegmentPrefix = segPrefix;
			}
			if(previousSegmentPrefix == null) {
				cachedPrefixLength = NO_PREFIX_LENGTH;
			}
		}
	}
	
	protected void checkSegments(IPv6AddressSegment segs[]) {
		IPAddressNetwork<?, ?, ?, ?, ?> network = getNetwork();
		for(IPAddressSegment seg : segs) {
			if(!network.isCompatible(seg.getNetwork())) {
				throw new NetworkMismatchException(seg);
			}
		}
	}

	protected static String getMessage(String key) {
		return HostIdentifierException.getMessage(key);
	}
	
	protected void initCachedValues(
			Integer prefixLen,
			boolean network,
			Integer cachedNetworkPrefix,
			Integer cachedMinPrefix,
			Integer cachedEquivalentPrefix,
			BigInteger cachedCount,
			RangeList zeroSegments,
			RangeList zeroRanges) {
		if(prefixCache == null) {
			prefixCache = new PrefixCache();
		}
		if(network) {
			setNetworkMaskPrefix(prefixLen);
		} else {
			setHostMaskPrefix(prefixLen);
		}
		super.initCachedValues(cachedNetworkPrefix, cachedCount);
		prefixCache.cachedMinPrefix = cachedMinPrefix;
		prefixCache.cachedIsSinglePrefixBlock = Objects.equals(cachedEquivalentPrefix, cachedNetworkPrefix);
		prefixCache.cachedEquivalentPrefix = cachedEquivalentPrefix;
	}
	
	@Override
	public boolean isSinglePrefixBlock() {
		if(!hasNoPrefixCache() && prefixCache.cachedIsSinglePrefixBlock != null) {
			return prefixCache.cachedIsSinglePrefixBlock;
		}
		boolean result = super.isSinglePrefixBlock();
		prefixCache.cachedIsSinglePrefixBlock = result;
		if(result) {
			prefixCache.cachedEquivalentPrefix = getNetworkPrefixLength();
		}
		return result;
	}
	
	protected static RangeList getNoZerosRange() {
		return IPAddressDivisionGrouping.getNoZerosRange();
	}
	
	protected static RangeList getSingleRange(int index, int len) {
		return IPAddressDivisionGrouping.getSingleRange(index, len);
	}
	
	protected static boolean isCompatibleNetworks(AddressNetwork<?> one, AddressNetwork<?> two) {
		return AddressDivisionGrouping.isCompatibleNetworks(one, two);
	}

	@Override
	public int getBitCount() {
		return getSegmentCount() * getBitsPerSegment();
	}

	@Override
	public int getByteCount() {
		return getSegmentCount() * getBytesPerSegment();
	}

	public static int bitsPerSegment(IPVersion version) {
		return IPAddressSegment.getBitCount(version);
	}

	public static int bytesPerSegment(IPVersion version) {
		return IPAddressSegment.getBitCount(version);
	}

	protected long longCount(int segCount) {
		if(isMultiple()) {
			return longCount(this, segCount);
		}
		return 1L;
	}

	protected long longPrefixCount(int prefixLength) {
		if(isMultiple()) {
			return longPrefixCount(this, prefixLength);
		}
		return 1;
	}

	protected long longZeroHostCount(int prefixLength, int segCount) {
		if(includesZeroHost(prefixLength)) {
			if(isMultiple()) {
				int bitsPerSegment = getBitsPerSegment();
				int prefixedSegment = getNetworkSegmentIndex(prefixLength, getBytesPerSegment(), bitsPerSegment);
				long zeroHostCount = getLongCount(i -> {
					if(i == prefixedSegment) {
						IPAddressSegment seg = getSegment(i);
						int shift = seg.getBitCount() - getPrefixedSegmentPrefixLength(bitsPerSegment, prefixLength, i);
						int count = ((seg.getUpperSegmentValue() >>> shift) - (seg.getSegmentValue() >>> shift)) + 1;
						return count;
					}
					return getSegment(i).getValueCount();
				}, prefixedSegment + 1);
				return zeroHostCount;
			} else {
				return 1L;
			}
		}
		return 0L;
	}

	protected abstract BigInteger getZeroHostCountImpl(int prefixLength, int segCount);

	@Override
	public BigInteger getNonZeroHostCount() {
		if(isPrefixed() && getNetworkPrefixLength() < getBitCount()) {
			BigInteger cached = cachedNonzeroHostCount;
			if(cached == null) {
				cachedNonzeroHostCount = cached = getCount().subtract(getZeroHostCountImpl(getNetworkPrefixLength(), getSegmentCount()));
			}
			return cached;
		}
		return getCount();
	}

	protected abstract BigInteger getCountImpl(int segCount);

	@Override
	public BigInteger getCountImpl() {
		return getCountImpl(getSegmentCount());
	}

	@Override
	public BigInteger getBlockCount(int segmentCount) {
		if(segmentCount < 0) {
			throw new IllegalArgumentException();
		}
		int segCount = getSegmentCount();
		if(segmentCount > segCount) {
			segmentCount = segCount;
		}
		return getCountImpl(segmentCount);
	}

	public boolean isIPv4() {
		return false;
	}
	
	public boolean isIPv6() {
		return false;
	}
	
	@Override
	public int getMaxSegmentValue() {
		return IPAddressSegment.getMaxSegmentValue(getIPVersion());
	}

	/*
	 * Starting from the first host bit according to the prefix, if the section is a sequence of zeros in both low and high values, 
	 * followed by a sequence where low values are zero and high values are 1, then the section is a subnet prefix.
	 * 
	 * Note that this includes sections where hosts are all zeros, or sections where hosts are full range of values, 
	 * so the sequence of zeros can be empty and the sequence of where low values are zero and high values are 1 can be empty as well.
	 * However, if they are both empty, then this returns false, there must be at least one bit in the sequence.
	 */
	//For explicit prefix config this always returns false.  For all prefix subnets config this always returns true if the prefix length does not extend beyond the address end
	protected static boolean isPrefixSubnet(IPAddressSegment sectionSegments[], Integer networkPrefixLength, IPAddressNetwork<?, ?, ?, ?, ?> network, boolean fullRangeOnly) {
		int segmentCount = sectionSegments.length;
		if(segmentCount == 0) {
			return false;
		}
		IPAddressSegment seg = sectionSegments[0];
		return ParsedAddressGrouping.isPrefixSubnet(
				segmentIndex -> sectionSegments[segmentIndex].getSegmentValue(),
				segmentIndex -> sectionSegments[segmentIndex].getUpperSegmentValue(),
				segmentCount,
				seg.getByteCount(),
				seg.getBitCount(),
				seg.getMaxSegmentValue(),
				networkPrefixLength,
				network.getPrefixConfiguration(),
				fullRangeOnly);
	}
	
	//this method is basically checking whether we can return "this" for getNetworkSection
	protected boolean isNetworkSection(int networkPrefixLength, boolean withPrefixLength) {
		int segmentCount = getSegmentCount();
		if(segmentCount == 0) {
			return true;
		}
		int bitsPerSegment = getBitsPerSegment();
		int prefixedSegmentIndex = getNetworkSegmentIndex(networkPrefixLength, getBytesPerSegment(), bitsPerSegment);
		if(prefixedSegmentIndex + 1 < segmentCount) {
			return false; //not the right number of segments
		}
		//the segment count matches, now compare the prefixed segment
		int segPrefLength = getPrefixedSegmentPrefixLength(bitsPerSegment, networkPrefixLength, prefixedSegmentIndex);// prefixedSegmentIndex of -1 already handled
		return !getSegment(segmentCount - 1).isNetworkChangedByPrefix(cacheBits(segPrefLength), withPrefixLength);
	}
	
	protected boolean isHostSection(int networkPrefixLength) {
		int segmentCount = getSegmentCount();
		if(segmentCount == 0) {
			return true;
		}
		if(networkPrefixLength >= getBitsPerSegment()) {
			return false;
		}
		return !getSegment(0).isHostChangedByPrefix(cacheBits(networkPrefixLength));
	}
	
	protected static int getNetworkSegmentIndex(int networkPrefixLength, int bytesPerSegment, int bitsPerSegment) {
		return ParsedAddressGrouping.getNetworkSegmentIndex(networkPrefixLength, bytesPerSegment, bitsPerSegment);
	}
	
	protected static int getHostSegmentIndex(int networkPrefixLength, int bytesPerSegment, int bitsPerSegment) {
		return ParsedAddressGrouping.getHostSegmentIndex(networkPrefixLength, bytesPerSegment, bitsPerSegment);
	}
	
	private Integer checkForPrefixMask(boolean network) {
		int count = getSegmentCount();
		if(count == 0) {
			return null;
		}
		int front, back;
		int maxval = getSegment(0).getMaxSegmentValue();
		if(network) {
			front = maxval;
			back = 0;
		} else {
			back = maxval;
			front = 0;
		}
		int prefixLen = 0;
		for(int i=0; i < count; i++) {
			IPAddressSegment seg = getSegment(i);
			int value = seg.getSegmentValue();
			if(value != front) {
				Integer segmentPrefixLen = seg.getBlockMaskPrefixLength(network);
				if(segmentPrefixLen == null) {
					return null;
				}
				prefixLen += segmentPrefixLen;
				for(i++; i < count; i++) {
					value = getSegment(i).getSegmentValue();
					if(value != back) {
						return null;
					}
				}
			} else {
				prefixLen += seg.getBitCount();
			}
		}
		//note that when segments.length == 0, we return 0 as well, since both the host mask and prefix mask are empty (length of 0 bits)
		return cacheBits(prefixLen);
	}
	
	/**
	 * If this address section is equivalent to the mask for a CIDR prefix block, it returns that prefix length.
	 * Otherwise, it returns null.
	 * A CIDR network mask is an address with all 1s in the network section and then all 0s in the host section.
	 * A CIDR host mask is an address with all 0s in the network section and then all 1s in the host section.
	 * The prefix length is the length of the network section.
	 * 
	 * Also, keep in mind that the prefix length returned by this method is not equivalent to the prefix length used to construct this object.
	 * The prefix length used to construct indicates the network and host section of this address.  
	 * The prefix length returned here indicates the whether the value of this address can be used as a mask for the network and host
	 * section of any other address.  Therefore the two values can be different values, or one can be null while the other is not.
	 * 
	 * This method applies only to the lower value of the range if this section represents multiple values.
	 * 
	 * @param network whether to check for a network mask or a host mask
	 * @return the prefix length corresponding to this mask, or null if there is no such prefix length
	 */
	public Integer getBlockMaskPrefixLength(boolean network) {
		Integer prefixLen;
		if(network) {
			if(hasNoPrefixCache() || (prefixLen = prefixCache.networkMaskPrefixLen) == null) {
				prefixLen = setNetworkMaskPrefix(checkForPrefixMask(network));
			}
		} else {
			if(hasNoPrefixCache() || (prefixLen = prefixCache.hostMaskPrefixLen) == null) {
				prefixLen = setHostMaskPrefix(checkForPrefixMask(network));
			}
		}
		if(prefixLen < 0) {
			return null;
		}
		return prefixLen;
	}
	
	private Integer setHostMaskPrefix(Integer prefixLen) {
		if(prefixLen == null) {
			prefixLen = prefixCache.hostMaskPrefixLen = NO_PREFIX_LENGTH;
		} else {
			prefixCache.hostMaskPrefixLen = prefixLen;
			prefixCache.networkMaskPrefixLen = NO_PREFIX_LENGTH; //cannot be both network and host mask
		}
		return prefixLen;
	}
	
	private Integer setNetworkMaskPrefix(Integer prefixLen) {
		if(prefixLen == null) {
			prefixLen = prefixCache.networkMaskPrefixLen = NO_PREFIX_LENGTH;
		} else {
			prefixCache.networkMaskPrefixLen = prefixLen;
			prefixCache.hostMaskPrefixLen = NO_PREFIX_LENGTH; //cannot be both network and host mask
		}
		return prefixLen;
	}

	protected static <T extends IPAddress, R extends IPAddressSection, S extends IPAddressSegment>
			R getNetworkSection(
					R original,
					int networkPrefixLength,
					boolean withPrefixLength,
					IPAddressCreator<T, R, ?, S, ?> creator,
					SegFunction<Integer, S> segProducer) {
		if(networkPrefixLength < 0 || networkPrefixLength > original.getBitCount()) {
			throw new PrefixLenException(original, networkPrefixLength);
		}
		if(original.isNetworkSection(networkPrefixLength, withPrefixLength)) {
			return original;
		}
		int bitsPerSegment = original.getBitsPerSegment();
		int networkSegmentCount = original.getNetworkSegmentCount(networkPrefixLength);
		S result[] = creator.createSegmentArray(networkSegmentCount);
		for(int i = 0; i < networkSegmentCount; i++) {
			Integer prefix = getSegmentPrefixLength(bitsPerSegment, cacheBits(networkPrefixLength), i);
			result[i] = segProducer.apply(prefix, i);
		}
		return creator.createSectionInternal(result);
	}

	protected int getNetworkSegmentCount(int networkPrefixLength) {
		return getNetworkSegmentIndex(networkPrefixLength, getBytesPerSegment(), getBitsPerSegment()) + 1;
	}
	
	protected static <T extends IPAddress, R extends IPAddressSection, S extends IPAddressSegment> 
			R getHostSection(
					R original,
					int networkPrefixLength,
					int hostSegmentCount,
					IPAddressCreator<T, R, ?, S, ?> creator,
					SegFunction<Integer, S> segProducer) {
		if(networkPrefixLength < 0 || networkPrefixLength > original.getBitCount()) {
			throw new PrefixLenException(original, networkPrefixLength);
		}
		if(original.isHostSection(networkPrefixLength)) {
			return original;
		}
		int segmentCount = original.getSegmentCount();
		S result[] = creator.createSegmentArray(hostSegmentCount);
		if(hostSegmentCount > 0) {
			int bitsPerSegment = original.getBitsPerSegment();
			for(int i = hostSegmentCount - 1, j = segmentCount - 1; i >= 0; i--, j--) {
				Integer prefix = getPrefixedSegmentPrefixLength(bitsPerSegment, networkPrefixLength, j);
				result[i] = segProducer.apply(prefix, j);
			}
		}
		return creator.createSectionInternal(result);
	}
	
	protected int getHostSegmentCount(int networkPrefixLength) {
		return getSegmentCount() - getHostSegmentIndex(networkPrefixLength, getBytesPerSegment(), getBitsPerSegment());
	}
	
	protected static Integer cacheBits(int i) {
		return AddressDivisionGrouping.cacheBits(i);
	}

	@FunctionalInterface
	public interface SegFunction<R, S> {
	    S apply(R addrItem, int value);
	}
	
	protected static <R extends IPAddressSection, S extends IPAddressSegment> R setPrefixLength(
			R original,
			IPAddressCreator<?, R, ?, S, ?> creator,
			int networkPrefixLength,
			boolean withZeros,
			boolean noShrink,
			boolean singleOnly,
			SegFunction<R, S> segProducer) throws IncompatibleAddressException {
		Integer existingPrefixLength = original.getNetworkPrefixLength();
		if(existingPrefixLength != null) {
			if(networkPrefixLength == existingPrefixLength.intValue()) {
				return original;
			} else if(noShrink && networkPrefixLength > existingPrefixLength.intValue()) {
				checkSubnet(original, networkPrefixLength);
				return original;
			}
		}
		checkSubnet(original, networkPrefixLength);
		IPAddressNetwork<?, R, ?, S, ?> network = creator.getNetwork();
		int maskBits;
		IntUnaryOperator segmentMaskProducer = null;
		if(network.getPrefixConfiguration().allPrefixedAddressesAreSubnets()) {
			if(existingPrefixLength != null) {
				if(networkPrefixLength > existingPrefixLength.intValue()) {
					if(withZeros) {
						maskBits = existingPrefixLength;
					} else {
						maskBits = networkPrefixLength;
					}
				} else { // networkPrefixLength < existingPrefixLength.intValue()
					maskBits = networkPrefixLength;
				} 
			} else {
				maskBits = networkPrefixLength;
			}
		} else {
			if(existingPrefixLength != null) {
				if(withZeros) {
					R leftMask, rightMask;
					if(networkPrefixLength > existingPrefixLength.intValue()) {
						leftMask = network.getNetworkMaskSection(existingPrefixLength);
						rightMask = network.getHostMaskSection(networkPrefixLength);
					} else {
						leftMask = network.getNetworkMaskSection(networkPrefixLength);
						rightMask = network.getHostMaskSection(existingPrefixLength);
					}
					segmentMaskProducer = i -> {
						int val1 = segProducer.apply(leftMask, i).getSegmentValue();
						int val2 = segProducer.apply(rightMask, i).getSegmentValue();
						return val1 | val2;
					};
				}
			}
			maskBits = original.getBitCount();
		}
		if(segmentMaskProducer == null) {
			R mask = network.getNetworkMaskSection(maskBits);
			segmentMaskProducer = i -> segProducer.apply(mask, i).getSegmentValue();
		}
		return getSubnetSegments(
				original,
				cacheBits(networkPrefixLength),
				creator,
				true,
				i -> segProducer.apply(original, i),
				segmentMaskProducer,
				singleOnly);
	}
	
	protected static <R extends IPAddressSection, S extends IPAddressSegment> R getSubnetSegments(
			R original,
			Integer networkPrefixLength,
			IPAddressCreator<?, R, ?, S, ?> creator,
			boolean verifyMask,
			IntFunction<S> segProducer,
			IntUnaryOperator segmentMaskProducer,
			boolean singleOnly) {
		if(networkPrefixLength != null && (networkPrefixLength < 0 || networkPrefixLength > original.getBitCount())) {
			throw new PrefixLenException(original, networkPrefixLength);
		}
		int bitsPerSegment = original.getBitsPerSegment();
		int count = original.getSegmentCount();
		boolean isAllSubnets = original.getNetwork().getPrefixConfiguration().allPrefixedAddressesAreSubnets() && !singleOnly;
		for(int i = 0; i < count; i++) {
			Integer segmentPrefixLength = getSegmentPrefixLength(bitsPerSegment, networkPrefixLength, i);
			S seg = segProducer.apply(i);
			//note that the mask can represent a range (for example a CIDR mask), 
			//but we use the lowest value (maskSegment.value) in the range when masking (ie we discard the range)
			int maskValue = segmentMaskProducer.applyAsInt(i);
			
			int value = seg.getSegmentValue(), upperValue = seg.getUpperSegmentValue();
			if(verifyMask) {
				if(isAllSubnets && segmentPrefixLength != null) {
					int hostMask = seg.getSegmentHostMask(segmentPrefixLength);
					maskValue |= hostMask;
				}
				Masker masker = IPAddressSegment.maskRange(value, upperValue, maskValue, seg.getMaxValue());
				if(!masker.isSequential()) {
					throw new IncompatibleAddressException(seg, "ipaddress.error.maskMismatch");
				}
				value = (int) masker.getMaskedLower(value, maskValue);
				upperValue = (int) masker.getMaskedUpper(upperValue, maskValue);
			} else {
				value &= maskValue;
				upperValue &= maskValue;
			}
			
			if(seg.isChangedBy(value, upperValue, segmentPrefixLength)) {
				S newSegments[] = creator.createSegmentArray(original.getSegmentCount());
				original.getSegments(0, i, newSegments, 0);
				newSegments[i] = creator.createSegment(value, upperValue, segmentPrefixLength);
				if(isAllSubnets && segmentPrefixLength != null) {
					if(++i < count) {
						S zeroSeg = creator.createSegment(0, cacheBits(0));
						Arrays.fill(newSegments, i, count, zeroSeg);
					}
				} else for(i++; i < count; i++) {
					segmentPrefixLength = getSegmentPrefixLength(bitsPerSegment, networkPrefixLength, i);
					seg  = segProducer.apply(i);
					maskValue = segmentMaskProducer.applyAsInt(i);
					value = seg.getSegmentValue();
					upperValue = seg.getUpperSegmentValue();
					if(verifyMask) {
						if(isAllSubnets && segmentPrefixLength != null) {
							int hostMask = seg.getSegmentHostMask(segmentPrefixLength);
							maskValue |= hostMask;
						}
						Masker masker = IPAddressSegment.maskRange(value, upperValue, maskValue, seg.getMaxValue());
						if(!masker.isSequential()) {
							throw new IncompatibleAddressException(seg, "ipaddress.error.maskMismatch");
						}
						value = (int) masker.getMaskedLower(value, maskValue);
						upperValue = (int) masker.getMaskedUpper(upperValue, maskValue);
					} else {
						value &= maskValue;
						upperValue &= maskValue;
					}
					if(seg.isChangedBy(value, upperValue, segmentPrefixLength)) {
						newSegments[i] = creator.createSegment(value, upperValue, segmentPrefixLength);
					} else {
						newSegments[i] = seg;
					}
					if(isAllSubnets && segmentPrefixLength != null) {
						if(++i < count) {
							S zeroSeg = creator.createSegment(0, cacheBits(0));
							Arrays.fill(newSegments, i, count, zeroSeg);
						}
						break;
					}
				}
				return creator.createPrefixedSectionInternal(newSegments, networkPrefixLength, singleOnly);
			}
		}
		return original;
	}
	
	protected static <R extends IPAddressSection, S extends IPAddressSegment> R getOredSegments(
			R original,
			Integer networkPrefixLength,
			IPAddressCreator<?, R, ?, S, ?> creator,
			boolean verifyMask,
			IntFunction<S> segProducer,
			IntUnaryOperator segmentMaskProducer) {
		if(networkPrefixLength != null && (networkPrefixLength < 0 || networkPrefixLength > original.getBitCount())) {
			throw new PrefixLenException(original, networkPrefixLength);
		}
		int bitsPerSegment = original.getBitsPerSegment();
		int count = original.getSegmentCount();
		boolean isAllSubnets = original.getNetwork().getPrefixConfiguration().allPrefixedAddressesAreSubnets();
		for(int i = 0; i < count; i++) {
			Integer segmentPrefixLength = getSegmentPrefixLength(bitsPerSegment, networkPrefixLength, i);
			S seg = segProducer.apply(i);
			int maskValue = segmentMaskProducer.applyAsInt(i);
			int value = seg.getSegmentValue(), upperValue = seg.getUpperSegmentValue();
			if(verifyMask) {
				if(isAllSubnets && segmentPrefixLength != null) {
					int networkMask = seg.getSegmentNetworkMask(segmentPrefixLength);
					maskValue &= networkMask;
				}
				BitwiseOrer masker = IPAddressSegment.bitwiseOrRange(value, upperValue, maskValue, seg.getMaxValue());
				if(!masker.isSequential()) {
					throw new IncompatibleAddressException(seg, "ipaddress.error.maskMismatch");
				}
				value = (int) masker.getOredLower(value, maskValue);
				upperValue = (int) masker.getOredUpper(upperValue, maskValue);
			} else {
				value |= maskValue;
				upperValue |= maskValue;
			}
			if(seg.isChangedBy(value, upperValue, segmentPrefixLength)) {
				S newSegments[] = creator.createSegmentArray(original.getSegmentCount());
				original.getSegments(0, i, newSegments, 0);
				newSegments[i] = creator.createSegment(value, upperValue, segmentPrefixLength);
				if(isAllSubnets && segmentPrefixLength != null) {
					if(++i < count) {
						S zeroSeg = creator.createSegment(0, cacheBits(0));
						Arrays.fill(newSegments, i, count, zeroSeg);
					}
				} else for(i++; i < count; i++) {
					segmentPrefixLength = getSegmentPrefixLength(bitsPerSegment, networkPrefixLength, i);
					seg  = segProducer.apply(i);
					maskValue = segmentMaskProducer.applyAsInt(i);
					value = seg.getSegmentValue();
					upperValue = seg.getUpperSegmentValue();
					if(verifyMask) {
						if(isAllSubnets && segmentPrefixLength != null) {
							int networkMask = seg.getSegmentNetworkMask(segmentPrefixLength);
							maskValue &= networkMask;
						}
						BitwiseOrer masker = IPAddressSegment.bitwiseOrRange(value, upperValue, maskValue, seg.getMaxValue());
						if(!masker.isSequential()) {
							throw new IncompatibleAddressException(seg, "ipaddress.error.maskMismatch");
						}
						value = (int) masker.getOredLower(value, maskValue);
						upperValue = (int) masker.getOredUpper(upperValue, maskValue);
					} else {
						value |= maskValue;
						upperValue |= maskValue;
					}
					if(seg.isChangedBy(value, upperValue, segmentPrefixLength)) {
						newSegments[i] = creator.createSegment(value, upperValue, segmentPrefixLength);
					} else {
						newSegments[i] = seg;
					}
					if(isAllSubnets && segmentPrefixLength != null) {
						if(++i < count) {
							S zeroSeg = creator.createSegment(0, cacheBits(0));
							Arrays.fill(newSegments, i, count, zeroSeg);
						}
						break;
					}
				}
				return creator.createPrefixedSectionInternal(newSegments, networkPrefixLength);
			}
		}
		return original;
	}

	protected static Integer getSegmentPrefixLength(int bitsPerSegment, Integer prefixLength, int segmentIndex) {
		return AddressDivisionGrouping.getSegmentPrefixLength(bitsPerSegment, prefixLength, segmentIndex);
	}

	protected static Integer getSegmentPrefixLength(int bitsPerSegment, int segmentPrefixedBits) {
		return AddressDivisionGrouping.getSegmentPrefixLength(bitsPerSegment, segmentPrefixedBits);
	}

	protected static <R extends IPAddressSection, S extends IPAddressSegment> R getLowestOrHighestSection(
			R section,
			IPAddressCreator<?, R, ?, S, ?> creator,
			Supplier<Iterator<S[]>> nonZeroHostIteratorSupplier,
			IntFunction<S> segProducer,
			boolean lowest,
			boolean excludeZeroHost) {
		boolean create = true;
		R result = null;
		S[] segs = null;
		if(lowest && excludeZeroHost && section.includesZeroHost()) {
			Iterator<S[]> it = nonZeroHostIteratorSupplier.get();
			if(!it.hasNext()) {
				create = false;
			} else {
				segs = it.next();
			}
		} else {
			segs = createSingle(section, creator, segProducer);
		}
		if(create) {
			Integer prefLength;
			result = section.getNetwork().getPrefixConfiguration().allPrefixedAddressesAreSubnets() || (prefLength = section.getNetworkPrefixLength()) == null ? 
				creator.createSectionInternal(segs) :
				creator.createPrefixedSectionInternal(segs, prefLength, true);
		}
		return result;
	}

	@Override
	public int getSegmentCount() {
		return getDivisionCount();
	}

	@Override
	public IPAddressSegment getSegment(int index) {
		return getSegmentsInternal()[index];
	}

	@Override
	public IPAddressSegment getDivision(int index) {
		return getSegmentsInternal()[index];
	}

	@Override
	public boolean containsPrefixBlock(int prefixLength) {
		checkSubnet(this, prefixLength);
		boolean isAllSubnets = getNetwork().getPrefixConfiguration().allPrefixedAddressesAreSubnets();
		if(isAllSubnets && isPrefixed() && getNetworkPrefixLength() <= prefixLength) {
			return true;
		}
		int divCount = getDivisionCount();
		int bitsPerSegment = getBitsPerSegment();
		int i = getHostSegmentIndex(prefixLength, getBytesPerSegment(), bitsPerSegment);
		if(i < divCount) {
			IPAddressSegment div = getDivision(i);
			int segmentPrefixLength = getPrefixedSegmentPrefixLength(bitsPerSegment, prefixLength, i);
			if(!div.containsPrefixBlock(segmentPrefixLength)) {
				return false;
			}
			if(isAllSubnets && div.isPrefixed()) {
				return true;
			}
			for(++i; i < divCount; i++) {
				div = getDivision(i);
				if(!div.isFullRange()) {
					return false;
				}
				if(isAllSubnets && div.isPrefixed()) {
					return true;
				}
			}
		}
		return true;
	}

	static boolean containsPrefixBlock(int prefixLength, IPAddressSegmentSeries lower, IPAddressSegmentSeries upper) {
		checkSubnet(lower, prefixLength);
		int divCount = lower.getDivisionCount();
		int bitsPerSegment = lower.getBitsPerSegment();
		int i = getHostSegmentIndex(prefixLength, lower.getBytesPerSegment(), bitsPerSegment);
		if(i < divCount) {
			IPAddressSegment div = lower.getSegment(i);
			IPAddressSegment upperDiv = upper.getSegment(i);
			int segmentPrefixLength = getPrefixedSegmentPrefixLength(bitsPerSegment, prefixLength, i);
			if(!div.containsPrefixBlock(div.getSegmentValue(), upperDiv.getSegmentValue(), segmentPrefixLength)) {
				return false;
			}
			for(++i; i < divCount; i++) {
				div = lower.getSegment(i);
				upperDiv = upper.getSegment(i);
				//is full range?
				if(!div.includesZero() || !upperDiv.includesMax()) {
					return false;
				}
			}
		}
		return true;
	}
	
	static boolean containsSinglePrefixBlock(int prefixLength, IPAddressSegmentSeries lower, IPAddressSegmentSeries upper) {
		checkSubnet(lower, prefixLength);
		int prevBitCount = 0;
		int divCount = lower.getDivisionCount();
		for(int i = 0; i < divCount; i++) {
			IPAddressSegment div = lower.getSegment(i);
			IPAddressSegment upperDiv = upper.getSegment(i);
			int bitCount = div.getBitCount();
			int totalBitCount = bitCount + prevBitCount;
			if(prefixLength >= totalBitCount) {
				if(!div.isSameValues(upperDiv)) {
					return false;
				}
			} else  {
				int divPrefixLen = Math.max(0, prefixLength - prevBitCount);
				if(!div.containsSinglePrefixBlock(div.getSegmentValue(), upperDiv.getSegmentValue(), divPrefixLen)) {
					return false;
				}
				for(++i; i < divCount; i++) {
					div = lower.getSegment(i);
					upperDiv = upper.getSegment(i);
					if(!div.includesZero() || !upperDiv.includesMax()) {
						return false;
					}
				}
				return true;
			}
			prevBitCount = totalBitCount;
		}
		return true;
	}

	/**
	 * @param other
	 * @return whether this subnet contains the given address section
	 */
	@Override
	public boolean contains(AddressSection other) {
		//check if they are comparable first
		int count = getSegmentCount();
		if(count != other.getSegmentCount()) {
			return false;
		}
		boolean prefixIsSubnet = isPrefixed() && getNetwork().getPrefixConfiguration().allPrefixedAddressesAreSubnets();
		int endIndex = prefixIsSubnet ? 
				getNetworkSegmentIndex(getNetworkPrefixLength(), getBytesPerSegment(), getBitsPerSegment()) :
					count - 1;
		for(int i = endIndex; i >= 0; i--) {
			IPAddressSegment seg = getSegment(i);
			if(!seg.contains(other.getSegment(i))) {
				return false;
			}
		}
		return true;
	}
	
	/**
	 * Returns whether this address contains the non-zero host addresses in other.
	 * @param other
	 * @return
	 */
	public boolean containsNonZeroHosts(IPAddressSection other) {
		if(!other.isPrefixed()) {
			return contains(other);
		}
		int otherPrefixLength = other.getNetworkPrefixLength();
		if(otherPrefixLength  == other.getBitCount()) {
			return contains(other);
		}
		return containsNonZeroHostsImpl(other, otherPrefixLength);
	}
	
	protected abstract boolean containsNonZeroHostsImpl(IPAddressSection other, int otherPrefixLength);

	/**
	 * Returns whether the prefix of this address contains all values of the same bits in the given address or subnet
	 * 
	 * @param other
	 * @return
	 */
	public abstract boolean prefixContains(IPAddressSection other);

	@Override
	public boolean isFullRange() {
		int divCount = getDivisionCount();
		if(getNetwork().getPrefixConfiguration().allPrefixedAddressesAreSubnets()) {
			for(int i = 0; i < divCount; i++) {
				IPAddressSegment div = getSegment(i);
				if(!div.isFullRange()) {
					return false;
				}
				Integer prefix = div.getSegmentPrefixLength();
				if(prefix != null) {
					//any segment that follows is full range
					break;
				}
			}
		} else return super.isFullRange();
		return true;
	}
	
	protected static <T extends IPAddress, R extends IPAddressSection, S extends IPAddressSegment> R intersect(
			R first,
			R other,
			IPAddressCreator<T, R, ?, S, ?> addrCreator,
			IntFunction<S> segProducer,
			IntFunction<S> otherSegProducer) {
		//check if they are comparable first.  We only check segment count, we do not care about start index.
		first.checkSectionCount(other);
		
		//larger prefix length should prevail?    hmmmmm... I would say that is true, choose the larger prefix
		Integer pref = first.getNetworkPrefixLength();
		Integer otherPref = other.getNetworkPrefixLength();
		if(pref != null) {
			if(otherPref != null) {
				if(otherPref > pref) {
					pref = otherPref;
				}
			} else {
				pref = null;
			}
		}
				
		if(other.contains(first)) {
			if(Objects.equals(pref, first.getNetworkPrefixLength())) {
				return first;
			}
		} else if(!first.isMultiple()) {
			return null;
		}
		if(first.contains(other)) {
			if(Objects.equals(pref, other.getNetworkPrefixLength())) {
				return other;
			}
		} else if(!other.isMultiple()) {
			return null;
		}
		
		int segCount = first.getSegmentCount();
		for(int i = 0; i < segCount; i++) {
			IPAddressSegment seg = first.getSegment(i);
			IPAddressSegment otherSeg = other.getSegment(i);
			int lower = seg.getSegmentValue();
			int higher = seg.getUpperSegmentValue();
			int otherLower = otherSeg.getSegmentValue();
			int otherHigher = otherSeg.getUpperSegmentValue();
			if(otherLower > higher || lower > otherHigher) {
				//no overlap in this segment means no overlap at all
				return null;
			}
		}
		
		S segs[] = addrCreator.createSegmentArray(segCount);
		for(int i = 0; i < segCount; i++) {
			S seg = segProducer.apply(i);
			S otherSeg = otherSegProducer.apply(i);
			Integer segPref = getSegmentPrefixLength(seg.getBitCount(), pref, i);
			if(seg.contains(otherSeg)) {
				if(!otherSeg.isChangedByPrefix(segPref, false)) {
					segs[i] = otherSeg;
					continue;
				}
			}
			if(otherSeg.contains(seg)) {
				if(!seg.isChangedByPrefix(segPref, false)) {
					segs[i] = seg;
					continue;
				}
			}
			int lower = seg.getSegmentValue();
			int higher = seg.getUpperSegmentValue();
			int otherLower = otherSeg.getSegmentValue();
			int otherHigher = otherSeg.getUpperSegmentValue();
			int newLower = Math.max(lower, otherLower);
			int newHigher = Math.min(higher, otherHigher);
			segs[i] = addrCreator.createSegment(newLower, newHigher, segPref);
		}
		R result = addrCreator.createSection(segs);
		return result;
	}

	@FunctionalInterface
	public interface TriFunction<R, S> {
	    S apply(R addrItem, R addrItem2, R addrItem3);
	}
	
	static <R extends IPAddressSegmentSeries, OperatorResult> OperatorResult applyOperatorToLowerUpper(
			R first,
			R other,
			UnaryOperator<R> getLower,
			UnaryOperator<R> getUpper,
			Comparator<R> comparator,
			Function<R, R> prefixRemover,
			TriFunction<R, OperatorResult> operatorFunctor) {
		R lower, upper;
		boolean isFirst, isOther;
		isFirst = isOther = true;
		if(first.equals(other)) {
			if(prefixRemover != null && first.isPrefixed()) {
				if(other.isPrefixed()) {
					lower = prefixRemover.apply(first);
					isOther = isFirst = false;
				} else {
					lower = other;
					isFirst = false;
				}
			} else {
				isOther = false;
				lower = first;
			}
			upper = getUpper.apply(lower);
			lower = getLower.apply(lower);
		} else {
			R firstLower = getLower.apply(first);
			R otherLower = getLower.apply(other);
			R firstUpper = getUpper.apply(first);
			R otherUpper = getUpper.apply(other);
			if(comparator.compare(firstLower, otherLower) > 0) {
				lower = otherLower;
				isFirst = false;
			} else {
				lower = firstLower;
				isOther = false;
			}
			if(comparator.compare(firstUpper, otherUpper) < 0) {
				upper = otherUpper;
				isFirst = false;
			} else {
				upper = firstUpper;
				isOther = false;
			}
			if(prefixRemover != null) {
				lower = prefixRemover.apply(lower);
				upper = prefixRemover.apply(upper);
			}
		}
		return operatorFunctor.apply(isFirst ? first : (isOther ? other : null), lower, upper);
	}

	@SuppressWarnings("unchecked")
	protected static <T extends IPAddressSegmentSeries> T coverWithPrefixBlock(
			T first,
			T other,
			UnaryOperator<T> getLower,
			UnaryOperator<T> getUpper,
			Comparator<T> comparator) throws AddressConversionException {
		return (T)
				IPAddressSection.applyOperatorToLowerUpper(first, other, getLower, getUpper, comparator, null, 
						IPAddressSection::coverWithPrefixBlock);
	}

	protected static IPAddressSegmentSeries coverWithPrefixBlock(
			IPAddressSegmentSeries original,
			IPAddressSegmentSeries lower,
			IPAddressSegmentSeries upper) {
		int segCount = lower.getSegmentCount();
		int bitsPerSegment = lower.getBitsPerSegment();
		int currentSegment = 0, previousSegmentBits = 0;
		for(; currentSegment < segCount; currentSegment++) {
			IPAddressSegment lowerSeg = lower.getSegment(currentSegment);
			IPAddressSegment upperSeg = upper.getSegment(currentSegment);
			int lowerValue = lowerSeg.getSegmentValue();//these are single addresses, so lower or upper value no different here
			int upperValue = upperSeg.getSegmentValue();
			int differing = lowerValue ^ upperValue;
			if(differing != 0) {
				int highestDifferingBitInRange = Integer.numberOfLeadingZeros(differing) - (Integer.SIZE - bitsPerSegment);
				int differingBitPrefixLen = highestDifferingBitInRange + previousSegmentBits;
				return (original != null ? original : lower).toPrefixBlock(differingBitPrefixLen);
			}
			previousSegmentBits += bitsPerSegment;
		}
		//all bits match, it's just a single address
		return (original != null ? original : lower).toPrefixBlock(lower.getBitCount());
	}

	private static <R extends IPAddressSection> R[] checkSequentialBlockContainment(
			R first,
			R other,
			UnaryOperator<R> prefixRemover,
			IntFunction<R[]> arrayProducer) {
		if(first.contains(other)) {
			return IPAddress.checkSequentialBlockFormat(first, other, true, prefixRemover, arrayProducer);
		} else if(other.contains(first)) {
			return IPAddress.checkSequentialBlockFormat(other, first, false, prefixRemover, arrayProducer);
		}
		return null;
	}

	private static <R extends IPAddressSection> R[] checkPrefixBlockContainment(
			R first,
			R other,
			UnaryOperator<R> prefixAdder,
			IntFunction<R[]> arrayProducer) {
		if(first.contains(other)) {
			return IPAddress.checkPrefixBlockFormat(first, other, true, prefixAdder, arrayProducer);
		} else if(other.contains(first)) {
			return IPAddress.checkPrefixBlockFormat(other, first, false, prefixAdder, arrayProducer);
		}
		return null;
	}

	/**
	 * Returns the smallest set of prefix blocks that spans both this and the supplied address or subnet.
	 * @param other
	 * @return
	 */
	protected static <R extends IPAddressSection> R[] getSpanningPrefixBlocks(
			R first,
			R other,
			UnaryOperator<R> getLower,
			UnaryOperator<R> getUpper,
			Comparator<R> comparator,
			UnaryOperator<R> prefixAdder,
			UnaryOperator<R> prefixRemover,
			IntFunction<R[]> arrayProducer) {
		first.checkSectionCount(other);
		R[] result = checkPrefixBlockContainment(first, other, prefixAdder, arrayProducer);
		if(result != null) {
			return result;
		}
		List<IPAddressSegmentSeries> blocks = applyOperatorToLowerUpper(first, other, getLower, getUpper, comparator, prefixRemover, (orig, lower, upper) -> IPAddressSection.splitIntoPrefixBlocks(lower, upper));
		result = blocks.toArray(arrayProducer.apply(blocks.size()));
		return result;
	}
	
	protected static <R extends IPAddressSection, S extends IPAddressSegment> SeriesCreator createSeriesCreator(IPAddressCreator<?, R, ?, S, ?> creator, int maxSegmentValue) {
		S allRangeSegment = creator.createSegment(0, maxSegmentValue, null);
		SeriesCreator seriesCreator = (series, index, lowerVal, upperVal) -> {
			S segments[] = creator.createSegmentArray(series.getSegmentCount());
			series.getSegments(0, index, segments, 0);
			segments[index] = creator.createSegment(lowerVal, upperVal, null);
			while(++index < segments.length) {
				segments[index] = allRangeSegment;
			}
			return creator.createSectionInternal(segments);
		};
		return seriesCreator;
	}
	
	protected static <R extends IPAddressSection, S extends IPAddressSegment> R[] getSpanningSequentialBlocks(
			R first,
			R other,
			UnaryOperator<R> getLower,
			UnaryOperator<R> getUpper,
			Comparator<R> comparator,
			UnaryOperator<R> prefixRemover,
			IPAddressCreator<?, R, ?, S, ?> creator) {
		R[] result = checkSequentialBlockContainment(first, other, prefixRemover, creator::createSectionArray);
		if(result != null) {
			return result;
		}
		SeriesCreator seriesCreator = createSeriesCreator(creator, first.getMaxSegmentValue());
		TriFunction<R, List<IPAddressSegmentSeries>> operatorFunctor = (orig, one, two) -> IPAddressSection.splitIntoSequentialBlocks(one, two, seriesCreator);
		List<IPAddressSegmentSeries> blocks = applyOperatorToLowerUpper(first, other, getLower, getUpper, comparator, prefixRemover, operatorFunctor);
		return blocks.toArray(creator.createSectionArray(blocks.size()));
	}
	
	@FunctionalInterface
	public interface SeriesCreator {
		IPAddressSegmentSeries apply(IPAddressSegmentSeries segmentSeries, int index, int lowerVal, int upperVal);
	}
	
	static List<IPAddressSegmentSeries> splitIntoSequentialBlocks(
			IPAddressSegmentSeries lower,
			IPAddressSegmentSeries upper,
			SeriesCreator seriesCreator) {
		ArrayList<IPAddressSegmentSeries> blocks = new ArrayList<>(IPv6Address.SEGMENT_COUNT);
		int segCount = lower.getSegmentCount();
		if(segCount == 0) {
			//all segments match, it's just a single address
			blocks.add(lower);
			return blocks;
		}
		int previousSegmentBits = 0, currentSegment = 0;
		int bitsPerSegment = lower.getBitsPerSegment();
		int segSegment;
		int lowerValue, upperValue;
		SeriesStack stack = null;
		Deque<IPAddressSegmentSeries> toAdd = null;
		while(true) {
			do {
				segSegment = currentSegment;
				IPAddressSegment lowerSeg = lower.getSegment(currentSegment);
				IPAddressSegment upperSeg = upper.getSegment(currentSegment++);
				lowerValue = lowerSeg.getSegmentValue();//these are single addresses, so lower or upper value no different here
				upperValue = upperSeg.getSegmentValue();
				previousSegmentBits += bitsPerSegment;
			} while(lowerValue == upperValue && currentSegment < segCount);
			
			if(lowerValue == upperValue) {
				blocks.add(lower);
			} else {	
				boolean lowerIsLowest = lower.includesZeroHost(previousSegmentBits);
				boolean higherIsHighest = upper.includesMaxHost(previousSegmentBits);
				if(lowerIsLowest) {
					if(higherIsHighest) {
						// full range
						IPAddressSegmentSeries series = seriesCreator.apply(lower, segSegment, lowerValue, upperValue);
						blocks.add(series);
					} else {
						IPAddressSegmentSeries topLower = upper.toZeroHost(previousSegmentBits);
						IPAddressSegmentSeries middleUpper = topLower.increment(-1);
						IPAddressSegmentSeries series = seriesCreator.apply(lower, segSegment, lowerValue, middleUpper.getSegment(segSegment).getSegmentValue());
						blocks.add(series);
						lower = topLower;
						continue;
					}
				} else if(higherIsHighest) {
					IPAddressSegmentSeries bottomUpper = lower.toMaxHost(previousSegmentBits);
					IPAddressSegmentSeries topLower = bottomUpper.increment(1);
					IPAddressSegmentSeries series = seriesCreator.apply(topLower, segSegment, topLower.getSegment(segSegment).getSegmentValue(), upperValue);
					if(toAdd == null) {
						toAdd = new ArrayDeque<>(IPv6Address.SEGMENT_COUNT);
					}
					toAdd.addFirst(series);
					upper = bottomUpper;
					continue;
				} else {	//lower 2:3:ffff:5:: to upper 2:4:1:5::      2:3:ffff:5:: to 2:3:ffff:ffff:ffff:ffff:ffff:ffff and 2:4:: to 2:3:ffff:ffff:ffff:ffff:ffff:ffff and 2:4:: to 2:4:1:5::
					//from top to bottom we have: top - topLower - middleUpper - middleLower - bottomUpper - lower
					IPAddressSegmentSeries topLower = upper.toZeroHost(previousSegmentBits);//2:4::
					IPAddressSegmentSeries middleUpper = topLower.increment(-1);//2:3:ffff:ffff:ffff:ffff:ffff:ffff
					IPAddressSegmentSeries bottomUpper = lower.toMaxHost(previousSegmentBits);//2:3:ffff:ffff:ffff:ffff:ffff:ffff
					IPAddressSegmentSeries middleLower = bottomUpper.increment(1);//2:4::
					if(middleLower.compareTo(middleUpper) <= 0) {
						IPAddressSegmentSeries series = seriesCreator.apply(middleLower, segSegment, middleLower.getSegment(segSegment).getSegmentValue(), middleUpper.getSegment(segSegment).getSegmentValue());
						if(toAdd == null) {
							toAdd = new ArrayDeque<>(IPv6Address.SEGMENT_COUNT);
						}
						toAdd.addFirst(series);
					}
					if(stack == null) {
						stack = new SeriesStack(IPv6Address.SEGMENT_COUNT);
					}
					stack.push(topLower, upper, previousSegmentBits, currentSegment); // do this one later
					upper = bottomUpper;
					continue;
				}
			}
			if(toAdd != null) {
				while(true) {
					IPAddressSegmentSeries saved = toAdd.pollFirst();
					if(saved == null) {
						break;
					}
					blocks.add(saved);
				}
			}
			if(stack == null || !stack.pop()) {
				return blocks;
			}
			lower = stack.lower;
			upper = stack.upper;
			previousSegmentBits = stack.previousSegmentBits;
			currentSegment = stack.currentSegment;
		}
	}
	
	static class SeriesStack {
		int stackSize;
		int top; // top of stack
		int capacity;
		
		IPAddressSegmentSeries seriesPairs[]; // stack items
		int indexPairs[]; // stack items
		
		IPAddressSegmentSeries lower, upper; // last popped items
		int previousSegmentBits, currentSegment; // last popped items
		
		SeriesStack(int initialCapacity) {
			this.capacity = 2 * initialCapacity;
		}
		
		void push(IPAddressSegmentSeries lower, IPAddressSegmentSeries upper, int previousSegmentBits, int currentSegment) {
			int top = this.top;
			if(top >= stackSize) {
				resize();
			}
			IPAddressSegmentSeries seriesPairs[] = this.seriesPairs;
			int indexPairs[] = this.indexPairs;
			seriesPairs[top] = lower;
			indexPairs[top++] = previousSegmentBits;
			seriesPairs[top] = upper;
			indexPairs[top++] = currentSegment;
			this.top = top;
		}
		
		boolean pop() {
			if(top <= 0) {
				return false;
			}
			IPAddressSegmentSeries seriesPairs[] = this.seriesPairs;
			int indexPairs[] = this.indexPairs;
			int top = this.top;
			currentSegment = indexPairs[--top];
			upper = seriesPairs[top];
			previousSegmentBits = indexPairs[--top];
			lower = seriesPairs[top];
			this.top = top;
			return true;
		}
		
		void resize() {
			int size = stackSize;
			if(size == 0) {
				// splits are limited by bit count, and each recursion here pushes a pair onto each stack
				size = capacity;
			} else {
				size <<= 1; // double the stack size
			}
			IPAddressSegmentSeries newSeriesPairs[] = new IPAddressSegmentSeries[size];
			int newIndexPairs[] = new int[size];
			if(top > 0) {
				System.arraycopy(seriesPairs, 0, newSeriesPairs, 0, top);
				System.arraycopy(indexPairs, 0, newIndexPairs, 0, top);
			}
			seriesPairs = newSeriesPairs;
			indexPairs = newIndexPairs;
			stackSize = size;
		}
	}
	
	static List<IPAddressSegmentSeries> splitIntoPrefixBlocks(
			IPAddressSegmentSeries lower,
			IPAddressSegmentSeries upper) {
		ArrayList<IPAddressSegmentSeries> blocks = new ArrayList<>();
		int previousSegmentBits = 0, currentSegment = 0;
		SeriesStack stack = null;
		
		while(true) {
			//Find first non-matching bit.  
			int differing = 0;
			int segCount = lower.getSegmentCount();
			int bitsPerSegment = lower.getBitsPerSegment();
			for(; currentSegment < segCount; currentSegment++) {
				IPAddressSegment lowerSeg = lower.getSegment(currentSegment);
				IPAddressSegment upperSeg = upper.getSegment(currentSegment);
				int lowerValue = lowerSeg.getSegmentValue();//these are single addresses, so lower or upper value no different here
				int upperValue = upperSeg.getSegmentValue();
				differing = lowerValue ^ upperValue;
				if(differing != 0) {
					break;
				}
				previousSegmentBits += bitsPerSegment;
			}
			if(differing == 0) {
				//all bits match, it's just a single address
				blocks.add(lower.toPrefixBlock(lower.getBitCount()));
			} else {
				boolean differingIsLowestBit = (differing == 1);
				if(differingIsLowestBit && currentSegment + 1 == segCount) {
					//only the very last bit differs, so we have a prefix block right there
					blocks.add(lower.toPrefixBlock(lower.getBitCount() - 1));
				} else {
					int highestDifferingBitInRange = Integer.numberOfLeadingZeros(differing) - (Integer.SIZE - bitsPerSegment);
					int differingBitPrefixLen = highestDifferingBitInRange + previousSegmentBits;
					if(lower.includesZeroHost(differingBitPrefixLen) && upper.includesMaxHost(differingBitPrefixLen)) {
						//full range at the differing bit, we have a single prefix block
						blocks.add(lower.toPrefixBlock(differingBitPrefixLen));
					} else {
						//neither a prefix block nor a single address
						//we split into two new ranges to continue  
						//starting from the differing bit,
						//lower top becomes 1000000...
						//upper bottom becomes 01111111...
						//so in each new range, the differing bit is at least one further to the right (or more)
						IPAddressSegmentSeries lowerTop = upper.toZeroHost(differingBitPrefixLen + 1);
						IPAddressSegmentSeries upperBottom = lowerTop.increment(-1);
						if(differingIsLowestBit) {
							previousSegmentBits += bitsPerSegment;
							currentSegment++;
						}
						if(stack == null) {
							stack = new SeriesStack(IPv6Address.BIT_COUNT);
						}
						stack.push(lowerTop, upper, previousSegmentBits, currentSegment); // do upper one later
						upper = upperBottom; // do lower one now
						continue;
					}
				}
			}
			if(stack == null || !stack.pop()) {
				return blocks;
			}
			lower = stack.lower;
			upper = stack.upper;
			previousSegmentBits = stack.previousSegmentBits;
			currentSegment = stack.currentSegment;
		}
	}
	
	//sort by prefix length, smallest blocks coming first
	//so this means null prefixes come first, then largest prefix length to smallest
	static final Comparator<? super IPAddressSegmentSeries> mergeListComparator = (one, two) ->  {
		Integer prefix1 = one.getPrefixLength();
		Integer prefix2 = two.getPrefixLength();
		int comparison = (prefix1 == prefix2) ? 0 : ((prefix1 == null) ? -1 : ((prefix2 == null) ? 1 : prefix2.compareTo(prefix1)));
		if(comparison != 0) {
			return comparison;
		}
		if(prefix1 == null || prefix1 != 0) {// this does not actually need to handle prefix len 0, but we handle anyway
			int networkSegIndex = (prefix1 == null) ? one.getSegmentCount() - 1 : getNetworkSegmentIndex(prefix1, one.getBytesPerSegment(), one.getBitsPerSegment());
			int hostSegIndex = (prefix1 == null) ? one.getSegmentCount() : getHostSegmentIndex(prefix1, one.getBytesPerSegment(), one.getBitsPerSegment());
			for(int i = 0; i < hostSegIndex; i++) {
				AddressSegment segOne = one.getSegment(i);
				AddressSegment segTwo = two.getSegment(i);
				int oneValue = segOne.getSegmentValue();
				int twoValue = segTwo.getSegmentValue();
				int oneUpperValue = segOne.getUpperSegmentValue();
				int twoUpperValue = segTwo.getUpperSegmentValue();
				comparison = (oneUpperValue - oneValue) - (twoUpperValue - twoValue);
				if(comparison != 0) {
					return comparison;
				}
			}
			for(int i = 0; i <= networkSegIndex; i++) {
				AddressSegment segOne = one.getSegment(i);
				AddressSegment segTwo = two.getSegment(i);
				int oneValue = segOne.getSegmentValue();
				int twoValue = segTwo.getSegmentValue();
				comparison = oneValue - twoValue;
				if(comparison != 0) {
					return comparison;
				}
			}
		}
		return comparison;
	};
	
	private static boolean organizeByMinPrefix(
			IPAddressSegmentSeries first,
			IPAddressSegmentSeries sections[],
			List<IPAddressSegmentSeries> list,
			boolean useBitCountPrefixLengths,
			Comparator<? super IPAddressSegmentSeries> listOrdering,
			Function<IPAddressSegmentSeries, Iterator<? extends IPAddressSegmentSeries>> blockIteratorFunc) {
		int bitCount = first.getBitCount();
		IPAddressSegmentSeries block = first.assignMinPrefixForBlock();
		int prefLength = block.getPrefixLength();
		if(useBitCountPrefixLengths || prefLength < bitCount) {
			first = block;
			if(prefLength == 0) {
				list.add(first);
			}
		}
		if(bitCount == 0 && list.isEmpty()) {
			list.add(first);
		}
		if(!list.isEmpty()) {
			return true;
		}
		for(int i = 0; i < sections.length; i++) {
			IPAddressSegmentSeries section = sections[i];
			if(section == null) {
				continue;
			}
			block = section.assignMinPrefixForBlock();
			prefLength = block.getPrefixLength();
			if(useBitCountPrefixLengths || prefLength < bitCount) {
				sections[i] = block;
				if(prefLength == 0 && list.isEmpty()) {
					list.add(block);
				}
			}
		}
		if(!list.isEmpty()) {
			return true;
		}
		Iterator<? extends IPAddressSegmentSeries> iterator = blockIteratorFunc.apply(first);
		iterator.forEachRemaining(list::add);
		for(int i = 0; i < sections.length; i++) {
			IPAddressSegmentSeries section = sections[i];
			if(section == null) {
				continue;
			}
			iterator = blockIteratorFunc.apply(section);
			iterator.forEachRemaining(list::add);
		}
		if(list.size() == 1) {
			return true;
		}
		list.sort(listOrdering);
		return false;
	}

	protected static List<IPAddressSegmentSeries> getMergedSequentialBlocks(
			IPAddressSegmentSeries first, IPAddressSegmentSeries sections[], SeriesCreator seriesCreator) {
		ArrayList<IPAddressSegmentSeries> list = new ArrayList<>();
		int bitsPerSegment = first.getBitsPerSegment();
		int bytesPerSegment = first.getBytesPerSegment();
		int segmentCount = first.getSegmentCount();
		
		// iterator must get the segment to iterate on based on prefix Length
		// it is the segment preceding the prefix length, the segment preceding the first non-full-range
		// you get that segment index, then you get the iterator for that segment index
		boolean singleElement = organizeByMinPrefix(first, sections, list, false, Address.ADDRESS_LOW_VALUE_COMPARATOR, series -> {
			Integer prefixLength = series.getPrefixLength();
			int segs = (prefixLength == null) ? series.getSegmentCount() - 1 : 
				getNetworkSegmentIndex(prefixLength, bytesPerSegment, bitsPerSegment);
			return series.blockIterator(segs);
		});
		if(singleElement) {
			list.set(0, list.get(0).withoutPrefixLength());
			return list;
		}
		ValueComparator reverseLowComparator = REVERSE_LOW_COMPARATOR;
		ValueComparator reverseHighComparator = REVERSE_HIGH_COMPARATOR;
		
		int removedCount = 0;
		int j = list.size() - 1, i = j - 1;
		top:
		while(j > 0) {
			IPAddressSegmentSeries item = list.get(i);
			IPAddressSegmentSeries otherItem = list.get(j);
			int compare = reverseHighComparator.compare(item, otherItem);
			// check for strict containment, case 1:
			// w   z
			//  x y
			if(compare > 0) {
				removedCount++;
				int k = j + 1;
				while(k < list.size() && list.get(k) == null) {
					k++;
				}
				if(k < list.size()) {
					list.set(j, list.get(k));
					list.set(k, null);
				} else {
					list.set(j, null);
					j = i;
					i--;
				}
				continue;
			}
			// non-strict containment, case 2:
			// w   z
			// w   z
			//
			// reverse containment, case 3:
			// w  y
			// w   z
			int rcompare = reverseLowComparator.compare(item, otherItem);
			if(rcompare >= 0) {
				removedCount++;
				list.set(i, otherItem);
				list.set(j, null);
				j = i;
				i--;
				continue;
			}

			//check for overlap
			
			Integer prefixLen = item.getPrefixLength();
			int rangeSegmentIndex = (prefixLen == null) ? segmentCount - 1 : 
				getNetworkSegmentIndex(prefixLen, bytesPerSegment, bitsPerSegment);
			
			Integer otherPrefixLen = otherItem.getPrefixLength();
			int otherRangeSegmentIndex = (otherPrefixLen == null) ? segmentCount - 1 : 
				getNetworkSegmentIndex(otherPrefixLen, bytesPerSegment, bitsPerSegment);
			
			// check for overlap in the non-full range segment,
			// which must be the same segment in both, otherwise it cannot be overlap,
			// it can only be containment.
			// The one with the earlier range segment can only contain the other, there cannot be overlap.
			// eg 1.a-b.*.* and 1.2.3.* must have a < 2 < b and that means 1.a-b.*.* contains 1.2.3.*)
			if(rangeSegmentIndex != otherRangeSegmentIndex) {
				j = i;
				i--;
				continue;
			}
			
			IPAddressSegment rangeSegment = item.getSegment(rangeSegmentIndex);
			IPAddressSegment otherRangeSegment = otherItem.getSegment(rangeSegmentIndex);
			int otherRangeItemValue = otherRangeSegment.getSegmentValue();
			int rangeItemUpperValue = rangeSegment.getUpperSegmentValue();
			
			//check for overlapping range in the range segment
			if(rangeItemUpperValue < otherRangeItemValue && rangeItemUpperValue + 1 != otherRangeItemValue) {
				j = i;
				i--;
				continue;
			}
			
			// now check all previous segments match
			for(int k = rangeSegmentIndex - 1; k >= 0; k--) {
				IPAddressSegment itemSegment = item.getSegment(k);
				IPAddressSegment otherItemSegment = otherItem.getSegment(k);
				int val = itemSegment.getSegmentValue();
				int otherVal = otherItemSegment.getSegmentValue();
				if(val != otherVal) {
					j = i;
					i--;
					continue top;
				}
			}
			IPAddressSegmentSeries joinedItem = seriesCreator.apply(
					item,
					rangeSegmentIndex,
					rangeSegment.getSegmentValue(),
					Math.max(rangeItemUpperValue, otherRangeSegment.getUpperSegmentValue()));
			joinedItem = joinedItem.assignMinPrefixForBlock();
			
			list.set(i, joinedItem);
			removedCount++;
			int k = j + 1;
			while(k < list.size() && list.get(k) == null) {
				k++;
			}
			if(k < list.size()) {
				list.set(j, list.get(k));
				list.set(k, null);
			} else {
				list.set(j, null);
				j = i;
				i--;
			}
		}
		if(removedCount > 0) {
			int newSize = list.size() - removedCount;
			for(int k = 0, l = 0; k < newSize; k++, l++) {
				while(list.get(l) == null) {
					l++;
				}
				list.set(k, list.get(l).withoutPrefixLength());
			}
			int last = list.size();
			while(removedCount-- > 0) {
				list.remove(--last);
			}
		} else for(int n = 0; n < list.size(); n++) {
			list.set(n, list.get(n).withoutPrefixLength());
		}
		return list;
	}
	
	private static final ValueComparator REVERSE_LOW_COMPARATOR = new ValueComparator(true, false, true);
	private static final ValueComparator REVERSE_HIGH_COMPARATOR = new ValueComparator(true, true, true);
	
	protected static List<IPAddressSegmentSeries> getMergedPrefixBlocks(IPAddressSegmentSeries first, IPAddressSegmentSeries sections[], boolean checkSize) {
		ArrayList<IPAddressSegmentSeries> list = new ArrayList<>(sections.length + 1);
		boolean singleElement = organizeByMinPrefix(first, sections, list, true, Address.ADDRESS_LOW_VALUE_COMPARATOR, IPAddressSegmentSeries::prefixBlockIterator);
		if(singleElement) {
			return list;
		}
		ValueComparator reverseLowComparator = REVERSE_LOW_COMPARATOR;
		ValueComparator reverseHighComparator = REVERSE_HIGH_COMPARATOR;
		int bitCount = first.getBitCount();
		int bitsPerSegment = first.getBitsPerSegment();
		int bytesPerSegment = first.getBytesPerSegment();

		//Now we see if we can match blocks or join them into larger blocks
		int removedCount = 0;
		int j = list.size() - 1, i = j - 1;
		top:
		while(j > 0) {
			IPAddressSegmentSeries item = list.get(i);
			IPAddressSegmentSeries otherItem = list.get(j);
			int compare = reverseHighComparator.compare(item, otherItem);
			// check for strict containment, case 1:
			// w   z
			//  x y
			if(compare > 0) {
				removedCount++;
				int k = j + 1;
				while(k < list.size() && list.get(k) == null) {
					k++;
				}
				if(k < list.size()) {
					list.set(j, list.get(k));
					list.set(k, null);
				} else {
					list.set(j, null);
					j = i;
					i--;
				}
				continue;
			}
			// non-strict containment, case 2:
			// w   z
			// w   z
			//
			// reverse containment, case 3:
			// w  y
			// w   z
			int rcompare = reverseLowComparator.compare(item, otherItem);
			if(rcompare >= 0) {
				removedCount++;
				list.set(i, otherItem);
				list.set(j, null);
				j = i;
				i--;
				continue;
			}
			// check for merge, case 4:
			// w   x
			//      y   z
			// where x and y adjacent, becoming:
			// w        z
			//
			Integer prefixLen = item.getPrefixLength();
			Integer otherPrefixLen = otherItem.getPrefixLength();
			if(!Objects.equals(prefixLen, otherPrefixLen)) {
				j = i;
				i--;
				continue;
			}
			int matchBitIndex = (prefixLen == null) ? bitCount - 1 : prefixLen - 1;
			int lastMatchSegmentIndex, lastBitSegmentIndex;
			if(matchBitIndex == 0) {
				lastMatchSegmentIndex = lastBitSegmentIndex = 0;
			} else {
				lastMatchSegmentIndex = getNetworkSegmentIndex(matchBitIndex, bytesPerSegment, bitsPerSegment);
				lastBitSegmentIndex = getHostSegmentIndex(matchBitIndex, bytesPerSegment, bitsPerSegment);
			}
			IPAddressSegment itemSegment = item.getSegment(lastMatchSegmentIndex);
			IPAddressSegment otherItemSegment = otherItem.getSegment(lastMatchSegmentIndex);
			int itemSegmentValue = itemSegment.getSegmentValue();
			int otherItemSegmentValue = otherItemSegment.getSegmentValue();
			int segmentLastBitIndex = bitsPerSegment - 1;
			if(lastBitSegmentIndex == lastMatchSegmentIndex) {
				int segmentBitToCheck = matchBitIndex % bitsPerSegment;
				int shift = segmentLastBitIndex - segmentBitToCheck;
				itemSegmentValue >>>= shift;
				otherItemSegmentValue >>>= shift;
			} else {
				int itemBitValue = item.getSegment(lastBitSegmentIndex).getSegmentValue();
				int otherItemBitalue = otherItem.getSegment(lastBitSegmentIndex).getSegmentValue();

				//we will make space for the last bit so we can do a single comparison
				itemSegmentValue = (itemSegmentValue << 1) | (itemBitValue >>> segmentLastBitIndex);
				otherItemSegmentValue = (otherItemSegmentValue << 1) | (otherItemBitalue >>> segmentLastBitIndex);
			}
			if(itemSegmentValue != otherItemSegmentValue) {
				itemSegmentValue ^= 1;//the ^ 1 flips the first bit
				if(itemSegmentValue != otherItemSegmentValue) {
					//neither an exact match nor a match when flipping the bit, so move on
					j = i;
					i--;
					continue;
				} //else we will merge these two into a single prefix block, presuming the initial segments match
			}
			//check initial segments
			for(int k = lastMatchSegmentIndex - 1; k >= 0; k--) {
				itemSegment = item.getSegment(k);
				otherItemSegment = otherItem.getSegment(k);
				int val = itemSegment.getSegmentValue();
				int otherVal = otherItemSegment.getSegmentValue();
				if(val != otherVal) {
					j = i;
					i--;
					continue top;
				}
			}
			IPAddressSegmentSeries joinedItem = otherItem.toPrefixBlock(matchBitIndex);
			list.set(i, joinedItem);
			removedCount++;
			int k = j + 1;
			while(k < list.size() && list.get(k) == null) {
				k++;
			}
			if(k < list.size()) {
				list.set(j, list.get(k));
				list.set(k, null);
			} else {
				list.set(j, null);
				j = i;
				i--;
			}
		}
		if(removedCount > 0) {
			int newSize = list.size() - removedCount;
			for(int k = 0, l = 0; k < newSize; k++, l++) {
				while(list.get(l) == null) {
					l++;
				}
				if(k != l) {
					list.set(k, list.get(l));
				}
			}
			int last = list.size();
			while(removedCount-- > 0) {
				list.remove(--last);
			}
		}
		return list;
	}

	protected static <T extends IPAddress, R extends IPAddressSection, S extends IPAddressSegment> R[] subtract(
			R first,
			R other,
			IPAddressCreator<T, R, ?, S, ?> addrCreator,
			IntFunction<S> segProducer,
			SegFunction<R, R> prefixApplier) {
		//check if they are comparable first
		first.checkSectionCount(other);
		if(!first.isMultiple()) {
			if(other.contains(first)) {
				return null;
			}
			R result[] = addrCreator.createSectionArray(1);
			result[0] = first;
			return result;
		}
		//getDifference: same as removing the intersection
		//   first you confirm there is an intersection in each segment.  
		// Then you remove each intersection, one at a time, leaving the other segments the same, since only one segment needs to differ.
		// To prevent adding the same section twice, use only the intersection (ie the relative complement of the diff) 
		// of segments already handled and not the whole segment.
		
		// For example: 0-3.0-3.2.4 subtracting 1-4.1-3.2.4, the intersection is 1-3.1-3.2.4
		// The diff of the first segment is just 0, giving 0.0-3.2.4 (subtract the first segment, leave the others the same)
		// The diff of the second segment is also 0, but for the first segment we use the intersection since we handled the first already, giving 1-3.0.2.4
		// 	(take the intersection of the first segment, subtract the second segment, leave remaining segments the same)
		int segCount = first.getSegmentCount();
		for(int i = 0; i < segCount; i++) {
			IPAddressSegment seg = first.getSegment(i);
			IPAddressSegment otherSeg = other.getSegment(i);
			int lower = seg.getSegmentValue();
			int higher = seg.getUpperSegmentValue();
			int otherLower = otherSeg.getSegmentValue();
			int otherHigher = otherSeg.getUpperSegmentValue();
			if(otherLower > higher || lower > otherHigher) {
				//no overlap in this segment means no overlap at all
				R result[] = addrCreator.createSectionArray(1);
				result[0] = first;
				return result;
			}
		}
		
		S intersections[] = addrCreator.createSegmentArray(segCount);
		ArrayList<R> sections = new ArrayList<R>();
		for(int i = 0; i < segCount; i++) {
			S seg = segProducer.apply(i);
			IPAddressSegment otherSeg = other.getSegment(i);
			int lower = seg.getSegmentValue();
			int higher = seg.getUpperSegmentValue();
			int otherLower = otherSeg.getSegmentValue();
			int otherHigher = otherSeg.getUpperSegmentValue();
			if(lower >= otherLower) {
				if(higher <= otherHigher) {
					//this segment is contained in the other
					if(seg.isPrefixed()) {
						intersections[i] = addrCreator.createSegment(lower, higher, null);
					} else {
						intersections[i] = seg;
					}
					continue;
				}
				//otherLower <= lower <= otherHigher < higher
				intersections[i] = addrCreator.createSegment(lower, otherHigher, null);
				R section = createDiffSection(first, otherHigher + 1, higher, i, addrCreator, segProducer, intersections);
				sections.add(section);
			} else {
				//lower < otherLower <= otherHigher
				R section = createDiffSection(first, lower, otherLower - 1, i, addrCreator, segProducer, intersections);
				sections.add(section);
				if(higher <= otherHigher) {
					intersections[i] = addrCreator.createSegment(otherLower, higher, null);
				} else {
					//lower < otherLower <= otherHigher < higher
					intersections[i] = addrCreator.createSegment(otherLower, otherHigher, null);
					section = createDiffSection(first, otherHigher + 1, higher, i, addrCreator, segProducer, intersections);
					sections.add(section);
				}
			}
		}
		if(sections.size() == 0) {
			return null;
		}
		
		//apply the prefix to the sections
		//for each section, we figure out what each prefix length should be
		if(first.isPrefixed()) {
			int thisPrefix = first.getNetworkPrefixLength();
			for(int i = 0; i < sections.size(); i++) {
				R section = sections.get(i);
				int bitCount = section.getBitCount();
				int totalPrefix = bitCount;
				for(int j = first.getSegmentCount() - 1; j >= 0 ; j--) {
					IPAddressSegment seg = section.getSegment(j);
					int segBitCount = seg.getBitCount();
					int segPrefix = seg.getMinPrefixLengthForBlock();
					if(segPrefix == segBitCount) {
						break;
					} else {
						totalPrefix -= segBitCount;
						if(segPrefix != 0) {
							totalPrefix += segPrefix;
							break;
						}
					}
				}
				if(totalPrefix != bitCount) {
					if(totalPrefix < thisPrefix) {
						totalPrefix = thisPrefix;
					}
					section = prefixApplier.apply(section, totalPrefix);
					sections.set(i, section);
				}
			}
		}
		
		R result[] = addrCreator.createSectionArray(sections.size());
		sections.toArray(result);
		return result;
	}
	
	private static <T extends IPAddress, R extends IPAddressSection, S extends IPAddressSegment> R createDiffSection(
			R original,
			int lower,
			int upper,
			int diffIndex,
			IPAddressCreator<T, R, ?, S, ?> addrCreator,
			IntFunction<S> segProducer,
			S intersectingValues[]) {
		int segCount = original.getSegmentCount();
		S segments[] = addrCreator.createSegmentArray(segCount);
		for(int j = 0; j < diffIndex; j++) {
			segments[j] = intersectingValues[j];
		}
		S diff = addrCreator.createSegment(lower, upper, null);
		segments[diffIndex] = diff;
		for(int j = diffIndex + 1; j < segCount; j++) {
			segments[j] = segProducer.apply(j);
		}
		R section = addrCreator.createSectionInternal(segments);
		return section;
	}

	@Override
	public abstract IPAddressSection toZeroHost();

	@Override
	public abstract IPAddressSection toZeroHost(int prefixLength);
	
	@Override
	public abstract IPAddressSection toZeroNetwork();
	
	@Override
	public abstract IPAddressSection toMaxHost();

	@Override
	public abstract IPAddressSection toMaxHost(int prefixLength);
	
	@Deprecated
	@Override
	public abstract IPAddressSection applyPrefixLength(int networkPrefixLength) throws PrefixLenException;
	
	protected void checkSectionCount(IPAddressSection sec) throws SizeMismatchException {
		if(sec.getSegmentCount() != getSegmentCount()) {
			throw new SizeMismatchException(this, sec);
		}
	}
	
	protected void checkMaskSectionCount(IPAddressSection mask) throws SizeMismatchException {
		if(mask.getSegmentCount() < getSegmentCount()) {
			throw new SizeMismatchException(this, mask);
		}
	}
	
	@Override
	public abstract IPAddressSection coverWithPrefixBlock();
		
	@Override
	public abstract IPAddressSection toPrefixBlock();

	@Override
	public abstract IPAddressSection toPrefixBlock(int networkPrefixLength);

	@Override
	public IPAddressSection getHostMask() {
		Integer prefLen = getNetworkPrefixLength();
		return getNetwork().getHostMask(prefLen == null ? 0 : getNetworkPrefixLength()).getSection(0, getSegmentCount());
	}

	@Override
	public IPAddressSection getNetworkMask() {
		Integer prefLen = getNetworkPrefixLength();
		return getNetwork().getHostMask(prefLen == null ? getBitCount() : getNetworkPrefixLength()).getSection(0, getSegmentCount());
	}

	/**
	 * Returns the equivalent CIDR address section with a prefix length for which the subnet block for that prefix matches the range of values in this section.
	 * <p>
	 * If no such prefix length exists, returns null.
	 * <p>
	 * If this address represents just a single address, "this" is returned.
	 * 
	 * @return
	 */
	@Override
	public IPAddressSection assignPrefixForSingleBlock() {
		if(!isMultiple()) {
			return this;
		}
		Integer newPrefix = getPrefixLengthForSingleBlock();
		if(newPrefix == null) {
			return null;
		}
		IPAddressSection result = setPrefixLength(newPrefix, false);
		result.hasNoPrefixCache();
		result.prefixCache.cachedIsSinglePrefixBlock = true;
		result.prefixCache.cachedEquivalentPrefix = newPrefix;
		return result;
	}
	
	/**
	 * Constructs an equivalent address section with the smallest CIDR prefix possible (largest network),
	 * such that the range of values are a set of subnet blocks for that prefix.
	 * 
	 * @return
	 */
	@Override
	public IPAddressSection assignMinPrefixForBlock() {
		return setPrefixLength(getMinPrefixLengthForBlock(), false);
	}

	@Override
	public boolean includesZeroHost() {
		Integer networkPrefixLength = getNetworkPrefixLength();
		if(networkPrefixLength == null || networkPrefixLength >= getBitCount()) {
			return false;
		}
		return includesZeroHost(networkPrefixLength);
	}
	
	@Override
	public boolean includesZeroHost(int networkPrefixLength) {
		if(networkPrefixLength < 0 || networkPrefixLength > getBitCount()) {
			throw new PrefixLenException(this, networkPrefixLength);
		}
		if(getNetwork().getPrefixConfiguration().allPrefixedAddressesAreSubnets() && isPrefixed() && getNetworkPrefixLength() <= networkPrefixLength) { 
			return true;
		}
		int bitsPerSegment = getBitsPerSegment();
		int bytesPerSegment = getBytesPerSegment();
		int prefixedSegmentIndex = getHostSegmentIndex(networkPrefixLength, bytesPerSegment, bitsPerSegment);
		int divCount = getSegmentCount();
		for(int i = prefixedSegmentIndex; i < divCount; i++) {
			IPAddressSegment div = getSegment(i);
			Integer segmentPrefixLength = getPrefixedSegmentPrefixLength(bitsPerSegment, networkPrefixLength, i);
			if(segmentPrefixLength != null) {
				int mask = div.getSegmentHostMask(segmentPrefixLength);
				if((mask & div.getDivisionValue()) != 0) {
					return false;
				}
				for(++i; i < divCount; i++) {
					div = getSegment(i);
					if(!div.includesZero()) {
						return false;
					}
				}
			}
		}
		return true;
	}

	@Override
	public boolean includesMaxHost() {
		Integer networkPrefixLength = getNetworkPrefixLength();
		if(networkPrefixLength == null || networkPrefixLength >= getBitCount()) {
			return false;
		}
		return includesMaxHost(networkPrefixLength);
	}
	
	@Override
	public boolean includesMaxHost(int networkPrefixLength) {
		if(networkPrefixLength < 0 || networkPrefixLength > getBitCount()) {
			throw new PrefixLenException(this, networkPrefixLength);
		}
		if(getNetwork().getPrefixConfiguration().allPrefixedAddressesAreSubnets() && isPrefixed() && getNetworkPrefixLength() <= networkPrefixLength) { 
			return true;
		}
		int bitsPerSegment = getBitsPerSegment();
		int bytesPerSegment = getBytesPerSegment();
		int prefixedSegmentIndex = getHostSegmentIndex(networkPrefixLength, bytesPerSegment, bitsPerSegment);
		int divCount = getSegmentCount();
		for(int i = prefixedSegmentIndex; i < divCount; i++) {
			IPAddressSegment div = getSegment(i);
			Integer segmentPrefixLength = getPrefixedSegmentPrefixLength(bitsPerSegment, networkPrefixLength, i);
			if(segmentPrefixLength != null) {
				int mask = div.getSegmentHostMask(segmentPrefixLength);
				if((mask & div.getUpperSegmentValue()) != mask) {
					return false;
				}
				for(++i; i < divCount; i++) {
					div = getSegment(i);
					if(!div.includesMax()) {
						return false;
					}
				}
			}
		}
		return true;
	}
	
	/**
	 * 
	 * @return whether the network section of the address, the prefix, consists of a single value
	 */
	public boolean isSingleNetwork() {
		Integer networkPrefixLength = getNetworkPrefixLength();
		if(networkPrefixLength == null || networkPrefixLength >= getBitCount()) {
			return !isMultiple();
		}
		int prefixedSegmentIndex = getNetworkSegmentIndex(networkPrefixLength, getBytesPerSegment(), getBitsPerSegment());
		if(prefixedSegmentIndex < 0) {
			return true;
		}
		for(int i = 0; i < prefixedSegmentIndex; i++) {
			IPAddressSegment div = getSegment(i);
			if(div.isMultiple()) {
				return false;
			}
		}
		IPAddressSegment div = getSegment(prefixedSegmentIndex);
		int differing = div.getSegmentValue() ^ div.getUpperSegmentValue();
		if(differing == 0) {
			return true;
		}
		int bitsPerSegment = div.getBitCount();
		int highestDifferingBitInRange = Integer.numberOfLeadingZeros(differing) - (Integer.SIZE - bitsPerSegment);
		return getSegmentPrefixLength(bitsPerSegment, networkPrefixLength, prefixedSegmentIndex) <= highestDifferingBitInRange;
	}
	
	/**
	 * Applies the mask to this address section and then compares values with the given address section
	 * 
	 * @param mask
	 * @param other
	 * @return
	 */
	public boolean matchesWithMask(IPAddressSection other, IPAddressSection mask) {
		checkMaskSectionCount(mask);
		checkSectionCount(other);
		int divCount = getSegmentCount();
		for(int i = 0; i < divCount; i++) {
			IPAddressSegment div = getSegment(i);
			IPAddressSegment maskSegment = mask.getSegment(i);
			IPAddressSegment otherSegment = other.getSegment(i);
			if(!div.matchesWithMask(
					otherSegment.getSegmentValue(), 
					otherSegment.getUpperSegmentValue(), 
					maskSegment.getSegmentValue())) {
				return false;
			}
		}
		return true;
	}
	
	@Override @Deprecated
	public abstract IPAddressSection removePrefixLength(boolean zeroed);

	@Override @Deprecated
	public abstract IPAddressSection removePrefixLength();
	
	@Override
	public abstract IPAddressSection withoutPrefixLength();
	
	protected static <T extends IPAddress, R extends IPAddressSection, S extends IPAddressSegment>
			R toPrefixBlock(
					R original,
					int networkPrefixLength,
					IPAddressCreator<T, R, ?, S, ?> creator,
					SegFunction<Integer, S> segProducer) {
		if(networkPrefixLength < 0 || networkPrefixLength > original.getBitCount()) {
			throw new PrefixLenException(original, networkPrefixLength);
		}
		if(original.isNetworkSubnet(networkPrefixLength)) {
			return original;
		}
		int bitsPerSegment = original.getBitsPerSegment();
		int segmentCount = original.getSegmentCount();
		S result[] = creator.createSegmentArray(segmentCount);
		for(int i = 0; i < segmentCount; i++) {
			Integer prefix = getPrefixedSegmentPrefixLength(bitsPerSegment, networkPrefixLength, i);
			result[i] = segProducer.apply(prefix, i);
		}
		return creator.createSectionInternal(result);
	}
	
	protected boolean isNetworkSubnet(int networkPrefixLength) {
		int segmentCount = getSegmentCount();
		if(segmentCount == 0) {
			return true;
		}
		int bitsPerSegment = getBitsPerSegment();
		int prefixedSegmentIndex = getHostSegmentIndex(networkPrefixLength, getBytesPerSegment(), bitsPerSegment);
		if(prefixedSegmentIndex >= segmentCount) {
			if(networkPrefixLength == getBitCount()) {
				IPAddressSegment last = getSegment(segmentCount - 1);
				return !last.isNetworkChangedByPrefixNonNull(last.getBitCount());
			}
			return true;
		}
		int segPrefLength = getPrefixedSegmentPrefixLength(bitsPerSegment, networkPrefixLength, prefixedSegmentIndex);
		if(getSegment(prefixedSegmentIndex).isNetworkChangedByPrefixNonNull(segPrefLength)) {
			return false;
		}
		if(!getNetwork().getPrefixConfiguration().allPrefixedAddressesAreSubnets()) {
			for(int i = prefixedSegmentIndex + 1; i < segmentCount; i++) {
				if(!getSegment(i).isFullRange()) {
					return false;
				}
			}
		}
		return true;
	}

	protected static <R extends IPAddressSection, S extends IPAddressSegment> R removePrefixLength(
			R original, boolean zeroed, IPAddressCreator<?, R, ?, S, ?> creator, SegFunction<R, S> segProducer) throws IncompatibleAddressException {
		if(!original.isPrefixed()) {
			return original;
		}
		IPAddressNetwork<?, R, ?, S, ?> network = creator.getNetwork();
		R mask = network.getNetworkMaskSection(zeroed ? original.getPrefixLength() : original.getBitCount());
		return getSubnetSegments(
				original,
				null,
				creator,
				zeroed,
				i -> segProducer.apply(original, i),
				i -> segProducer.apply(mask, i).getSegmentValue(),
				false);
	}

	@Override
	public IPAddressSection adjustPrefixBySegment(boolean nextSegment, boolean zeroed) {
		int prefix = getAdjustedPrefix(nextSegment, getBitsPerSegment(), false);
		Integer existing = getNetworkPrefixLength();
		if(existing == null) {
			if(nextSegment ? prefix == getBitCount() : prefix == 0) {
				return this;
			}
		} else if(existing != null && existing == prefix && prefix != 0) {
			//remove the prefix from the end
			return removePrefixLength(zeroed);
		}
		return setPrefixLength(prefix, zeroed);
	}
	
	@Override
	public abstract IPAddressSection adjustPrefixBySegment(boolean nextSegment);

	@Override
	public abstract IPAddressSection adjustPrefixLength(int adjustment);
	
	@Override
	public abstract IPAddressSection adjustPrefixLength(int adjustment, boolean zeroed);
	
	protected static <R extends IPAddressSection, S extends IPAddressSegment> IPAddressSection adjustPrefixLength(
			R original, int adjustment, boolean withZeros, IPAddressCreator<?, R, ?, S, ?> creator, SegFunction<R, S> segProducer) throws IncompatibleAddressException {
		if(adjustment == 0 && original.isPrefixed()) {
			return original;
		}
		int prefix = original.getAdjustedPrefix(adjustment, false, false);
		if(prefix > original.getBitCount()) {
			if(!original.isPrefixed()) {
				return original;
			}
			IPAddressNetwork<?, R, ?, S, ?> network = creator.getNetwork();
			R mask = network.getNetworkMaskSection(withZeros ? original.getPrefixLength() : original.getBitCount());
			return getSubnetSegments(
					original,
					null,
					creator,
					withZeros,
					i -> segProducer.apply(original, i),
					i -> segProducer.apply(mask, i).getSegmentValue(),
					false);
		}
		if(prefix < 0) {
			prefix = 0;
		}
		return original.setPrefixLength(prefix, withZeros);
	}

	@Override
	public abstract IPAddressSection setPrefixLength(int prefixLength);

	@Override
	public abstract IPAddressSection setPrefixLength(int prefixLength, boolean zeroed);
	
	/**
	 * Sets the prefix length while allowing the caller to control whether bits moved in or out of the prefix become zero, 
	 * and whether a zero host for the new prefix bits can be translated into a prefix block.  
	 * The latter behaviour only applies to the default prefix handling configuration,
	 * PREFIXED_ZERO_HOSTS_ARE_SUBNETS.  The methods  {@link #setPrefixLength(int, boolean)} and {@link #setPrefixLength(int)}
	 * use a value of true for zeroed and for zeroHostIsBlock.
	 * <p>
	 * For example, when zeroHostIsBlock is true, applying to 1.2.0.0 the prefix length 16 results in 1.2.*.*&#x2f;16 
	 * <p>
	 * Or if you start with 1.2.0.0&#x2f;24, setting the prefix length to 16 results in 
	 * a zero host followed by the existing prefix block, which is then converted to a full prefix block, 1.2.*.*&#x2f;16
	 * <p>
	 * When both zeroed and zeroHostIsBlock are true, applying the prefix length of 16 to 1.2.4.0&#x2f;24 also results in 
	 * a zero host followed by the existing prefix block, which is then converted to a full prefix block, 1.2.*.*&#x2f;16.
	 * <p>
	 * When both zeroed and zeroHostIsBlock are false, the resulting address always encompasses the same set of addresses as the original,
	 * albeit with a different prefix length.
	 * 
	 * @param prefixLength
	 * @param zeroed
	 * @param zeroHostIsBlock
	 * @return
	 */
	public abstract IPAddressSection setPrefixLength(int prefixLength, boolean zeroed, boolean zeroHostIsBlock);

	private boolean hasNoPrefixCache() {
		if(prefixCache == null) {
			synchronized(this) {
				if(prefixCache == null) {
					prefixCache = new PrefixCache();
					return true;
				}
			}
		}
		return false;
	}
	
	/**
	 * Returns the smallest CIDR prefix length possible (largest network) for which this includes the block of address sections for that prefix.
	 *
	 * @see inet.ipaddr.format.standard.IPAddressDivision#getBlockMaskPrefixLength(boolean)
	 * 
	 * @return
	 */
	@Override
	public int getMinPrefixLengthForBlock() {
		Integer result;
		if(hasNoPrefixCache() || (result = prefixCache.cachedMinPrefix) == null) {
			prefixCache.cachedMinPrefix = result = cacheBits(super.getMinPrefixLengthForBlock());
		}
		return result;
	}
	
	/**
	 * Returns a prefix length for which the range of this address section matches the block of addresses for that prefix.
	 * <p>
	 * If no such prefix exists, returns null
	 * <p>
	 * If this address section represents a single value, returns the bit length
	 * <p>
	 * @return the prefix length or null
	 */
	@Override
	public Integer getPrefixLengthForSingleBlock() {
		if(!hasNoPrefixCache()) {
			Integer result = prefixCache.cachedEquivalentPrefix;
			if(result != null) {
				if(result < 0) {
					return null;
				}
				return result;
			}
		}
		Integer res = super.getPrefixLengthForSingleBlock();
		if(res == null) {
			prefixCache.cachedEquivalentPrefix = NO_PREFIX_LENGTH;
			prefixCache.cachedIsSinglePrefixBlock = false;
			return null;
		}
		if(isPrefixed() && res.equals(getNetworkPrefixLength())) {
			prefixCache.cachedIsSinglePrefixBlock = true;
		}
		prefixCache.cachedEquivalentPrefix = res;
		return res;
	}

	@Override
	public abstract IPAddressSection getLowerNonZeroHost();
	
	@Override
	public abstract IPAddressSection getLower();
	
	@Override
	public abstract IPAddressSection getUpper();
	
	@Override
	public abstract IPAddressSection reverseSegments();
	
	@Override
	public abstract IPAddressSection reverseBits(boolean perByte);
	
	@Override
	public abstract IPAddressSection reverseBytes();
	
	@Override
	public abstract IPAddressSection reverseBytesPerSegment();

	protected IPAddressSegment[] getSegmentsInternal() {
		return (IPAddressSegment[]) getDivisionsInternal();
	}

	@Override
	public abstract IPAddressSection getSection(int index);

	@Override
	public abstract IPAddressSection getSection(int index, int endIndex);

	@Override
	public void getSegments(AddressSegment segs[]) {
		getSegments(0, getDivisionCount(), segs, 0);
	}
	
	@Override
	public void getSegments(int start, int end, AddressSegment segs[], int destIndex) {
		System.arraycopy(getDivisionsInternal(), start, segs, destIndex, end - start);
	}
	
	protected static <T extends IPAddress, R extends IPAddressSection, S extends IPAddressSegment> R createEmbeddedSection(
			IPAddressCreator<T, R, ?, S, ?> creator, S segs[], IPAddressSection encompassingSection) {
		return creator.createEmbeddedSectionInternal(encompassingSection, segs);
	}
	
	@Override
	public abstract Iterable<? extends IPAddressSection> getIterable();
	
	@Override
	public abstract Iterator<? extends IPAddressSection> nonZeroHostIterator();

	@Override
	public abstract Iterator<? extends IPAddressSection> iterator();
	
	@Override
	public abstract AddressComponentSpliterator<? extends IPAddressSection> spliterator();
	
	@Override
	public abstract Stream<? extends IPAddressSection> stream();

	@Override
	public abstract Iterator<? extends IPAddressSection> prefixIterator();

	@Override
	public abstract AddressComponentSpliterator<? extends IPAddressSection> prefixSpliterator();

	@Override
	public abstract Stream<? extends IPAddressSection> prefixStream();
		
	@Override
	public abstract Iterator<? extends IPAddressSection> prefixBlockIterator();

	@Override
	public abstract AddressComponentSpliterator<? extends IPAddressSection> prefixBlockSpliterator();

	@Override
	public abstract Stream<? extends IPAddressSection> prefixBlockStream();
		
	@Override
	public abstract Iterator<? extends IPAddressSection> blockIterator(int segmentCount);
	
	@Override
	public abstract AddressComponentSpliterator<? extends IPAddressSection> blockSpliterator(int segmentCount);

	@Override
	public abstract Stream<? extends IPAddressSection> blockStream(int segmentCount);
		
	@Override
	public Iterator<? extends IPAddressSection> sequentialBlockIterator() {
		return blockIterator(getSequentialDivisionIndex());
	}

	@Override
	public AddressComponentSpliterator<? extends IPAddressSection> sequentialBlockSpliterator() {
		return blockSpliterator(getSequentialDivisionIndex());
	}

	@Override
	public Stream<? extends IPAddressSection> sequentialBlockStream() {
		return blockStream(getSequentialDivisionIndex());
	}
		
	@Override
	public BigInteger getSequentialBlockCount() {
		int sequentialSegCount = getSequentialDivisionIndex();
		return getPrefixCount(sequentialSegCount * getBitsPerSegment());
	}
	
	@Override
	protected int getSequentialDivisionIndex() {
		return super.getSequentialDivisionIndex();
	}

	// this iterator function used by sequential ranges
	static <S extends AddressSegment> Iterator<S[]> iterator(
			int divCount,
			AddressSegmentCreator<S> segmentCreator,
			IntFunction<Iterator<S>> segIteratorProducer,
			int networkSegmentIndex,
			int hostSegmentIndex,
			IntFunction<Iterator<S>> prefixedSegIteratorProducer) {
		return segmentsIterator(
				divCount, segmentCreator, null, segIteratorProducer, null,
				networkSegmentIndex,
				hostSegmentIndex,
				prefixedSegIteratorProducer);
	}
	
	// this one is used by the sequential ranges
	static <T extends Address, S extends AddressSegment> Iterator<T> iterator(
			T original,
			AddressCreator<T, ?, ?, S> creator,
			Iterator<S[]> iterator) {
		return iterator(original != null, original, creator, iterator, null);
	}
	
	@FunctionalInterface
	static interface SeqRangeIteratorProvider<S, T> extends IteratorProvider<S,T>{}

	static class IPAddressSeqRangeSpliterator<S extends AddressComponentRange, T> extends AddressItemRangeSpliterator<S, T> implements IPAddressSeqRangeSplitterSink<S, T> {
		
		final Predicate<IPAddressSeqRangeSplitterSink<S, T>> splitter;
		
		IPAddressSeqRangeSpliterator(
				S forIteration,
				Predicate<IPAddressSeqRangeSplitterSink<S, T>> splitter,
				SeqRangeIteratorProvider<S, T> iteratorProvider,
				ToLongFunction<S> longSizer) {
			super(forIteration, null, iteratorProvider, null, null, longSizer);
			this.splitter = splitter;
		}
		
		IPAddressSeqRangeSpliterator(
				S forIteration,
				Predicate<IPAddressSeqRangeSplitterSink<S, T>> splitter,
				SeqRangeIteratorProvider<S, T> iteratorProvider,
				Function<S, BigInteger> sizer,
				Predicate<S> downSizer,
				ToLongFunction<S> longSizer) {
			super(forIteration, null, iteratorProvider, sizer, downSizer, longSizer);
			this.splitter = splitter;
		}
		
		IPAddressSeqRangeSpliterator(
				S forIteration,
				Predicate<IPAddressSeqRangeSplitterSink<S, T>> splitter,
				SeqRangeIteratorProvider<S, T> iteratorProvider,
				boolean isLowest,
				Function<S, BigInteger> sizer,
				Predicate<S> downSizer,
				ToLongFunction<S> longSizer) {
			super(forIteration, null, iteratorProvider, isLowest, false, sizer, downSizer, longSizer);
			this.splitter = splitter;
		}
		
		@Override
		protected boolean split() {
			return splitter.test(this);
		}
		
		@Override
		protected IPAddressSeqRangeSpliterator<S, T> createSpliterator(
				S split, 
				boolean isLowest,
				Function<S, BigInteger> sizer,
				Predicate<S> downSizer,
				ToLongFunction<S> longSizer) {
			return new IPAddressSeqRangeSpliterator<S, T>(split, splitter, (SeqRangeIteratorProvider<S, T>) iteratorProvider, isLowest, sizer, downSizer, longSizer);
		}
	}
	
	static class IPAddressSeqRangePrefixSpliterator<S extends AddressComponentRange> 
		extends IPAddressSeqRangeSpliterator<S, S> implements AddressComponentSpliterator<S> {
		
		IPAddressSeqRangePrefixSpliterator(
				S forIteration,
				Predicate<IPAddressSeqRangeSplitterSink<S, S>> splitter,
				SeqRangeIteratorProvider<S, S> iteratorProvider,
				ToLongFunction<S> longSizer) {
			super(forIteration, splitter, iteratorProvider, longSizer);
		}
		
		IPAddressSeqRangePrefixSpliterator(
				S forIteration,
				Predicate<IPAddressSeqRangeSplitterSink<S, S>> splitter,
				SeqRangeIteratorProvider<S, S> iteratorProvider,
				Function<S, BigInteger> sizer,
				Predicate<S> downSizer,
				ToLongFunction<S> longSizer) {
			super(forIteration, splitter, iteratorProvider, sizer, downSizer, longSizer);
		}
		
		IPAddressSeqRangePrefixSpliterator(
				S forIteration,
				Predicate<IPAddressSeqRangeSplitterSink<S, S>> splitter,
				SeqRangeIteratorProvider<S, S> iteratorProvider,
				boolean isLowest,
				Function<S, BigInteger> sizer,
				Predicate<S> downSizer,
				ToLongFunction<S> longSizer) {
			super(forIteration, splitter, iteratorProvider, isLowest, sizer, downSizer, longSizer);
		}
		
		@Override
		protected IPAddressSeqRangePrefixSpliterator<S> createSpliterator(
				S split, 
				boolean isLowest,
				Function<S, BigInteger> sizer,
				Predicate<S> downSizer,
				ToLongFunction<S> longSizer) {
			return new IPAddressSeqRangePrefixSpliterator<S>(split, splitter, (SeqRangeIteratorProvider<S, S>) iteratorProvider, isLowest, sizer, downSizer, longSizer);
		}
		
		@Override
		public IPAddressSeqRangePrefixSpliterator<S> trySplit() {
			return (IPAddressSeqRangePrefixSpliterator<S>) super.trySplit();
		}
	}
	
	@Override
	public abstract IPAddressSection increment(long increment);
	
	@Override
	public abstract IPAddressSection incrementBoundary(long increment);
	
	public boolean isEntireAddress() {
		return getSegmentCount() == IPAddress.getSegmentCount(getIPVersion());
	}
	
	protected boolean isMultiple(int segmentCount) {
		for(int i = 0; i < segmentCount; i++) {
			if(getSegment(i).isMultiple()) {
				return true;
			}
		}
		return false;
	}
	
	/**
	 * Returns whether this section has a prefix length and if so, 
	 * whether the host section is zero for this section or all sections in this set of address sections.
	 * If the host section is zero length (there are no host bits at all), returns false.
	 * 
	 * @return
	 */
	public boolean isZeroHost() {
		if(!isPrefixed()) {
			return false;
		}
		return isZeroHost(getNetworkPrefixLength());
	}
	
	/**
	 * Returns whether the host is zero for the given prefix length for this section or all sections in this set of address sections.
	 * If this section already has a prefix length, then that prefix length is ignored.
	 * If the host section is zero length (there are no host bits at all), returns false.
	 * 
	 * @return
	 */
	public boolean isZeroHost(int prefixLength) {
		if(prefixLength < 0 || prefixLength > getBitCount()) {
			throw new PrefixLenException(this, prefixLength);
		}
		return isZeroHost(prefixLength, getSegments(), getBytesPerSegment(), getBitsPerSegment(), getBitCount());
	}
	
	protected <S extends IPAddressSegment> boolean isZeroHost(S segments[]) {
		if(!isPrefixed()) {
			return false;
		}
		return isZeroHost(getNetworkPrefixLength(), segments, getBytesPerSegment(), getBitsPerSegment(), getBitCount());
	}
	
	protected <S extends IPAddressSegment> boolean isZeroHost(S segments[], int prefixLength) {
		return isZeroHost(prefixLength, segments, getBytesPerSegment(), getBitsPerSegment(), getBitCount());
	}
	
	protected static <S extends IPAddressSegment> boolean isZeroHost(int prefLen, S segments[], int bytesPerSegment, int bitsPerSegment, int bitCount) {
		if(segments.length == 0 ) {
			return false;
		}
		if(prefLen >= bitCount) {
			return false;
		}
		int divCount = segments.length;
		int prefixedSegmentIndex = getHostSegmentIndex(prefLen, bytesPerSegment, bitsPerSegment);
		for(int i = prefixedSegmentIndex; i < divCount; i++) {
			Integer segmentPrefixLength = getPrefixedSegmentPrefixLength(bitsPerSegment, prefLen, prefixedSegmentIndex);
			S div = segments[i];
			if(segmentPrefixLength != null) {
				int mask = div.getSegmentHostMask(segmentPrefixLength);
				if(div.isMultiple() || (mask & div.getSegmentValue()) != 0) {
					return false;
				}
				for(++i; i < divCount; i++) {
					div = segments[i];
					if(!div.isZero()) {
						return false;
					}
				}
			}
		}
		return true;
	}
	
	InetAddress toInetAddress(IPAddress address) {
		InetAddress result;
		if(hasNoValueCache() || (result = valueCache.inetAddress) == null) {
			valueCache.inetAddress = result = address.toInetAddressImpl(getBytes());
		}
		return result;
	}
	
	InetAddress toUpperInetAddress(IPAddress address) {
		InetAddress result;
		if(hasNoValueCache() || (result = valueCache.upperInetAddress) == null) {
			valueCache.upperInetAddress = result = address.toInetAddressImpl(getUpperBytes());
		}
		return result;
	}
	
	////////////////string creation below ///////////////////////////////////////////////////////////////////////////////////////////

	static void checkLengths(int length, StringBuilder builder) {
		IPAddressStringParams.checkLengths(length, builder);
	}
	
	@Override
	public String toString() {
		return toNormalizedString();//for ipv6, the canonical string can be the same for two different sections
	}

	@Override
	public String[] getSegmentStrings() {
		return getDivisionStrings();
	}
	
	protected abstract void cacheNormalizedString(String str);
	
	protected abstract IPStringCache getStringCache();
	
	protected abstract boolean hasNoStringCache();
	
	/*
	 * There are two approaches when going beyond the usual segment by segment approach to producing strings for IPv6 and IPv4.
	 * We can use the inet_aton approach, creating new segments as desired (one, two or three segments instead of the usual 4).
	 * Then each such segment must simply know it's own sizes, whether bits, bytes, or characters, as IPAddressJoinedSegments and its subclasses show.
	 * The limitations to this are the fact that arithmetic is done with Java longs, limiting the possible sizes.  Also, we must define new classes to accommodate the new segments.
	 * A disadvantage to this approach is that the new segments may be short lived, so any caching is not helpful.
	 * 
	 * The second approach is to print with no separator chars (no '.' or ':') and with leading zeros, but otherwise print in the same manner.
	 * So 1:2 would become 00010002.  
	 * This works in cases where the string character boundaries line up with the segment boundaries.
	 * This works for hexadecimal, where each segment is exactly two characters for IPv4, and each segment is exactly 4 characters for IPv6.
	 * For other radices, this is not so simple.
	 * 
	 * A hybrid approach would use both approaches.  For instance, for octal we could simply divide into segments where each segment has 6 bits,
	 * corresponding to exactly two octal characters, or any combination where each segment has some multiple of 3 bits.  It helps if the segment bit length
	 * divides the total bit length, so the first segment does not end up with too many leading zeros.  
	 * In the cases where the above approaches do not work, this approach works.
	 */
	

	@Override
	public String toBinaryString() throws IncompatibleAddressException {
		String result;
		if(hasNoStringCache() || (result = getStringCache().binaryString) == null) {
			IPStringCache stringCache = getStringCache();
			stringCache.binaryString = result = toBinaryString(null);
		}
		return result;
	}
	
	protected String toBinaryString(CharSequence zone) {
		if(isDualString()) {
			return toNormalizedStringRange(toIPParams(IPStringCache.binaryParams), getLower(), getUpper(), zone);
		}
		return toIPParams(IPStringCache.binaryParams).toString(this, zone);
	}
	
	@Override
	public String toOctalString(boolean with0Prefix) throws IncompatibleAddressException {  
		String result;
		if(hasNoStringCache() || (result = (with0Prefix ? getStringCache().octalStringPrefixed : getStringCache().octalString)) == null) {
			IPStringCache stringCache = getStringCache();
			result = toOctalString(with0Prefix, null);
			if(with0Prefix) {
				stringCache.octalStringPrefixed = result;
			} else {
				stringCache.octalString = result;
			}
		}
		return result;
	}
	
	protected String toOctalString(boolean with0Prefix, CharSequence zone) throws IncompatibleAddressException {
		if(isDualString()) {
			IPAddressSection lower = getLower();
			IPAddressSection upper = getUpper();
			IPAddressBitsDivision lowerDivs[] = lower.createNewDivisions(3, IPAddressBitsDivision::new, IPAddressBitsDivision[]::new);
			IPAddressStringDivisionSeries lowerPart = new IPAddressDivisionGrouping(lowerDivs, getNetwork());
			IPAddressBitsDivision upperDivs[] = upper.createNewDivisions(3, IPAddressBitsDivision::new, IPAddressBitsDivision[]::new);
			IPAddressStringDivisionSeries upperPart = new IPAddressDivisionGrouping(upperDivs, getNetwork());
			return toNormalizedStringRange(toIPParams(with0Prefix ? IPStringCache.octalPrefixedParams : IPStringCache.octalParams), lowerPart, upperPart, zone);
		}
		IPAddressBitsDivision divs[] = createNewPrefixedDivisions(3, null, null, IPAddressBitsDivision::new, IPAddressBitsDivision[]::new);
		IPAddressStringDivisionSeries part = new IPAddressDivisionGrouping(divs, getNetwork());
		return toIPParams(with0Prefix ? IPStringCache.octalPrefixedParams : IPStringCache.octalParams).toString(part, zone);
	}

	@Override
	public String toHexString(boolean with0xPrefix) throws IncompatibleAddressException {  
		String result;
		if(hasNoStringCache() || (result = (with0xPrefix ? getStringCache().hexStringPrefixed : getStringCache().hexString)) == null) {
			IPStringCache stringCache = getStringCache();
			result = toHexString(with0xPrefix, null);
			if(with0xPrefix) {
				stringCache.hexStringPrefixed = result;
			} else {
				stringCache.hexString = result;
			}
		}
		return result;
	}
	
	//overridden in ipv6 to handle zone
	protected String toHexString(boolean with0xPrefix, CharSequence zone) throws IncompatibleAddressException {
		if(isDualString()) {
			return toNormalizedStringRange(toIPParams(with0xPrefix ? IPStringCache.hexPrefixedParams : IPStringCache.hexParams), getLower(), getUpper(), zone);
		}
		return toIPParams(with0xPrefix ? IPStringCache.hexPrefixedParams : IPStringCache.hexParams).toString(this, zone);
	}
	
	@Override
	public String toNormalizedString(IPStringOptions stringOptions) {
		return toNormalizedString(stringOptions, this);
	}

	public static String toNormalizedString(IPStringOptions opts, IPAddressStringDivisionSeries section) {
		return toIPParams(opts).toString(section);
	}

	protected static IPAddressStringParams<IPAddressStringDivisionSeries> toIPParams(IPStringOptions opts) {
		//since the params here are not dependent on the section, we could cache the params in the options 
		//this is not true on the IPv6 side where compression settings change based on the section
		
		@SuppressWarnings("unchecked")
		IPAddressStringParams<IPAddressStringDivisionSeries> result = (IPAddressStringParams<IPAddressStringDivisionSeries>) getCachedParams(opts);
			
		if(result == null) {
			result = new IPAddressStringParams<IPAddressStringDivisionSeries>(opts.base, opts.separator, opts.uppercase);
			result.expandSegments(opts.expandSegments);
			result.setWildcards(opts.wildcards);
			result.setWildcardOption(opts.wildcardOption);
			result.setSegmentStrPrefix(opts.segmentStrPrefix);
			result.setAddressSuffix(opts.addrSuffix);
			result.setAddressLabel(opts.addrLabel);
			result.setReverse(opts.reverse);
			result.setSplitDigits(opts.splitDigits);
			result.setZoneSeparator(opts.zoneSeparator);
			setCachedParams(opts, result);
		}
		return result;
	}

		
	/**
	 * Returns at most a couple dozen string representations:
	 * 
	 * -mixed (1:2:3:4:5:6:1.2.3.4)
	 * -upper and lower case
	 * -full compressions or no compression (a:0:0:c:d:0:e:f or a::c:d:0:e:f or a:0:b:c:d::e:f)
	 * -full leading zeros (000a:0000:000b:000c:000d:0000:000e:000f)
	 * -combinations thereof
	 * 
	 * @return
	 */
	public IPAddressPartStringCollection toStandardStringCollection() {
		return toStringCollection(new IPStringBuilderOptions(IPStringBuilderOptions.LEADING_ZEROS_FULL_ALL_SEGMENTS));
	}

	/**
	 * Use this method with care...  a single IPv6 address can have thousands of string representations.
	 * 
	 * Examples: 
	 * "::" has 1297 such variations, but only 9 are considered standard
	 * "a:b:c:0:d:e:f:1" has 1920 variations, but only 12 are standard
	 * 
	 * Variations included in this method:
	 * -all standard variations
	 * -choosing specific segments for full leading zeros (::a:b can be ::000a:b, ::a:000b, or ::000a:000b)
	 * -choosing which zero-segments to compress (0:0:a:: can be ::a:0:0:0:0:0 or 0:0:a::)
	 * -mixed representation (1:2:3:4:5:6:1.2.3.4)
	 * -all combinations of such variations
	 * 
	 * Variations omitted from this method: 
	 * -mixed case of a-f, which you can easily handle yourself with String.equalsIgnoreCase
	 * -adding a variable number of leading zeros (::a can be ::0a, ::00a, ::000a)
	 * -choosing any number of zero-segments anywhere to compress (:: can be 0:0:0::0:0)
	 * 
	 * @return
	 */
	public IPAddressPartStringCollection toAllStringCollection() {
		return toStringCollection(new IPStringBuilderOptions(IPStringBuilderOptions.LEADING_ZEROS_FULL_SOME_SEGMENTS));
	}
	
	/**
	 * Returns a set of strings for search the standard string representations in a database
	 * 
	 * -compress the largest compressible segments or no compression (a:0:0:c:d:0:e:f or a::c:d:0:e:f)
	 * -upper/lowercase is not considered because many databases are case-insensitive
	 * 
	 * @return
	 */
	public IPAddressPartStringCollection toDatabaseSearchStringCollection() {
		return toStringCollection(new IPStringBuilderOptions());
	}
	
	/**
	 * Get all representations of this address including this IPAddressSection.  
	 * This includes:
	 * <ul>
	 * <li>alternative segment groupings expressed as {@link IPAddressDivisionGrouping}</li>
	 * <li>conversions to IPv6, and alternative representations of those IPv6 addresses</li>
	 * </ul>
	 * 
	 * @param options
	 * @return
	 */
	public IPAddressStringDivisionSeries[] getParts(IPStringBuilderOptions options) {
		if(options.includes(IPStringBuilderOptions.BASIC)) {
			return new IPAddressStringDivisionSeries[] { this };
		}
		return EMPTY_PARTS;
	}
	
	/**
	 * This method gives you an SQL clause that allows you to search the database for the front part of an address or 
	 * addresses in a given network.
	 * 
	 * This is not as simple as it sounds, because the same address can be written in different ways (especially for IPv6)
	 * and in addition, addresses in the same network can have different beginnings (eg 1.0.0.0/7 are all addresses from 0.0.0.0 to 1.255.255.255),
	 * so you can see they start with both 1 and 0.  You can reduce the number of possible beginnings by choosing a segment
	 * boundary for the network prefix.
	 * 
	 * The SQL produced works for MySQL.  For a different database type, 
	 * use {@link #getStartsWithSQLClause(StringBuilder, String, IPAddressSQLTranslator)}
	 * 
	 * @param builder
	 * @param expression the expression that must match the condition, whether a column name or other
	 */
	public void getStartsWithSQLClause(StringBuilder builder, String expression) {
		getStartsWithSQLClause(builder, expression, new MySQLTranslator());
	}
	
	public void getStartsWithSQLClause(StringBuilder builder, String expression, IPAddressSQLTranslator translator) {
		getStartsWithSQLClause(builder, expression, true, translator);
	}
	
	private void getStartsWithSQLClause(StringBuilder builder, String expression, boolean isFirstCall, IPAddressSQLTranslator translator) {
		if(isFirstCall && isMultiple()) {
			Iterator<? extends IPAddressSection> sectionIterator = iterator();
			builder.append('(');
			boolean isNotFirst = false;
			while(sectionIterator.hasNext()) {
				if(isNotFirst) {
					builder.append(" OR ");
				} else {
					isNotFirst = true;
				}
				IPAddressSection next = sectionIterator.next();
				next.getStartsWithSQLClause(builder, expression, false, translator);
			}
			builder.append(')');
		} else if(getSegmentCount() > 0) { //there is something to match and we are searching for an exact network prefix	
			IPAddressPartStringCollection createdStringCollection = toDatabaseSearchStringCollection();
			boolean isNotFirst = false;
			if(createdStringCollection.size() > 1) {
				builder.append('(');
			}
			boolean isEntireAddress = isEntireAddress();
			//for every string representation of our address section in the collection, we get an SQL clause that will match it
			for(IPAddressPartConfiguredString<?, ?> createdStr: createdStringCollection) {
				if(isNotFirst) {
					builder.append(" OR ");
				} else {
					isNotFirst = true;
				}
				SQLStringMatcher<?, ?, ?> matcher = createdStr.getNetworkStringMatcher(isEntireAddress, translator);
				matcher.getSQLCondition(builder.append('('), expression).append(')');
			}
			if(createdStringCollection.size() > 1) {
				builder.append(')');
			}
		}
	}

	/* the various string representations - these fields are for caching */
	protected static class IPStringCache extends StringCache {
		public static final IPStringOptions hexParams;
		public static final IPStringOptions hexPrefixedParams;
		public static final IPStringOptions octalParams;
		public static final IPStringOptions octalPrefixedParams;
		public static final IPStringOptions binaryParams;
		public static final IPStringOptions canonicalSegmentParams;

		static {
			WildcardOptions allWildcards = new WildcardOptions(WildcardOptions.WildcardOption.ALL);
			hexParams = new IPStringOptions.Builder(16).setSeparator(null).setExpandedSegments(true).setWildcardOptions(allWildcards).toOptions();
			hexPrefixedParams = new IPStringOptions.Builder(16).setSeparator(null).setExpandedSegments(true).setWildcardOptions(allWildcards).setAddressLabel(IPAddress.HEX_PREFIX).toOptions();
			octalParams = new IPStringOptions.Builder(8).setSeparator(null).setExpandedSegments(true).setWildcardOptions(allWildcards).toOptions();
			octalPrefixedParams = new IPStringOptions.Builder(8).setSeparator(null).setExpandedSegments(true).setWildcardOptions(allWildcards).setAddressLabel(IPAddress.OCTAL_PREFIX).toOptions();
			binaryParams = new IPStringOptions.Builder(2).setSeparator(null).setExpandedSegments(true).setWildcardOptions(allWildcards).toOptions();
			canonicalSegmentParams = new IPStringOptions.Builder(10, ' ').toOptions();
		}
		
		public String normalizedWildcardString;
		public String fullString;
		public String sqlWildcardString;

		public String reverseDNSString;
		
		public String octalStringPrefixed;
		public String octalString;
		public String binaryString;
		
		public String segmentedBinaryString;
	}
	
	public static class WildcardOptions {
		public enum WildcardOption {
			NETWORK_ONLY, //only print wildcards that are part of the network portion (only possible with subnet address notation, otherwise this option is ignored)
			ALL //print wildcards for any visible (non-compressed) segments
		}
		
		public final WildcardOption wildcardOption;
		public final Wildcards wildcards;
		
		public WildcardOptions() {
			this(WildcardOption.NETWORK_ONLY);
		}
		
		public WildcardOptions(WildcardOption wildcardOption) {
			this(wildcardOption, new Wildcards());
		}
		
		public WildcardOptions(WildcardOption wildcardOption, Wildcards wildcards) {
			this.wildcardOption = wildcardOption;
			this.wildcards = wildcards;
		}
	}

	/**
	 * Represents a clear way to create a specific type of string.
	 * 
	 * @author sfoley
	 */
	public static class IPStringOptions extends StringOptions {
		
		public final String addrSuffix;
		public final WildcardOption wildcardOption;
		public final char zoneSeparator;
		
		protected IPStringOptions(
				int base,
				boolean expandSegments,
				WildcardOption wildcardOption,
				Wildcards wildcards,
				String segmentStrPrefix,
				Character separator,
				char zoneSeparator,
				String label,
				String suffix,
				boolean reverse,
				boolean splitDigits,
				boolean uppercase) {
			super(base, expandSegments, wildcards, segmentStrPrefix, separator, label, reverse, splitDigits, uppercase);
			this.addrSuffix = suffix;
			this.wildcardOption = wildcardOption;
			this.zoneSeparator = zoneSeparator;
		}
		
		public static class Builder extends StringOptions.Builder {

			protected String addrSuffix = "";
			protected WildcardOption wildcardOption = WildcardOption.NETWORK_ONLY;
			protected char zoneSeparator = IPv6Address.ZONE_SEPARATOR;
			
			public Builder(int base) {
				this(base, ' ');
			}
			
			protected Builder(int base, char separator) {
				super(base, separator);
			}
			
			@Override
			public Builder setWildcards(Wildcards wildcards) {
				return (Builder) super.setWildcards(wildcards);
			}
			
			/*
			 * .in-addr.arpa, .ip6.arpa, .ipv6-literal.net are examples of suffixes tacked onto the end of address strings
			 */
			public Builder setAddressSuffix(String suffix) {
				this.addrSuffix = suffix;
				return this;
			}
			
			public Builder setWildcardOptions(WildcardOptions wildcardOptions) {
				setWildcardOption(wildcardOptions.wildcardOption);
				return setWildcards(wildcardOptions.wildcards);
			}
			
			public Builder setWildcardOption(WildcardOption wildcardOption) {
				this.wildcardOption = wildcardOption;
				return this;
			}
			
			@Override
			public Builder setReverse(boolean reverse) {
				return (Builder) super.setReverse(reverse);
			}
			
			@Override
			public Builder setUppercase(boolean uppercase) {
				return (Builder) super.setUppercase(uppercase);
			}
			
			@Override
			public Builder setSplitDigits(boolean splitDigits) {
				return (Builder) super.setSplitDigits(splitDigits);
			}
			
			@Override
			public Builder setExpandedSegments(boolean expandSegments) {
				return (Builder) super.setExpandedSegments(expandSegments);
			}
			
			@Override
			public Builder setRadix(int base) {
				return (Builder) super.setRadix(base);
			}
			
			/*
			 * separates the divisions of the address, typically ':' or '.', but also can be null for no separator
			 */
			@Override
			public Builder setSeparator(Character separator) {
				return (Builder) super.setSeparator(separator);
			}
			
			public Builder setZoneSeparator(char separator) {
				this.zoneSeparator = separator;
				return this;
			}
			
			@Override
			public Builder setAddressLabel(String label) {
				return (Builder) super.setAddressLabel(label);
			}
			
			@Override
			public Builder setSegmentStrPrefix(String prefix) {
				return (Builder) super.setSegmentStrPrefix(prefix);
			}
			
			@Override
			public IPStringOptions toOptions() {
				return new IPStringOptions(base,
						expandSegments, wildcardOption, wildcards, segmentStrPrefix, separator, zoneSeparator, addrLabel, addrSuffix, reverse, splitDigits, uppercase);
			}
		}
	}
	
	/**
	 * This user-facing class is designed to be a clear way to create a collection of strings.
	 * 
	 * @author sfoley
	 *
	 */
	public static class IPStringBuilderOptions {
		public static final int BASIC = 0x1;//no compressions, lowercase only, no leading zeros, no mixed, no nothing
		
		public static final int LEADING_ZEROS_FULL_ALL_SEGMENTS = 0x10; //0001:0002:00ab:0abc::
		public static final int LEADING_ZEROS_FULL_SOME_SEGMENTS = 0x20 | LEADING_ZEROS_FULL_ALL_SEGMENTS; //1:0002:00ab:0abc::, 0001:2:00ab:0abc::, ...
		public static final int LEADING_ZEROS_PARTIAL_SOME_SEGMENTS = 0x40 | LEADING_ZEROS_FULL_SOME_SEGMENTS; //1:02:00ab:0abc::, 01:2:00ab:0abc::, ...

		public final int options;
		
		public IPStringBuilderOptions() {
			this(BASIC);
		}
		
		public IPStringBuilderOptions(int options) {
			this.options = options;
		}
		
		public boolean includes(int option) {
			return (option & options) == option;
		}
		
		public boolean includesAny(int option) {
			return (option & options) != 0;
		}
		
		@Override
		public String toString() {
			TreeMap<Integer, String> options = new TreeMap<>();
			Field fields[] = getClass().getFields();
			for(Field field: fields) {
				int modifiers = field.getModifiers();
				if(Modifier.isFinal(modifiers) && Modifier.isStatic(modifiers)) {
					try {
						int constant = field.getInt(null);
						String option = field.getName() + ": " + includes(constant) + System.lineSeparator();
						options.put(constant, option);
					} catch(IllegalAccessException e) {}
				}
			}
			Collection<String> values = options.values(); //the iterator for this Collection is sorted since we use a SortedMap
			StringBuilder builder = new StringBuilder();
			for(String val : values) {
				builder.append(val);
			}
			return builder.toString();
		}
	}
}
