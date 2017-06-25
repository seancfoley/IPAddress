/*
 * Copyright 2017 Sean C Foley
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
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.TreeMap;
import java.util.function.BiFunction;
import java.util.function.IntFunction;

import inet.ipaddr.IPAddress.IPVersion;
import inet.ipaddr.IPAddressSection.WildcardOptions.WildcardOption;
import inet.ipaddr.IPAddressTypeNetwork.IPAddressCreator;
import inet.ipaddr.format.AddressDivisionGrouping;
import inet.ipaddr.format.AddressDivisionGrouping.StringOptions.Wildcards;
import inet.ipaddr.format.IPAddressBitsDivision;
import inet.ipaddr.format.IPAddressDivisionGrouping;
import inet.ipaddr.format.IPAddressStringDivisionSeries;
import inet.ipaddr.format.util.IPAddressPartConfiguredString;
import inet.ipaddr.format.util.IPAddressPartStringCollection;
import inet.ipaddr.format.util.sql.IPAddressSQLTranslator;
import inet.ipaddr.format.util.sql.MySQLTranslator;
import inet.ipaddr.format.util.sql.SQLStringMatcher;
import inet.ipaddr.ipv6.IPv6Address;

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
public abstract class IPAddressSection extends IPAddressDivisionGrouping implements AddressSection {
	
	private static final long serialVersionUID = 3L;
	private static final IPAddressStringDivisionSeries EMPTY_PARTS[] = new IPAddressStringDivisionSeries[0];
	
	/* caches objects to avoid recomputing them */
	protected static class PrefixCache {
		/* for caching */
		private Integer networkMaskPrefixLen; //null indicates this field not initialized, -1 indicates the prefix len is null
		private Integer hostMaskPrefixLen; //null indicates this field not initialized, -1 indicates the prefix len is null
		
		/* also for caching */
		private Integer cachedMinPrefix; //null indicates this field not initialized
		private Integer cachedEquivalentPrefix; //null indicates this field not initialized, -1 indicates the prefix len is null
	}
	
	protected transient PrefixCache prefixCache;
	
	protected IPAddressSection(IPAddressSegment segments[], byte bytes[], boolean cloneSegments, boolean cloneBytes) {
		super(cloneSegments ? segments.clone() : segments);
		Integer previousSegmentPrefix = null;
		for(IPAddressSegment segment : segments) {
			if(segment == null) {
				throw new NullPointerException("null segment");
			}
			/**
			 * Across an address prefixes are:
			 * IPv6: (null):...:(null):(1 to 16):(0):...:(0)
			 * or IPv4: ...(null).(1 to 8).(0)...
			 */
			Integer segPrefix = segment.getSegmentPrefixLength();
			if(previousSegmentPrefix != null && (segPrefix == null || segPrefix != 0)) {
				throw new IllegalArgumentException("Segments invalid due to inconsistent prefix values");
			}
			previousSegmentPrefix = segPrefix;
		}
		if(bytes != null) {
			setBytes(cloneBytes ? bytes.clone() : bytes);
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
		prefixCache.cachedEquivalentPrefix = cachedEquivalentPrefix;
	}
	
	protected static RangeList getNoZerosRange() {
		return IPAddressDivisionGrouping.getNoZerosRange();
	}
	
	protected static RangeList getSingleRange(int index, int len) {
		return IPAddressDivisionGrouping.getSingleRange(index, len);
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
	
	public boolean isIPv4() {
		return false;
	}
	
	public boolean isIPv6() {
		return false;
	}
	
	public abstract IPVersion getIPVersion();
	
	protected static int getSegmentIndex(Integer networkPrefixLength, int byteLength, int bytesPerSegment) {
		int byteIndex = getByteIndex(networkPrefixLength, byteLength);
		if(bytesPerSegment > 1) {
			if(bytesPerSegment == 2) {
				return byteIndex >>> 1;
			}
			return byteIndex / bytesPerSegment;
		}
		return byteIndex;
		
	}
	
	protected static int getByteIndex(Integer networkPrefixLength, int byteLength) {
		if(networkPrefixLength == null) {
			return byteLength;
		}
		if(networkPrefixLength < 0 || networkPrefixLength > (byteLength << 3)) {
			throw new AddressTypeException(networkPrefixLength, "ipaddress.error.prefixSize");
		}
		if(networkPrefixLength == 0) {
			return 0;
		}
		return (networkPrefixLength - 1) >>> 3;
	}
	
	public abstract int getByteIndex(int networkPrefixLength);
	
	public abstract int getSegmentIndex(int networkPrefixLength);
	
	public abstract IPAddressSection getNetworkSection(int networkPrefixLength, boolean withPrefixLength);
	
	public abstract IPAddressSection getNetworkSection(int networkPrefixLength);
	
	//this method is basically checking whether we can return "this" for getNetworkSection
	protected boolean isNetworkSection(int networkPrefixLength, boolean withPrefixLength) {
		int segmentCount = getSegmentCount();
		if(segmentCount == 0) {
			return true;
		}
		int prefixedSegment = getSegmentIndex(networkPrefixLength);
		if(prefixedSegment + 1 < segmentCount) {
			return false; //not the right number of segments
		}
		//the segment count matches, now compare the prefixed segment
		int lastSegmentIndex = segmentCount - 1;
		int bitsPerSegment = getBitsPerSegment();
		int segmentPrefixLength = networkPrefixLength - (lastSegmentIndex * bitsPerSegment); 
		return !getSegment(lastSegmentIndex).isNetworkChangedByPrefix(getSegmentPrefixLength(bitsPerSegment, segmentPrefixLength), withPrefixLength);
	}
	
	protected boolean isHostSection(int networkPrefixLength) {
		int segmentCount = getSegmentCount();
		if(segmentCount == 0) {
			return true;
		}
		if(networkPrefixLength >= getBitsPerSegment()) {
			return false;
		}
		return !getSegment(0).isHostChangedByPrefix(networkPrefixLength);
	}
	
	public abstract IPAddressSection getHostSection(int networkPrefixLength);

	private Integer checkForPrefixMask(boolean network) {
		int front, back;
		if(network) {
			front = getSegment(0).getMaxSegmentValue();
			back = 0;
		} else {
			back = getSegment(0).getMaxSegmentValue();
			front = 0;
		}
		int prefixLen = 0;
		for(int i=0; i < getSegmentCount(); i++) {
			IPAddressSegment seg = getSegment(i);
			int value = seg.getLowerSegmentValue();
			if(value != front) {
				Integer segmentPrefixLen = seg.getMaskPrefixLength(network);
				if(segmentPrefixLen == null) {
					return null;
				}
				prefixLen += segmentPrefixLen;
				for(i++; i < getSegmentCount(); i++) {
					value = getSegment(i).getLowerSegmentValue();
					if(value != back) {
						return null;
					}
				}
			} else {
				prefixLen += seg.getBitCount();
			}
		}
		//note that when segments.length == 0, we return 0 as well, since both the host mask and prefix mask are empty (length of 0 bits)
		return prefixLen;
	}
	
	/**
	 * If this address section is equivalent to the mask for a CIDR prefix, it returns that prefix length.
	 * Otherwise, it returns null.
	 * A CIDR network mask is an address with all 1s in the network section and then all 0s in the host section.
	 * A CIDR host mask is an address with all 0s in the network section and then all 1s in the host section.
	 * The prefix length is the length of the network section.
	 * 
	 * Also, keep in mind that the prefix length returned by this method is not equivalent to the prefix length used to construct this object.
	 * The prefix length used to construct indicates the network and host portion of this address.  
	 * The prefix length returned here indicates the whether the value of this address can be used as a mask for the network and host
	 * portion of any other address.  Therefore the two values can be different values, or one can be null while the other is not.
	 * 
	 * This method applies only to the lower value of the range if this section represents multiple values.
	 * 
	 * @param network whether to check for a network mask or a host mask
	 * @return the prefix length corresponding to this mask, or null if this address is not a CIDR prefix mask
	 */
	public Integer getMaskPrefixLength(boolean network) {
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
			prefixLen = prefixCache.hostMaskPrefixLen = -1;
		} else {
			prefixCache.hostMaskPrefixLen = prefixLen;
			prefixCache.networkMaskPrefixLen = -1; //cannot be both network and host mask
		}
		return prefixLen;
	}
	
	private Integer setNetworkMaskPrefix(Integer prefixLen) {
		if(prefixLen == null) {
			prefixLen = prefixCache.networkMaskPrefixLen = -1;
		} else {
			prefixCache.networkMaskPrefixLen = prefixLen;
			prefixCache.hostMaskPrefixLen = -1; //cannot be both network and host mask
		}
		return prefixLen;
	}

	protected static <T extends IPAddress, R extends IPAddressSection, S extends IPAddressSegment>
			R getNetworkSection(
					R original,
					int networkPrefixLength,
					int networkSegmentCount,
					boolean withPrefixLength,
					IPAddressCreator<T, R, ?, S> creator,
					BiFunction<Integer, Integer, S> segProducer) {
		if(networkPrefixLength < 0 || networkPrefixLength > original.getBitCount()) {
			throw new AddressTypeException(original, networkPrefixLength, "ipaddress.error.prefixSize");
		}
		if(original.isNetworkSection(networkPrefixLength, withPrefixLength)) {
			return original;
		}
		int bitsPerSegment = original.getBitsPerSegment();
		S result[] = creator.createSegmentArray(networkSegmentCount);
		if(networkSegmentCount > 0) {
			for(int i = 0; i < networkSegmentCount; i++) {
				Integer prefix = getSegmentPrefixLength(bitsPerSegment, networkPrefixLength, i);
				result[i] = segProducer.apply(i, prefix);
			}
		}
		return creator.createSectionInternal(result);
	}
	
	protected int getNetworkSegmentCount(int networkPrefixLength) {
		if(networkPrefixLength <= 0) {
			return 0;
		}
		int bitsPerSegment = getBitsPerSegment();
		int result = (networkPrefixLength + (bitsPerSegment - 1)) / bitsPerSegment;
		int segmentCount = getSegmentCount();
		if(result > segmentCount) {
			return segmentCount;
		}
		return result;
	}
	
	protected static <T extends IPAddress, R extends IPAddressSection, S extends IPAddressSegment> 
			R getHostSection(R original, int networkPrefixLength, int hostSegmentCount, IPAddressCreator<T, R, ?, S> creator,
					BiFunction<Integer, Integer, S> segProducer) {
		if(networkPrefixLength < 0 || networkPrefixLength > original.getBitCount()) {
			throw new AddressTypeException(original, networkPrefixLength, "ipaddress.error.prefixSize");
		}
		if(original.isHostSection(networkPrefixLength)) {
			return original;
		}
		int segmentCount = original.getSegmentCount();
		S result[] = creator.createSegmentArray(hostSegmentCount);
		if(hostSegmentCount > 0) {
			int bitsPerSegment = original.getBitsPerSegment();
			for(int i = hostSegmentCount - 1, j = segmentCount - 1; i >= 0; i--, j--) {
				Integer prefix = getSegmentPrefixLength(bitsPerSegment, networkPrefixLength, j);
				result[i] = segProducer.apply(j, prefix);
			}
		}
		return creator.createSectionInternal(result);
	}
	
	protected int getHostSegmentCount(int networkPrefixLength) {
		if(networkPrefixLength <= 0) {
			return getSegmentCount();
		}
		int hostBits = getHostBits(networkPrefixLength);
		if(hostBits <= 0) {
			return 0;
		}
		int bitsPerSegment = getBitsPerSegment();
		return (hostBits + bitsPerSegment - 1) / bitsPerSegment;
	}
	
	public Integer getHostBits() {
		if(isPrefixed()) {
			return getHostBits(getNetworkPrefixLength());
		}
		return null;
	}
	
	private int getHostBits(int networkPrefixLength) {
		return getSegmentCount() * getBitsPerSegment() - networkPrefixLength;
	}
	
	@FunctionalInterface
	public interface SegFunction<R, S> {
	    S apply(R section, int value);
	}
	
	protected static <R extends IPAddressSection, S extends IPAddressSegment> R setPrefixLength(
			R original,
			IPAddressCreator<?, R, ?, S> creator,
			int networkPrefixLength,
			boolean withZeros,
			boolean noShrink,
			IPAddressTypeNetwork<?, R, S> network,
			SegFunction<R, S> segProducer) {
		original.checkSubnet(networkPrefixLength);
		Integer existingPrefixLength = original.getNetworkPrefixLength();
		int maskBits;
		if(existingPrefixLength != null) {
			if(networkPrefixLength > existingPrefixLength) {
				if(noShrink) {
					return original;
				} else if(withZeros) {
					maskBits = existingPrefixLength;
				} else {
					maskBits = networkPrefixLength;
				}
			} else if(networkPrefixLength < existingPrefixLength) {
				maskBits = networkPrefixLength;
			} else {
				return original;
			}
		} else {
			maskBits = networkPrefixLength;
		}
		R mask = network.getNetworkMaskSection(maskBits);
		
		return getSubnetSegments(original, networkPrefixLength, creator, false, i -> segProducer.apply(original, i), i -> segProducer.apply(mask, i));
	}
	
	protected static <R extends IPAddressSection, S extends IPAddressSegment> R getSubnetSegments(
			R original,
			Integer networkPrefixLength,
			IPAddressCreator<?, R, ?, S> creator,
			boolean verifyMask,
			IntFunction<S> segProducer,
			IntFunction<S> maskSegProducer) {
		if(networkPrefixLength != null && (networkPrefixLength < 0 || networkPrefixLength > original.getBitCount())) {
			throw new AddressTypeException(original, networkPrefixLength, "ipaddress.error.prefixSize");
		}
		int bitsPerSegment = original.getBitsPerSegment();
		int count = original.getSegmentCount();
		for(int i = 0; i < count; i++) {
			Integer segmentPrefixLength = getSegmentPrefixLength(bitsPerSegment, networkPrefixLength, i);
			S seg = segProducer.apply(i);
			S mask = maskSegProducer.apply(i);
			int maskValue = mask.getLowerSegmentValue();
			if(seg.isChangedByMask(maskValue, segmentPrefixLength)) {
				if(verifyMask && !seg.isMaskCompatibleWithRange(maskValue, segmentPrefixLength)) {
					throw new AddressTypeException(seg, mask, "ipaddress.error.maskMismatch");
				}
				S newSegments[] = creator.createSegmentArray(original.getSegmentCount());
				original.getSegments(0, i, newSegments, 0);
				newSegments[i] = creator.createSegment(seg.getLowerSegmentValue() & maskValue, seg.getUpperSegmentValue() & maskValue, segmentPrefixLength);
				if(segmentPrefixLength == null) {
					for(i++; i < count; i++) {
						segmentPrefixLength = getSegmentPrefixLength(bitsPerSegment, networkPrefixLength, i);
						seg  = segProducer.apply(i);
						mask = maskSegProducer.apply(i);
						maskValue = mask.getLowerSegmentValue();
						if(!seg.isChangedByMask(maskValue, segmentPrefixLength)) {
							newSegments[i] = seg;
						} else {
							if(verifyMask && !seg.isMaskCompatibleWithRange(maskValue, segmentPrefixLength)) {
								throw new AddressTypeException(seg, mask, "ipaddress.error.maskMismatch");
							}
							newSegments[i] = creator.createSegment(seg.getLowerSegmentValue() & maskValue, seg.getUpperSegmentValue() & maskValue, segmentPrefixLength);
						}
						if(segmentPrefixLength != null) {
							break;
						}
					}
				}
				if(++i < count) {
					S zeroSeg = creator.createSegment(0, 0);
					do {
						newSegments[i] = zeroSeg;
					} while(++i < count);
				}
				return creator.createSectionInternal(newSegments);
			}
		}
		return original;
	}
	
	protected static <R extends IPAddressSection, S extends IPAddressSegment> R getOredSegments(
			R original,
			Integer networkPrefixLength,
			IPAddressCreator<?, R, ?, S> creator,
			IntFunction<S> segProducer,
			IntFunction<S> maskSegProducer) {
		if(networkPrefixLength != null && (networkPrefixLength < 0 || networkPrefixLength > original.getBitCount())) {
			throw new AddressTypeException(original, networkPrefixLength, "ipaddress.error.prefixSize");
		}
		int bitsPerSegment = original.getBitsPerSegment();
		int count = original.getSegmentCount();
		for(int i = 0; i < count; i++) {
			Integer segmentPrefixLength = getSegmentPrefixLength(bitsPerSegment, networkPrefixLength, i);
			S seg = segProducer.apply(i);
			S mask = maskSegProducer.apply(i);
			int maskValue = mask.getLowerSegmentValue();
			if(seg.isChangedByOr(maskValue, segmentPrefixLength)) {
				if(!seg.isBitwiseOrCompatibleWithRange(maskValue, segmentPrefixLength)) {
					throw new AddressTypeException(seg, mask, "ipaddress.error.maskMismatch");
				}
				S newSegments[] = creator.createSegmentArray(original.getSegmentCount());
				original.getSegments(0, i, newSegments, 0);
				newSegments[i] = creator.createSegment(seg.getLowerSegmentValue() | maskValue, seg.getUpperSegmentValue() | maskValue, segmentPrefixLength);
				if(segmentPrefixLength == null) {
					for(i++; i < count; i++) {
						segmentPrefixLength = getSegmentPrefixLength(bitsPerSegment, networkPrefixLength, i);
						seg  = segProducer.apply(i);
						mask = maskSegProducer.apply(i);
						maskValue = mask.getLowerSegmentValue();
						if(!seg.isChangedByOr(maskValue, segmentPrefixLength)) {
							newSegments[i] = seg;
						} else {
							if(!seg.isBitwiseOrCompatibleWithRange(maskValue, segmentPrefixLength)) {
								throw new AddressTypeException(seg, mask, "ipaddress.error.maskMismatch");
							}
							newSegments[i] = creator.createSegment(seg.getLowerSegmentValue() | maskValue, seg.getUpperSegmentValue() | maskValue, segmentPrefixLength);
						}
						if(segmentPrefixLength != null) {
							break;
						}
					}
				}
				if(++i < count) {
					S zeroSeg = creator.createSegment(0, 0);
					do {
						newSegments[i] = zeroSeg;
					} while(++i < count);
				}
				return creator.createSectionInternal(newSegments);
			}
			if(seg.isPrefixed()) {
				break;
			}
		}
		return original;
	}
	
	//call this instead of the method below if you already know the networkPrefixLength doesn't extend to the end of the last segment of the section or address
	static Integer getSplitSegmentPrefixLength(int bitsPerSegment, Integer networkPrefixLength, int segmentIndex) {
		if(networkPrefixLength != null) {
			int segmentPrefixLength = networkPrefixLength - (segmentIndex * bitsPerSegment); 
			return getSegmentPrefixLength(bitsPerSegment, segmentPrefixLength);
		}
		return null;
	}

	/**
	 * Across the address prefixes are:
	 * IPv6: (null):...:(null):(1 to 16):(0):...:(0)
	 * or IPv4: ...(null).(1 to 8).(0)...
	 */
	public static Integer getSegmentPrefixLength(int bitsPerSegment, Integer prefixLength, int segmentIndex) {
		return AddressDivisionGrouping.getSegmentPrefixLength(bitsPerSegment, prefixLength, segmentIndex);
	}
	
	/**
	 * Across the address prefixes are:
	 * IPv6: (null):...:(null):(1 to 16):(0):...:(0)
	 * or IPv4: ...(null).(1 to 8).(0)...
	 */
	public static Integer getSegmentPrefixLength(int bitsPerSegment, int segmentPrefixedBits) {
		return AddressDivisionGrouping.getSegmentPrefixLength(bitsPerSegment, segmentPrefixedBits);
	}
	
	static Integer getJoinedSegmentPrefixLength(int bitsPerSegment, Integer highBits, Integer lowBits) {
		if(lowBits == null) {
			return null;
		}
		if(lowBits == 0) {
			return highBits;
		}
		return lowBits + bitsPerSegment;
	}
	
	public abstract IPAddressNetwork getNetwork();
	
	@Override
	public int getSegmentCount() {
		return getDivisionCount();
	}
	
	@Override
	public IPAddressSegment getSegment(int index) {
		return (IPAddressSegment) divisions[index];
	}

	/**
	 * @param other
	 * @return whether this subnet contains the given address section
	 */
	public boolean contains(IPAddressSection other) {
		//check if they are comparable first
		if(getSegmentCount() != other.getSegmentCount()) {
			return false;
		}
		for(int i=0; i < getSegmentCount(); i++) {
			IPAddressSegment seg = getSegment(i);
			if(!seg.contains(other.getSegment(i))) {
				return false;
			}
			if(seg.isPrefixed()) {
				//no need to check host section which contains all possible hosts
				break;
			}
		}
		return true;
	}
	
	@Override
	public boolean isFullRange() {
		int divCount = getDivisionCount();
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
		return true;
	}
	
	protected static <T extends IPAddress, R extends IPAddressSection, S extends IPAddressSegment> R[] 
			subtract(R first, R other, IPAddressCreator<T, R, ?, S> addrCreator, IntFunction<S> segProducer, BiFunction<R, Integer, R> prefixApplier) {
		//check if they are comparable first
		int segCount = first.getSegmentCount();
		if(segCount != other.getSegmentCount()) {
			throw new AddressTypeException(first, other, "ipaddress.error.sizeMismatch");
		}
		if(!first.isMultiple()) {
			if(other.contains(first)) {
				return null;
			}
			R result[] = addrCreator.createSectionArray(1);
			result[0] = first;
			return result;
		} else {
			//getDifference: same as removing the intersection
			//   first you confirm there is an intersection in each segment.  
			// Then you remove each intersection, one at a time, leaving the other segments the same, since only one segment needs to differ.
			// To prevent adding the same section twice, use only the intersection (ie the relative complement of the diff) of segments already handled and not the whole segment.
			
			// For example: 0-3.0-3.2.4 subtracting 1-4.1-3.2.4
			// The diff of the first segment is just 0, giving 0.0-3.2.4
			// The diff of the second segment is also 0, but for the first segment we use the intersection since we handled the first already, giving 1-3.0.2.4
			
			for(int i = 0; i < segCount; i++) {
				IPAddressSegment seg = first.getSegment(i);
				IPAddressSegment otherSeg = other.getSegment(i);
				int lower = seg.getLowerSegmentValue();
				int higher = seg.getUpperSegmentValue();
				int otherLower = otherSeg.getLowerSegmentValue();
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
				int lower = seg.getLowerSegmentValue();
				int higher = seg.getUpperSegmentValue();
				int otherLower = otherSeg.getLowerSegmentValue();
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
			
			//apply the prefix to the sections
			if(first.isPrefixed()) {
				int thisPrefix = first.getNetworkPrefixLength();
				for(int i = 0; i < sections.size(); i++) {
					R section = sections.get(i);
					int bitCount = section.getBitCount();
					int totalPrefix = bitCount;
					for(int j = first.getSegmentCount() - 1; j >= 0 ; j--) {
						IPAddressSegment seg = section.getSegment(j);
						int segBitCount = seg.getBitCount();
						int segPrefix = seg.getMinPrefix();
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
	}
	
	private static <T extends IPAddress, R extends IPAddressSection, S extends IPAddressSegment> R 
			createDiffSection(R original, int lower, int upper, int diffIndex, IPAddressCreator<T, R, ?, S> addrCreator, IntFunction<S> segProducer, S intersectingValues[]) {
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

	/**
	 * Returns whether the given mask and prefix combination can be used to generate a subnet.
	 * See {@link IPAddress#isMaskCompatibleWithRange(IPAddress, Integer)}
	 * 
	 * @param mask
	 * @param networkPrefixLength
	 * @return
	 */
	public boolean isMaskCompatibleWithRange(IPAddressSection mask, Integer networkPrefixLength) {
		IPVersion version = getIPVersion();
		if(!version.equals(mask.getIPVersion())) {
			throw new AddressTypeException(this, mask, "ipaddress.error.typeMismatch");
		}
		int segmentCount = getSegmentCount();
		if(mask.getSegmentCount() != segmentCount) {
			throw new AddressTypeException(this, mask, "ipaddress.error.sizeMismatch");
		}
		if(networkPrefixLength != null && (networkPrefixLength < 0 || networkPrefixLength > getBitCount())) {
			throw new AddressTypeException(this, networkPrefixLength, "ipaddress.error.prefixSize");
		}
		if(isMultiple() && (networkPrefixLength == null || networkPrefixLength > 0)) {
			int bitsPerSegment = getBitsPerSegment();
			if(networkPrefixLength == null) {
				networkPrefixLength = segmentCount * bitsPerSegment;
			}
			for(int i = 0; i < segmentCount; i++, networkPrefixLength -= bitsPerSegment) {
				Integer segmentPrefix = getSegmentPrefixLength(bitsPerSegment, networkPrefixLength);
				IPAddressSegment segment = getSegment(i);
				IPAddressSegment maskSegment = mask.getSegment(i);
				if(!segment.isMaskCompatibleWithRange(maskSegment.getLowerSegmentValue(), segmentPrefix)) {
					return false;
				}
			}
		}
		return true;
	}
	
	/**
	 * Applies the given network prefix bit length.
	 */
	@Override
	public abstract IPAddressSection applyPrefixLength(int networkPrefixLength) throws AddressTypeException;
	
	protected void checkSubnet(int networkPrefixLength) throws AddressTypeException {
		if(networkPrefixLength < 0 || networkPrefixLength > getBitCount()) {
			throw new AddressTypeException(this, networkPrefixLength, "ipaddress.error.prefixSize");
		}
	}

	protected void checkSectionCount(IPAddressSection mask) throws AddressTypeException {
		if(mask.getSegmentCount() != getSegmentCount()) {
			throw new AddressTypeException(this, mask, "ipaddress.error.sizeMismatch");
		}
	}
	
	/**
	 * Returns the CIDR address section for which the range of addresses
	 * in this section is specified using just a single value and a prefix length in the returned section.
	 * 
	 * Otherwise, returns null.
	 * 
	 * If this address represents just a single address, this is returned.
	 * 
	 * @return
	 */
	public IPAddressSection toPrefixedEquivalent() {
		if(!isMultiple()) {
			return this;
		}
		Integer newPrefix = getEquivalentPrefix();
		return newPrefix == null ? null : applyPrefixLength(newPrefix);
	}
	
	/**
	 * Constructs an equivalent address section with the smallest CIDR prefix length possible (largest network),
	 * such that the address represents the exact same range of addresses.
	 * 
	 * @return
	 */
	public IPAddressSection toMinPrefixedEquivalent() {
		return applyPrefixLength(getMinPrefix());
	}
	
	public abstract IPAddressSection removePrefixLength(boolean zeroed);

	@Override
	public abstract IPAddressSection removePrefixLength();

	protected static <R extends IPAddressSection, S extends IPAddressSegment> R removePrefixLength(
			R original, boolean zeroed, boolean onlyPrefixZeroed, IPAddressCreator<?, R, ?, S> creator, IPAddressTypeNetwork<?, R, S> network, SegFunction<R, S> segProducer) { // (section, i) -> section.getSegment(i)
		if(!original.isPrefixed()) {
			return original;
		}
		int maskBitCount;
		if(zeroed) {
			Integer pref = original.getPrefixLength();
			if(onlyPrefixZeroed) {//handle cases like */4 in which zeroing the latter part of the address is not compatible with the initial part of the address having a range
				int segmentIndex = original.getSegmentIndex(pref);
				IPAddressSegment seg = original.getSegment(segmentIndex);
				if(seg.isRangeEquivalentToPrefix()) {
					maskBitCount = pref;
				} else {
					maskBitCount = (segmentIndex + 1) * seg.getBitCount();
				}
			} else {
				maskBitCount = pref;
			}
			
		} else {
			maskBitCount = original.getBitCount();
		}
		R mask = network.getNetworkMaskSection(maskBitCount);
		return getSubnetSegments(original, null, creator, false, i -> segProducer.apply(original, i), i -> segProducer.apply(mask, i));
	}

	@Override
	public IPAddressSection adjustPrefixBySegment(boolean nextSegment) {
		int prefix = getAdjustedPrefix(nextSegment, getBitsPerSegment(), false);
		Integer existing = getNetworkPrefixLength();
		if(existing == null) {
			if(nextSegment ? prefix == getBitCount() : prefix == 0) {
				return this;
			}
		} else if(existing != null && existing == prefix) {
			//remove the prefix from the end
			return removePrefixLength();
		}
		return setPrefixLength(prefix);
	}

	@Override
	public abstract IPAddressSection adjustPrefixLength(int adjustment);
	
	protected static <R extends IPAddressSection, S extends IPAddressSegment> IPAddressSection adjustPrefixLength(
			R original, int adjustment, IPAddressCreator<?, R, ?, S> creator, IPAddressTypeNetwork<?, R, S> network, SegFunction<R, S> segProducer) { // (section, i) -> section.getSegment(i)
		if(adjustment == 0) {
			return original;
		}
		int prefix = original.getAdjustedPrefix(adjustment, false, false);
		
		if(prefix < 0 || prefix > original.getBitCount()) {
			if(!original.isPrefixed()) {
				return original;
			}
			
			int maskBitCount = prefix < 0 ? 0 : original.getPrefixLength();
			R mask = network.getNetworkMaskSection(maskBitCount);
			return getSubnetSegments(original, null, creator, false, i -> segProducer.apply(original, i), i -> segProducer.apply(mask, i));
		}
		return original.setPrefixLength(prefix);
	}

	@Override
	public abstract IPAddressSection setPrefixLength(int prefixLength);

	public abstract IPAddressSection setPrefixLength(int prefixLength, boolean zeroed);

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
	 * Returns the smallest CIDR prefix possible (largest network),
	 * such that this address paired with that prefix represents the exact same range of addresses.
	 *
	 * @see inet.ipaddr.format.IPAddressDivision#getMaskPrefixLength(boolean)
	 * 
	 * @return
	 */
	@Override
	public int getMinPrefix() {
		Integer result;
		if(hasNoPrefixCache() || (result = prefixCache.cachedMinPrefix) == null) {
			prefixCache.cachedMinPrefix = result = super.getMinPrefix();
		}
		return result;
	}
	
	/**
	 * Returns a prefix length for which the range of this address section can be specified only using the section's lower value and the prefix length
	 * 
	 * If no such prefix exists, returns null
	 * If this address section represents a single value, returns the bit length
	 * 
	 * @return the prefix length or null
	 */
	@Override
	public Integer getEquivalentPrefix() {
		if(!hasNoPrefixCache()) {
			Integer result = prefixCache.cachedEquivalentPrefix;
			if(result != null) {
				if(result < 0) {
					return null;
				}
				return result;
			}
		}
		Integer res = super.getEquivalentPrefix();
		if(res == null) {
			prefixCache.cachedEquivalentPrefix = -1;
			return null;
		}
		return prefixCache.cachedEquivalentPrefix = res;
	}
	
	/**
	 * If this represents an address section with ranging values, returns an address section representing the lower values of the range
	 * If this represents an address section with a single value in each segment, returns this.
	 * 
	 * @return
	 */
	@Override
	public abstract IPAddressSection getLower();
	
	/**
	 * If this represents an address section with ranging values, returns an address section representing the upper values of the range
	 * If this represents an address section with a single value in each segment, returns this.
	 * 
	 * @return
	 */
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
	
	/**
	 * @return an array containing the segments
	 */
	@Override
	public abstract IPAddressSegment[] getSegments();

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
		System.arraycopy(divisions, start, segs, destIndex, end - start);
	}
	
	protected static <T extends IPAddress, R extends IPAddressSection, S extends IPAddressSegment> R createSection(IPAddressCreator<T, R, ?, S> creator, S segs[]) {
		return creator.createSectionInternal(segs);
	}
	
	@Override
	public abstract Iterable<? extends IPAddressSection> getIterable();
	
	@Override
	public abstract Iterator<? extends IPAddressSection> iterator();
	
	@Override
	public abstract Iterator<? extends IPAddressSegment[]> segmentsIterator();
	
	public boolean isEntireAddress() {
		return getSegmentCount() == IPAddress.segmentCount(getIPVersion());
	}
	
	////////////////string creation below ///////////////////////////////////////////////////////////////////////////////////////////

	static void checkLengths(int length, StringBuilder builder) {
		IPAddressStringParams.checkLengths(length, builder);
	}
	
	public String[] getSegmentStrings() {
		String result[] = new String[getSegmentCount()];
		for(int i = 0; i < result.length; i++) {
			result[i] = getSegment(i).getWildcardString();
		}
		return result;
	}

	@Override
	public String toString() {
		return toNormalizedString();
	}

	/**
	 * This produces a string with no compressed segments and all segments of full length,
	 * which is 4 characters for IPv6 segments and 3 characters for IPv4 segments.
	 */
	public abstract String toFullString();
	
	
	protected abstract void cacheNormalizedString(String str);
	
	/**
	 * This produces the shortest valid string.
	 * For subnets the string will not have wildcards in host segments (there will be zeros instead), only in network segments.
	 */
	@Override
	public abstract String toCompressedString();
	
	/**
	 * Returns a string with a CIDR prefix length if this section has a network prefix length.
	 * For IPv6, the host section will be compressed with ::, for IPv4 the host section will be zeros.
	 * @return
	 */
	public abstract String toPrefixLengthString();
	
	/**
	 * Produces a consistent subnet string.
	 * 
	 * In the case of IPv4, this means that wildcards are used instead of a network prefix.
	 * In the case of IPv6, a prefix will be used and the host section will be compressed with ::.
	 */
	public abstract String toSubnetString();
	
	/**
	 * This produces a string similar to the normalized string and avoids the CIDR prefix.
	 * CIDR addresses will be shown with wildcards and ranges instead of using the CIDR prefix notation.
	 */
	public abstract String toNormalizedWildcardString();
	
	/**
	 * This produces a string similar to the canonical string and avoids the CIDR prefix.
	 * Addresses with a network prefix length will be shown with wildcards and ranges instead of using the CIDR prefix length notation.
	 * IPv6 addresses will be compressed according to the canonical representation.
	 */
	public abstract String toCanonicalWildcardString();
	
	/**
	 * This is similar to toNormalizedWildcardString, avoiding the CIDR prefix, but with compression as well.
	 */
	public abstract String toCompressedWildcardString();
	
	/**
	 * This is the same as the string from toNormalizedWildcardString except that:
	 * -it uses IPAddress.SEGMENT_SQL_WILDCARD instead of IPAddress.SEGMENT_WILDCARD
	 * -it uses IPAddress.SEGMENT_SQL_SINGLE_WILDCARD
	 */
	public abstract String toSQLWildcardString();
	
	protected abstract IPStringCache getStringCache();
	
	protected abstract boolean hasNoStringCache();
	
	/**
	 * Generates the reverse DNS lookup string
	 * For 8.255.4.4 it is 4.4.255.8.in-addr.arpa
	 * For 2001:db8::567:89ab it is b.a.9.8.7.6.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa
	 * 
	 *
	 * @throw {@link AddressTypeException} if this address is a subnet of multiple addresses
	 * @return
	 */
	public abstract String toReverseDNSLookupString();

	/*
	 * There are two approaches when going beyond the usual segment by segment approach to strings for IPv6 and IPv4.
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
	
	/**
	 * Writes this address section as a single binary value with always the exact same number of characters
	 * 
	 * If this section represents a range of values outside of the network prefix length, then this is printed as a range of two hex values.
	 */
	public String toBinaryString() {
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
	
	/**
	 * Writes this address as a single hexadecimal value with always the exact same number of characters, with or without a preceding 0x prefix.
	 * 
	 * For IPv4 there are 8 hex characters, for IPv6 there are 32 hex characters.
	 * 
	 * If this section represents a range of values outside of the network prefix length, then this is printed as a range of two hex values.
	 */
	public String toOctalString(boolean with0Prefix) {  
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
	
	protected String toOctalString(boolean with0Prefix, CharSequence zone) {
		if(isDualString()) {
			IPAddressSection lower = getLower();
			IPAddressSection upper = getUpper();
			IPAddressBitsDivision lowerDivs[] = lower.createNewDivisions(3, IPAddressBitsDivision::new, IPAddressBitsDivision[]::new);
			IPAddressStringDivisionSeries lowerPart = new IPAddressDivisionGrouping(lowerDivs);
			IPAddressBitsDivision upperDivs[] = upper.createNewDivisions(3, IPAddressBitsDivision::new, IPAddressBitsDivision[]::new);
			IPAddressStringDivisionSeries upperPart = new IPAddressDivisionGrouping(upperDivs);
			return toNormalizedStringRange(toIPParams(with0Prefix ? IPStringCache.octalPrefixedParams : IPStringCache.octalParams), lowerPart, upperPart, zone);
		}
		IPAddressBitsDivision divs[] = createNewPrefixedDivisions(3, getNetworkPrefixLength(), IPAddressBitsDivision::new, IPAddressBitsDivision[]::new);
		IPAddressStringDivisionSeries part = new IPAddressDivisionGrouping(divs);
		return toIPParams(with0Prefix ? IPStringCache.octalPrefixedParams : IPStringCache.octalParams).toString(part, zone);
	}
	
	/**
	 * Writes this address as a single hexadecimal value with always the exact same number of characters, with or without a preceding 0x prefix.
	 * 
	 * For IPv4 there are 8 hex characters, for IPv6 there are 32 hex characters.
	 * 
	 * If this section represents a range of values outside of the network prefix length, then this is printed as a range of two hex values.
	 */
	@Override
	public String toHexString(boolean with0xPrefix) {  
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
	protected String toHexString(boolean with0xPrefix, CharSequence zone) {
		if(isDualString()) {
			return toNormalizedStringRange(toIPParams(with0xPrefix ? IPStringCache.hexPrefixedParams : IPStringCache.hexParams), getLower(), getUpper(), zone);
		}
		return toIPParams(with0xPrefix ? IPStringCache.hexPrefixedParams : IPStringCache.hexParams).toString(this, zone);
	}
	
	public String toNormalizedString(IPStringOptions stringOptions) {
		return toNormalizedString(stringOptions, this);
	}

	public static String toNormalizedString(IPStringOptions opts, IPAddressStringDivisionSeries section) {
		return toIPParams(opts).toString(section);
	}
	
	protected static AddressStringParams<IPAddressStringDivisionSeries> toParams(IPStringOptions opts) {
		//since the params here are not dependent on the section, we could cache the params in the options 
		//this is not true on the IPv6 side where compression settings change based on the section
		
		@SuppressWarnings("unchecked")
		AddressStringParams<IPAddressStringDivisionSeries> result = (AddressStringParams<IPAddressStringDivisionSeries>) getCachedParams(opts);
		if(result == null) {
			result = new IPAddressStringParams<IPAddressStringDivisionSeries>(opts.base, opts.separator, opts.uppercase);
			result.expandSegments(opts.expandSegments);
			result.setWildcards(opts.wildcards);
			result.setSegmentStrPrefix(opts.segmentStrPrefix);
			result.setAddressLabel(opts.addrLabel);
			result.setReverse(opts.reverse);
			result.setSplitDigits(opts.splitDigits);
			result.setRadix(opts.base);
			result.setUppercase(opts.uppercase);
			result.setSeparator(opts.separator);
			result.setZoneSeparator(opts.zoneSeparator);
			setCachedParams(opts, result);
		}
		return result;
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
	
	public abstract IPAddressPartStringCollection toStringCollection(IPStringBuilderOptions options);

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
			WildcardOptions wildcardsRangeOnlyNetworkOnly = new WildcardOptions(WildcardOptions.WildcardOption.NETWORK_ONLY);
			hexParams = new IPStringOptions.Builder(16).setSeparator(null).setExpandedSegments(true).setWildcardOptions(wildcardsRangeOnlyNetworkOnly).toParams();
			hexPrefixedParams = new IPStringOptions.Builder(16).setSeparator(null).setExpandedSegments(true).setWildcardOptions(wildcardsRangeOnlyNetworkOnly).setAddressLabel(IPAddress.HEX_PREFIX).toParams();
			octalParams = new IPStringOptions.Builder(8).setSeparator(null).setExpandedSegments(true).setWildcardOptions(wildcardsRangeOnlyNetworkOnly).toParams();
			octalPrefixedParams = new IPStringOptions.Builder(8).setSeparator(null).setExpandedSegments(true).setWildcardOptions(wildcardsRangeOnlyNetworkOnly).setAddressLabel(IPAddress.OCTAL_PREFIX).toParams();
			binaryParams = new IPStringOptions.Builder(2).setSeparator(null).setExpandedSegments(true).setWildcardOptions(wildcardsRangeOnlyNetworkOnly).toParams();
			canonicalSegmentParams = new IPStringOptions.Builder(10, ' ').toParams();
		}
		
		public String normalizedWildcardString;
		public String fullString;
		public String sqlWildcardString;

		public String reverseDNSString;
		
		public String octalStringPrefixed;
		public String octalString;
		public String binaryString;
	}
	
	public static class WildcardOptions {
		public enum WildcardOption {
			NETWORK_ONLY, //only print wildcards that are part of the network portion
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
			protected WildcardOption wildcardOption;
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
			public IPStringOptions toParams() {
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
