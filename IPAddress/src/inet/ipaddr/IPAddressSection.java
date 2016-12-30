package inet.ipaddr;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.NoSuchElementException;
import java.util.TreeMap;
import java.util.function.BiFunction;
import java.util.function.IntFunction;
import java.util.function.Supplier;

import inet.ipaddr.IPAddress.IPVersion;
import inet.ipaddr.IPAddressSection.WildcardOptions.Wildcards;
import inet.ipaddr.IPAddressTypeNetwork.IPAddressCreator;
import inet.ipaddr.IPAddressTypeNetwork.IPAddressSegmentCreator;
import inet.ipaddr.format.IPAddressDivision;
import inet.ipaddr.format.IPAddressPart;
import inet.ipaddr.format.IPAddressSegmentGrouping;
import inet.ipaddr.format.util.IPAddressPartConfiguredString;
import inet.ipaddr.format.util.IPAddressPartStringCollection;
import inet.ipaddr.format.util.IPAddressPartStringCollection.StringParams;
import inet.ipaddr.format.util.IPAddressPartStringParams;
import inet.ipaddr.format.util.sql.IPAddressSQLTranslator;
import inet.ipaddr.format.util.sql.MySQLTranslator;
import inet.ipaddr.format.util.sql.SQLStringMatcher;
import inet.ipaddr.ipv4.IPv4Address;

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
public abstract class IPAddressSection extends IPAddressSegmentGrouping {
	
	private static final long serialVersionUID = 1L;
	private static final IPAddressPart EMPTY_PARTS[] = new IPAddressPart[0];
	
	/* the address bytes for the lowest value */
	private transient byte[] lowerBytes;

	/* caches objects to avoid recomputing them */
	protected static class SectionCache {
		/* for caching */
		private Integer networkMaskPrefixLen; //null indicates this field not initialized, -1 indicates the prefix len is null
		private Integer hostMaskPrefixLen; //null indicates this field not initialized, -1 indicates the prefix len is null
		
		/* also for caching */
		private Integer cachedMinPrefix; //null indicates this field not initialized
		private Integer cachedEquivalentPrefix; //null indicates this field not initialized, -1 indicates the prefix len is null
		
		public IPAddressSection lowerSection;
		public IPAddressSection upperSection;
	}
	
	protected transient SectionCache sectionCache;
	
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
	
	protected static <S extends IPAddressSegment> S[] toSegments(byte bytes[], int segmentCount, int bytesPerSegment, int bitsPerSegment, IPAddressSegmentCreator<S> creator, Integer networkPrefixLength) {
		return IPAddress.toSegments(bytes, null, segmentCount, bytesPerSegment, bitsPerSegment, creator, networkPrefixLength);
	}
	
	protected static <S extends IPAddressSegment> S[] toCIDRSegments(Integer bits, S segments[], IPAddressSegmentCreator<S> segmentCreator, BiFunction<S, Integer, S> segProducer) {
		segments = segments.clone();
		if(bits != null) {
			for(int i = 0; i < segments.length; i++) {
				S seg = segments[i];
				int bitCount = seg.getBitCount();
				Integer segmentPrefixLength = IPAddressSection.getSegmentPrefixLength(bitCount, bits, i);
				segments[i] = segProducer.apply(seg, segmentPrefixLength);
			}
		}
		return segments;
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
		if(sectionCache == null) {
			sectionCache = new SectionCache();
		}
		if(network) {
			setNetworkMaskPrefix(prefixLen);
		} else {
			setHostMaskPrefix(prefixLen);
		}
		super.initCachedValues(cachedNetworkPrefix, cachedCount);
		sectionCache.cachedMinPrefix = cachedMinPrefix;
		sectionCache.cachedEquivalentPrefix = cachedEquivalentPrefix;
	}
	
	protected static RangeList getNoZerosRange() {
		return IPAddressSegmentGrouping.getNoZerosRange();
	}
	
	protected static RangeList getSingleRange(int index, int len) {
		return IPAddressSegmentGrouping.getSingleRange(index, len);
	}
	
	public abstract int getBitsPerSegment();
	
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
	
	public abstract int getBytesPerSegment();
	
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
		return byteIndex / bytesPerSegment;
	}
	
	protected static int getByteIndex(Integer networkPrefixLength, int byteLength) {
		if(networkPrefixLength == null) {
			return byteLength;
		}
		if(networkPrefixLength < 0 || networkPrefixLength > byteLength * 8) {
			throw new IPAddressTypeException(networkPrefixLength, "ipaddress.error.prefixSize");
		}
		return Math.min((networkPrefixLength - 1) >> 3, byteLength);
	}
	
	public abstract int getByteIndex(Integer networkPrefixLength);
	
	public abstract int getSegmentIndex(Integer networkPrefixLength);
	
	protected abstract IPAddressSegmentCreator<?> getSegmentCreator();
	
	protected abstract IPAddressCreator<?, ?, ?> getAddressCreator();
	
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
			if(hasNoSectionCache() || (prefixLen = sectionCache.networkMaskPrefixLen) == null) {
				prefixLen = setNetworkMaskPrefix(checkForPrefixMask(network));
			}
		} else {
			if(hasNoSectionCache() || (prefixLen = sectionCache.hostMaskPrefixLen) == null) {
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
			prefixLen = sectionCache.hostMaskPrefixLen = -1;
		} else {
			sectionCache.hostMaskPrefixLen = prefixLen;
			sectionCache.networkMaskPrefixLen = -1; //cannot be both network and host mask
		}
		return prefixLen;
	}
	
	private Integer setNetworkMaskPrefix(Integer prefixLen) {
		if(prefixLen == null) {
			prefixLen = sectionCache.networkMaskPrefixLen = -1;
		} else {
			sectionCache.networkMaskPrefixLen = prefixLen;
			sectionCache.hostMaskPrefixLen = -1; //cannot be both network and host mask
		}
		return prefixLen;
	}

	protected static <T extends IPAddress, R extends IPAddressSection, S extends IPAddressSegment>
			R getNetworkSegments(
					R original,
					int networkPrefixLength,
					int networkSegmentCount,
					boolean withPrefixLength,
					IPAddressCreator<T, R, S> creator,
					BiFunction<Integer, Integer, S> segProducer) {
		if(networkPrefixLength < 0 || networkPrefixLength > original.getBitCount()) {
			throw new IPAddressTypeException(original, networkPrefixLength, "ipaddress.error.prefixSize");
		}
		if(original.isNetworkSection(networkPrefixLength, withPrefixLength)) {
			return original;
		}
		int segmentCount = original.getSegmentCount();
		int bitsPerSegment = original.getBitsPerSegment();
		int totalBits = segmentCount * bitsPerSegment;
		if(networkPrefixLength > totalBits) {
			return original;
		}
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
			R getHostSegments(R original, int networkPrefixLength, int networkSegmentCount, IPAddressCreator<T, R, S> creator,
					BiFunction<Integer, Integer, S> segProducer) {
		if(networkPrefixLength < 0 || networkPrefixLength > original.getBitCount()) {
			throw new IPAddressTypeException(original, networkPrefixLength, "ipaddress.error.prefixSize");
		}
		if(original.isHostSection(networkPrefixLength) || networkPrefixLength <= 0) {
			return original;
		}
		int segmentCount = original.getSegmentCount();
		S result[] = creator.createSegmentArray(networkSegmentCount);
		if(networkSegmentCount > 0) {
			int bitsPerSegment = original.getBitsPerSegment();
			for(int i = networkSegmentCount - 1, j = segmentCount - 1; i >= 0; i--, j--) {
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
	
	protected static <T extends IPAddress, R extends IPAddressSection, S extends IPAddressSegment> R getSubnetSegments(
			R original,
			R maskSection,
			Integer networkPrefixLength,
			IPAddressCreator<T, R, S> creator,
			boolean verifyMask,
			IntFunction<S> segProducer,
			IntFunction<S> maskSegProducer) {
		if(networkPrefixLength != null && (networkPrefixLength < 0 || networkPrefixLength > original.getBitCount())) {
			throw new IPAddressTypeException(original, networkPrefixLength, "ipaddress.error.prefixSize");
		}
		int i=0;
		int bitsPerSegment = original.getBitsPerSegment();
		for(; i < original.getSegmentCount(); i++) {
			Integer segmentPrefixLength = getSegmentPrefixLength(bitsPerSegment, networkPrefixLength, i);
			S seg = segProducer.apply(i);
			S mask = maskSegProducer.apply(i);
			if(seg.isChangedByMask(mask.getLowerSegmentValue(), segmentPrefixLength)) {
				S newSegments[] = creator.createSegmentArray(original.getSegmentCount());
				original.copySegments(0, i, newSegments, 0);
				for(int j = i; j < original.getSegmentCount(); j++) {
					segmentPrefixLength = getSegmentPrefixLength(bitsPerSegment, networkPrefixLength, j);
					seg  = segProducer.apply(j);
					mask = maskSegProducer.apply(j);
					int maskValue = mask.getLowerSegmentValue();
					if(j > i && !seg.isChangedByMask(maskValue, segmentPrefixLength)) {
						newSegments[j] = seg;
					} else {
						if(verifyMask && !seg.isMaskCompatibleWithRange(maskValue, segmentPrefixLength)) {
							throw new IPAddressTypeException(seg, mask, "ipaddress.error.maskMismatch");
						}
						newSegments[j] = creator.createSegment(seg.getLowerSegmentValue() & maskValue, seg.getUpperSegmentValue() & maskValue, segmentPrefixLength);
					}
				}
				return creator.createSectionInternal(newSegments);
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
	public static Integer getSegmentPrefixLength(int bitsPerSegment, Integer networkPrefixLength, int segmentIndex) {
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
	public static Integer getSegmentPrefixLength(int bitsPerSegment, int segmentBits) {
		if(segmentBits <= 0) {
			return 0; //none of the bits in this segment matter
		} else if(segmentBits <= bitsPerSegment) {
			return segmentBits;//some of the bits in this segment matter
		}
		return null; //all the bits in this segment matter
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
	
	/**
	 * @throws IPAddressTypeException if this address does not map to a single address.
	 * If you want to get subnet bytes or mask bytes, call getLowestBytes
	 */
	public byte[] getBytes() {
		if(isMultiple()) {
			throw new IPAddressTypeException(this, "ipaddress.error.unavailable.numeric");
		}
		return getLowestBytes();
	}
	
	/**
	 * Gets the bytes for the lowest address in the range represented by this address.
	 * 
	 * @return
	 */
	public byte[] getLowestBytes() {
		if(lowerBytes == null) {
			setBytes(getBytesImpl(true));
		}
		return lowerBytes.clone();
	}
	
	void setBytes(byte bytes[]) {
		lowerBytes = bytes;
	}
	
	private byte[] getBytesImpl(boolean low) {
		int bytesPerSegment = getBytesPerSegment();
		int byteCount = getSegmentCount() * bytesPerSegment;
	 	byte bytes[] = new byte[byteCount];
		for(int i = 0, n = 0; i < byteCount; i += bytesPerSegment, n++) {
			IPAddressSegment seg = getSegment(n);
			int segmentValue = low ? seg.getLowerSegmentValue() : seg.getUpperSegmentValue();
			int k = bytesPerSegment + i;
			for(int j = k - 1; ; j--) {
				bytes[j] = (byte) (0xff & segmentValue);
				if(j <= i) {
					break;
				}
				segmentValue >>= 8;
			}
		}
		return bytes;
	}
	
	public int getSegmentCount() {
		return getDivisionCount();
	}
	
	public IPAddressSegment getSegment(int index) {
		return (IPAddressSegment) divisions[index];
	}
	
	public void copySegments(int start, int end, IPAddressSegment segs[], int index) {
		System.arraycopy (divisions, start, segs, index, end - start);
	}

	/**
	 * 
	 * @return whether this section in decimal appears the same as this segment in octal.
	 * 	This is true if all the values lies between 0 and 8 (so the octal and decimal values are the same)
	 */
	public static boolean isDecimalSameAsOctal(boolean checkRange, IPAddressPart part) {
		int count = part.getDivisionCount();
		for(int i = 0; i < count; i++) {
			IPAddressDivision seg = part.getDivision(i);
			if(!checkRange ? seg.rangeIsWithin(0, 7) : seg.valueIsWithin(0, 7)) {
				return false;
			}
		}
		return true;	
	}
	
	public boolean isContainedBy(IPAddressSection other) {
		return other.contains(this);
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
	
	/**
	 * Subtract the give subnet from this subnet, returning an array of sections for the result (the subnets will not be contiguous so an array is required).
	 * 
	 * Computes the subnet difference, the set of addresses in this address section but not in the provided section.
	 * 
	 * Keep in mind this is set subtraction, not subtraction of segment values.  We have a subnet of addresses and we are removing some of those addresses.
	 * 
	 * @param other
	 * @throws IPAddressTypeException if the two sections are not comparable
	 * @return the difference
	 */
	public abstract IPAddressSection[] subtract(IPAddressSection other);
	
	protected static <T extends IPAddress, R extends IPAddressSection, S extends IPAddressSegment> R[] 
			subtract(R first, R other, IPAddressCreator<T, R, S> addrCreator, IntFunction<S> segProducer, BiFunction<R, Integer, R> prefixApplier) {
		//check if they are comparable first
		int segCount = first.getSegmentCount();
		if(segCount != other.getSegmentCount()) {
			throw new IPAddressTypeException(first, other, "ipaddress.error.sizeMismatch");
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
			createDiffSection(R original, int lower, int upper, int diffIndex, IPAddressCreator<T, R, S> addrCreator, IntFunction<S> segProducer, S intersectingValues[]) {
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
			throw new IPAddressTypeException(this, mask, "ipaddress.error.typeMismatch");
		}
		int segmentCount = getSegmentCount();
		if(mask.getSegmentCount() != segmentCount) {
			throw new IPAddressTypeException(this, mask, "ipaddress.error.sizeMismatch");
		}
		if(networkPrefixLength != null && (networkPrefixLength < 0 || networkPrefixLength > getBitCount())) {
			throw new IPAddressTypeException(this, networkPrefixLength, "ipaddress.error.prefixSize");
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
	 * Creates a subnet address using the given mask. 
	 */
	public abstract IPAddressSection toSubnet(IPAddressSection mask) throws IPAddressTypeException;
	
	/**
	 * Creates a subnet address using the given CIDR prefix bits.
	 */
	public abstract IPAddressSection toSubnet(int networkPrefixLength) throws IPAddressTypeException;
	
	protected void checkSubnet(int networkPrefixLength) throws IPAddressTypeException {
		if(networkPrefixLength < 0 || networkPrefixLength > getBitCount()) {
			throw new IPAddressTypeException(this, networkPrefixLength, "ipaddress.error.prefixSize");
		}
	}
	
	/**
	 * Creates a subnet address using the given mask.  If networkPrefixLength is non-null, applies the prefix length as well.
	 * @throws IPAddressTypeException if the mask is not compatible, see {@link IPAddress#isMaskCompatibleWithRange(IPAddress, Integer)}
	 */
	public abstract IPAddressSection toSubnet(IPAddressSection mask, Integer networkPrefixLength) throws IPAddressTypeException;
	
	protected void checkSubnet(IPAddressSection mask, Integer networkPrefixLength) throws IPAddressTypeException {
		int segmentCount = getSegmentCount();
		if(mask.getSegmentCount() != segmentCount) {
			throw new IPAddressTypeException(this, mask, "ipaddress.error.sizeMismatch");
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
		return newPrefix == null ? null : toSubnet(newPrefix);
	}
	
	/**
	 * Constructs an equivalent address section with the smallest CIDR prefix length possible (largest network),
	 * such that the address represents the exact same range of addresses.
	 * 
	 * @return
	 */
	public IPAddressSection toMinimalPrefixed() {
		return toSubnet(getMinPrefix());
	}
	
	/**
	 * Return an address section for the network encompassing this address section.  
	 * The bits indicate the number to reduce the network bits in the network address in comparison to this address.
	 * 
	 * @param prefixLengthDecrement the number to reduce the network bits in order to create a larger network.  
	 * 	If null, then this method has the same behaviour as toSupernet()
	 * @return
	 */
	public IPAddressSection toSupernet(Integer prefixLengthDecrement) {
		int newPrefix = getSupernetPrefix(prefixLengthDecrement);
		return toSubnet(newPrefix);
	}
	
	/**
	 * Return an address section for the network encompassing this address section,
	 * with the network portion of the returned address extending to the furthest segment boundary
	 * located entirely within but not matching the network portion of this address,
	 * unless the network portion has no bits in which case the same address is returned.  
	 * 
	 * @return the encompassing network
	 */
	public IPAddressSection toSupernet() {
		return toSupernet(null);
	}
	
	int getSupernetPrefix(Integer prefixLengthDecrement) {
		int bits;
		Integer prefix = getNetworkPrefixLength();
		if(prefixLengthDecrement == null) {
			int bitsPerSegment = getBitsPerSegment();
			if(prefix == null) {
				bits = bitsPerSegment;
			} else {
				int adjustment = prefix % bitsPerSegment;
				bits = (adjustment > 0) ? adjustment : bitsPerSegment;
			}
		} else {
			bits = prefixLengthDecrement;
		}
		int newPrefix;
		if(prefix == null) {
			prefix = getBitCount();
		}
		if(prefix <= bits) {
			newPrefix = 0;
		} else {
			newPrefix = prefix - bits;
		}
		return newPrefix;
	}
	
	protected boolean hasNoSectionCache() {
		if(sectionCache == null) {
			synchronized(this) {
				if(sectionCache == null) {
					sectionCache = new SectionCache();
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
	public int getMinPrefix() {
		Integer result;
		if(hasNoSectionCache() || (result = sectionCache.cachedMinPrefix) == null) {
			int totalPrefix = getBitCount();
			for(int i = getSegmentCount() - 1; i >= 0 ; i--) {
				IPAddressSegment seg = getSegment(i);
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
			sectionCache.cachedMinPrefix = result = totalPrefix;
		}
		return result;
	}
	
	/**
	 * Returns a prefix length for which the range of this address section can be specified only using the section's lower value and the prefix length
	 * 
	 * If no such prefix exists, returns null
	 * If this address section represents a single value, returns the bit length
	 * 
	 * @return
	 */
	public Integer getEquivalentPrefix() {
		if(!hasNoSectionCache()) {
			Integer result = sectionCache.cachedEquivalentPrefix;
			if(result != null) {
				if(result < 0) {
					return null;
				}
				return result;
			}
		}
		int totalPrefix = 0;
		for(int i = 0; i < getSegmentCount(); i++) {
			IPAddressSegment seg = getSegment(i);
			int segPrefix = seg.getMinPrefix();
			if(!seg.isRangeEquivalent(segPrefix)) {
				sectionCache.cachedEquivalentPrefix = -1;
				return null;
			}
			if(seg.isPrefixed()) {
				return sectionCache.cachedEquivalentPrefix = totalPrefix + segPrefix;
			}
			if(segPrefix < seg.getBitCount()) {
				//remaining segments must be full range or we return null
				for(i++; i < getSegmentCount(); i++) {
					IPAddressSegment laterSeg = getSegment(i);
					if(!laterSeg.isFullRange()) {
						sectionCache.cachedEquivalentPrefix = -1;
						return null;
					}
				}
				return sectionCache.cachedEquivalentPrefix = totalPrefix + segPrefix;
			}
			totalPrefix += segPrefix;
		}
		return sectionCache.cachedEquivalentPrefix = totalPrefix;
	}
	
	/**
	 * If this represents an address section with ranging values, returns an address section representing the lower values of the range
	 * If this represents an address section with a single value in each segment, returns this.
	 * 
	 * @return
	 */
	public abstract IPAddressSection getLowerSection();
	
	/**
	 * If this represents an address section with ranging values, returns an address section representing the upper values of the range
	 * If this represents an address section with a single value in each segment, returns this.
	 * 
	 * @return
	 */
	public abstract IPAddressSection getUpperSection();
	
	/**
	 * If this represents an address section with ranging values, returns an array of address segments representing the lower values of the range
	 * If this represents an address section with a single value in each segment, returns an array containing the segments for this section.
	 * 
	 * @return
	 */
	public abstract IPAddressSegment[] getLowerSegments();
	
	
	/**
	 * If this represents an address section with ranging values, returns an an array of address segments representing the upper values of the rang
	 * If this represents an address section with a single value in each segment, returns an array containing the segments for this section.
	 * 
	 * @return
	 */
	public abstract IPAddressSegment[] getUpperSegments();
	
	/**
	 * @return an array containing the segments
	 */
	public abstract IPAddressSegment[] getSegments();
	
	protected static <R extends IPAddressSection, S extends IPAddressSegment> S[] getSingle(
			R original, S originalSegs[], IPAddressSegmentCreator<S> segmentCreator, IntFunction<S> segProducer, boolean allowTheseSegments) {
		if(!original.isPrefixed() && !original.isMultiple()) {
			if(allowTheseSegments) {
				return originalSegs;
			}
			return originalSegs.clone();//if the array becomes public, we must clone it
		}
		return createSingle(original, segmentCreator, segProducer);
	}
	
	protected static <R extends IPAddressSection, S extends IPAddressSegment> S[] createSingle(R original, IPAddressSegmentCreator<S> segmentCreator, IntFunction<S> segProducer) {
		int segmentCount = original.getSegmentCount();
		S segs[] = segmentCreator.createSegmentArray(segmentCount);
		for(int i = 0; i < segmentCount; i++) {
			segs[i] = segProducer.apply(i);
		}
		return segs;
	}
	
	protected static <T extends IPAddress, R extends IPAddressSection, S extends IPAddressSegment> R createSection(IPAddressCreator<T, R, S> creator, S segs[]) {
		return creator.createSectionInternal(segs);
	}
	
	protected static <R extends IPAddressSection> R getSingle(R original, Supplier<R> singleFromMultipleCreator) {
		if(!original.isPrefixed() && !original.isMultiple()) {
			return original;
		}
		return singleFromMultipleCreator.get();
	}
	
	public abstract Iterator<? extends IPAddressSection> sectionIterator();
	
	protected static class SectionIterator<T extends IPAddress, R extends IPAddressSection, S extends IPAddressSegment> implements Iterator<R> {
		private Iterator<S[]> iterator;
		private IPAddressCreator<T, R, S> creator;
		private R original;
		
		public SectionIterator(R original, IPAddressCreator<T, R, S> creator, Iterator<S[]> iterator) {
			this.original = original;
			this.iterator = iterator;
			this.creator = creator;
		}

		@Override
		public R next() {
			if(original != null) {
				R result = original;
	    		original = null;
		    	return result;
	    	}
			if(!iterator.hasNext()) {
	    		throw new NoSuchElementException();
	    	}
			S next[] = iterator.next();
	    	return creator.createSectionInternal(next);
	    }

		@Override
		public boolean hasNext() {
			return original != null || iterator.hasNext();
		}

	    @Override
		public void remove() {
	    	throw new UnsupportedOperationException();
	    }
	};
	
	public abstract Iterator<? extends IPAddressSegment[]> iterator();
	
	protected <S extends IPAddressSegment> Iterator<S[]> iterator(
			IPAddressSegmentCreator<S> segmentCreator,
			boolean skipThis,
			Supplier<S[]> segs,
			IntFunction<Iterator<S>> segIteratorProducer) {
		if(!isMultiple()) {
			return new Iterator<S[]>() {
				boolean done = skipThis;
				
				@Override
				public boolean hasNext() {
					return !done;
				}

			    @Override
				public S[] next() {
			    	if(done) {
			    		throw new NoSuchElementException();
			    	}
			    	done = true;
			    	return segs.get();
			    }

			    @Override
				public void remove() {
			    	throw new UnsupportedOperationException();
			    }
			};
		}

		return new Iterator<S[]>() {
			private boolean done;
			final int segmentCount = getSegmentCount();
			
			@SuppressWarnings("unchecked")
			private final Iterator<S> variations[] = new Iterator[segmentCount];
			
			private S nextSet[] = segmentCreator.createSegmentArray(segmentCount);  {
				updateVariations(0);
				if(skipThis) {
					increment();
				}
			}
			
			private void updateVariations(int start) {
				for(int i = start; i < segmentCount; i++) {
					variations[i] = segIteratorProducer.apply(i);
					nextSet[i] = variations[i].next();
				}
			}
			
			@Override
			public boolean hasNext() {
				return !done;
			}
			
		    @Override
			public S[] next() {
		    	if(done) {
		    		throw new NoSuchElementException();
		    	}
		    	S segs[] = nextSet.clone();
		    	increment();
		    	return segs;
		    }
		    
		    private void increment() {
		    	for(int j = segmentCount - 1; j >= 0; j--) {
		    		if(variations[j].hasNext()) {
		    			nextSet[j] = variations[j].next();
		    			updateVariations(j + 1);
		    			return;
		    		}
		    	}
		    	done = true;
		    }

		    @Override
			public void remove() {
		    	throw new UnsupportedOperationException();
		    }
		};
	}
	
	public boolean isEntireAddress() {
		return getSegmentCount() == IPAddress.segmentCount(getIPVersion());
	}
	
	////////////////string creation below ///////////////////////////////////////////////////////////////////////////////////////////

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
	 * This produces a canonical string.
	 * 
	 * RFC 5952 describes canonical representations.
	 * http://en.wikipedia.org/wiki/IPv6_address#Recommended_representation_as_text
	 * http://tools.ietf.org/html/rfc5952
	 */
	public abstract String toCanonicalString();

	/**
	 * This produces a string with no compressed segments and all segments of full length,
	 * which is 4 characters for IPv6 segments and 3 characters for IPv4 segments.
	 */
	public abstract String toFullString();
	
	/**
	 * The normalized string returned by this method is consistent with java.net.Inet4Address and java.net.Inet6address.
	 * IPs are not compressed nor mixed in this representation.
	 */
	public abstract String toNormalizedString();
	
	protected abstract void cacheNormalizedString(String str);
	
	/**
	 * This produces the shortest valid string.
	 * For subnets the string will not have wildcards in host segments (there will be zeros instead), only in network segments.
	 */
	public abstract String toCompressedString();
	
	/**
	 * Returns a string with a CIDR prefix length if this section has a network prefix length.
	 * For IPv6, the host section will be compressed with ::, for IPv4 the host section will be zeros.
	 * @return
	 */
	public abstract String toNetworkPrefixLengthString();
	
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
	
	
	protected abstract StringCache getStringCache();
	
	protected abstract boolean hasNoStringCache();
	
	/*
	 * There are two approaches when going beyond the usual segment by segment approach to strings for IPv6 and IPv4.
	 * We can use the inet_aton approach, creating new segments as desired (one, two or three segments instead of the usual 4).
	 * Then each such segment must simply know it's own sizes, whether bits, bytes, or characters, as IPAddressJoinedSegments and its subclasses show.
	 * The limitations to this are the fact that arithmetic is done with Java longs, limiting the possible sizes.  Also, we must define new classes to accommodate the new segments.
	 * A con to this approach is that the new segments may be short lived, so any caching is not helpful.
	 * 
	 * The second approach is to print with no separator chars (no '.' or ':') and with leading zeros, but otherwise print in the same manner.
	 * So 1:2 would become 00010002.  
	 * This works in cases where the string character boundaries line up with the segment boundaries.
	 * This works for hexadecimal, where each segment is exactly two characters for IPv4, and each segment is exactly 4 characters for IPv6.
	 * For other radices, this is not so simple.
	 * 
	 * A hybrid approach would use both approaches.  For instance, for octal we could simply divide into segments where each segment has 6 bits,
	 * corresponding to exactly two octal characters, or each segment has some multiple of 3 bits.  It helps if the segment bit length
	 * divides the total bit length, so the first segment does not end up with too many leading zeros.  
	 * In the cases where the above approaches do not work, this approach works.
	 */
	/*
	 * TODO let's do octal using hybrid.  You want a single segment of just 2 bits, then a segment of 30 bits, for IPv4.  For IPv6, 63, 63, 2, or 30,30,30,30,3,3,2
	 * Need the same initial test isDualString.  Almost all the work is in the new segment classes.
	 * 
	 * base 85: how do we do that?  not a power of 2.  Cannot split easily.  128 is nearest power of 2, 7 bits.
	 * But we do not need an exact bit match, that is just useful for using shift arithmetic.
	 * All we need is a sensible distribution. Long.MAX is less than 85 to the power of 9, greater than 85 to the power of 8.  So we can put 8 base 85 digits in a long.
	 * So we choose 2 segments of 8 digits and one more of 4 digits.
	 * Still, this is awkward arithmetic, it's not like we can take the entire number of just divide by 85 to the power of 8.
	 * 
	 * http://www.numberworld.org/y-cruncher/internals/radix-conversion.html
	 * 
	 * N = 32, M = 20, b = 85
X is a 32 digit number base 16 
Want a 20 digit number R in base 85

Compute
high = floor(X / (85 ^ 10))  where we got 10 as 20/2
low = X - ((85 ^ 10) * high)

This give two numbers to be converted to 10 digits each

Do this again on each of high and low

high2 = floor(Y / (85 ^ 5))
low2 = Y - ((85 ^ 5) * high)

So now we have 4 sections of 5 base 85 digits

These are still too large for ints, which makes sense since the original 128 bits divided into 4 sections is 32 bits
which is slightly too large for a signed int.

But we can use our optimized IPAddressDivision algorith anyway which does its own switching over to ints.

So I'd say we convert the 128 bit integer to a BigInteger, then we divide into 4 segments as above.  4 segments, each responsible for 5 base 85 chars.
Each will be similar to IPAddressJoinedSegments but this time no joining taking place.  The bit count will be 32 for each.
In fact, I don't think I need to do any division, or do I?  This is a bit confusing.  In fact, not sure about the bit count.
85^5 is 4,437,053,125
2^32 is 4,294,967,296
So the bit count doesn't align with the segments.
So IPAddressDivision, as is, does not quite align perfectly either.

One option is to move stuff from IPAddressDivision to IPaddresssegment if we can.
Move getMaskPrefixLength, isMaskCompatibleWithRange...  Not sure this is feasible.  We have the prefix, which is bit-focused, integrated into the string generation.
There is no number of bits that aligns with a base 85 set of digits, except when we have just one segment, in which case long no good.

OR, even if they do not align perfectly, each number of bits corresponds to a segment.  But there is still no "bit count" for each one.

It may be easiest to just not use IPAddressDivision but to use static methods within it.  The fact is, we cannot align bits or prefixes to 
pieces of the base 85 address of 20 chars.  We would need a simplified pair of string params and divisions that did not have bits or prefixes.
In fact, the string params themselbes are fine.
Maybe we can just reuse everything with the rpefix stuff not working?
How do we even know what the prefix is if we do not have it stored in the segments.

More and MOre I think I need to reuse existing string params, but just use a single division for all 32 bits.
Then the prefix and so on makes sense.  Those things operate on IPAddressPart.
Each part provides a division.  We need to break up division so it is not long-based.
We wanted to do the same for Mac Address!  The reason was to drop the prefix, not to drop the "long".
But we wanted to support mac address prefixes too, in some ways they are similar.

OK, so that means we change "networkPrefixLength" to just prefixLength
In which case IPAddressPart can be change to AddressPart
Then we need to change IPAddressDivision to be conformant to both mac and to base 85

	 */
	

	/**
	 * Writes this address as a single hexadecimal value with always the exact same number of characters, with or without a preceding 0x prefix.
	 * 
	 * For IPv4 there are 8 hex characters, for IPv6 there are 32 hex characters.
	 * 
	 * If this section represents a range of values outside of the network prefix length, then this is printed as a range of two hex values.
	 */
	public String toHexString(boolean withPrefix) {  
		String result;
		if(hasNoStringCache() || (result = (withPrefix ? getStringCache().hexStringPrefixed : getStringCache().hexString)) == null) {
			result = toHexString(withPrefix, null);
			if(withPrefix) {
				getStringCache().hexStringPrefixed = result;
			} else {
				getStringCache().hexString = result;
			}
		}
		return result;
	}
	
	private boolean isDualString() {
		int count = getSegmentCount();
		for(int i = 0; i < count; i++) {
			IPAddressSegment segment = getSegment(i);
			if(!segment.isRangeEquivalentToPrefix()) {
				boolean isLastFull = true;
				IPAddressSegment lastSegment = null;
				for(int j = count - 1; j >= 0; j--) {
					segment = getSegment(j);
					if(segment.isMultiple()) {
						if(!isLastFull) {
							throw new IPAddressTypeException(segment, i, lastSegment, i + 1, "ipaddress.error.segmentMismatch");
						}
						isLastFull = segment.isFullRange();
					} else {
						isLastFull = false;
					}
					lastSegment = segment;
				}
				return true;
			}
		}
		return false;
	}
	
	protected String toHexString(boolean withPrefix, String zone) {
		if(isDualString()) {
			return toNormalizedStringRange(withPrefix ? StringCache.hexPrefixedParams : StringCache.hexParams, zone);
		}
		return toNormalizedString(withPrefix ? StringCache.hexPrefixedParams : StringCache.hexParams);
	}
	
	protected static StringParams<IPAddressPart> toParams(StringOptions opts) {
		//since the params here are not dependent on the section, we could cache the params in the options 
		//this is not true on the IPv6 side where compression settings change based on the section
		@SuppressWarnings("unchecked")
		StringParams<IPAddressPart> result = (StringParams<IPAddressPart>) getCachedParams(opts);
		if(result == null) {
			result = new StringParams<IPAddressPart>(opts.base, opts.separator, opts.uppercase);
			result.expandSegments(opts.expandSegments);
			result.setWildcardOption(opts.wildcardOptions);
			result.setSegmentStrPrefix(opts.segmentStrPrefix);
			result.setAddressSuffix(opts.addrSuffix);
			result.setAddressLabel(opts.addrPrefix);
			result.setReverse(opts.reverse);
			result.setSplitDigits(opts.splitDigits);
			setCachedParams(opts, result);
		}
		return result;
	}
	
	protected String toNormalizedStringRange(StringOptions stringOptions, String zone) {
		IPAddressPart part1 = getLowerSection(), part2 = getUpperSection();
		StringParams<IPAddressPart> params = toParams(stringOptions);
		int length = params.getStringLength(part1) + params.getStringLength(part2);
		StringBuilder builder;
		String separator = params.getWildcardOption().wildcards.rangeSeparator;
		if(separator != null) {
			length += separator.length();
			builder = new StringBuilder(length);
			params.append(params.append(builder, part1).append(separator), part2);
		} else {
			builder = new StringBuilder(length);
			params.append(params.append(builder, part1), part2);
		}
		params.checkLengths(length, builder);
		return builder.toString();
	}
	
	//this is overridden in the IPv6 subclass to handle the zone which is IPv6 only
	protected String toNormalizedString(StringOptions stringOptions, String zone) {
		return toNormalizedString(stringOptions);
	}
	
	public String toNormalizedString(StringOptions stringOptions) {
		return toNormalizedString(stringOptions, this);
	}

	public static String toNormalizedString(StringOptions opts, IPAddressPart section) {
		return toParams(opts).toString(section);
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
	 * <li>alternative segment groupings expressed as IPAddressSegmentGrouping</li>
	 * <li>conversions to IPv6, and alternative representations of those IPv6 addresses</li>
	 * </ul>
	 * 
	 * @param options
	 * @return
	 */
	public IPAddressPart[] getParts(IPStringBuilderOptions options) {
		if(options.includes(IPStringBuilderOptions.BASIC)) {
			return new IPAddressPart[] { this };
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
			Iterator<? extends IPAddressSection> sectionIterator = sectionIterator();
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
	protected static class StringCache {
		public static final StringOptions hexParams;
		public static final StringOptions hexPrefixedParams;
		
		static {
			WildcardOptions wildcardsRangeOnlyNetworkOnly = new WildcardOptions(WildcardOptions.WildcardOption.NETWORK_ONLY, new Wildcards(IPAddress.RANGE_SEPARATOR_STR));
			hexParams = new StringOptions.Builder().setSeparator(null).setExpandedSegments(true).setWildcardOptions(wildcardsRangeOnlyNetworkOnly).setRadix(16).toParams();
			hexPrefixedParams = new StringOptions.Builder().setSeparator(null).setExpandedSegments(true).setWildcardOptions(wildcardsRangeOnlyNetworkOnly).setRadix(16).setAddressPrefix("0x").toParams();
		}
		
		public String canonicalString;
		public String normalizedWildcardString;
		public String fullString;
		public String sqlWildcardString;
		public String hexString;
		public String hexStringPrefixed;
		
		//we piggy-back on the section cache for strings that are full address only
		public String reverseDNSString;
	}
	
	public static class WildcardOptions {
		public enum WildcardOption {
			NETWORK_ONLY, //only print wildcards that are part of the network portion
			ALL //print wildcards for any non-compressed segments
		}
		
		public final WildcardOption wildcardOption;
		public final Wildcards wildcards;
		
		public static class Wildcards {
			public final String rangeSeparator;//cannot be null
			public final String wildcard;//can be null
			public final String singleWildcard;//can be null
			
			public Wildcards() {
				this(IPAddress.RANGE_SEPARATOR_STR, IPAddress.SEGMENT_WILDCARD_STR, null);
			}
			
			public Wildcards(String wildcard, String singleWildcard) {
				this(IPAddress.RANGE_SEPARATOR_STR, wildcard, singleWildcard);
			}
			
			public Wildcards(String rangeSeparator) {
				this(rangeSeparator, null, null);
			}
			
			public Wildcards(String rangeSeparator, String wildcard, String singleWildcard) {
				if(rangeSeparator == null) {
					rangeSeparator = IPAddress.RANGE_SEPARATOR_STR;
				}
				this.rangeSeparator = rangeSeparator;
				this.wildcard = wildcard;
				this.singleWildcard = singleWildcard;
			}
		}
		
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
	
	protected static IPAddressPartStringParams<?> getCachedParams(StringOptions opts) {
		return opts.cachedParams;
	}
	
	protected static void setCachedParams(StringOptions opts, IPAddressPartStringParams<?> cachedParams) {
		opts.cachedParams = cachedParams;
	}
	
	/**
	 * Represents a clear way to create a specific type of string.
	 * 
	 * @author sfoley
	 */
	public static class StringOptions {
		public final WildcardOptions wildcardOptions;
		public final boolean expandSegments;
		public final int base;
		public final String segmentStrPrefix;
		public final Character separator;
		public final String addrSuffix;
		public final String addrPrefix;
		public final boolean reverse;
		public final boolean splitDigits;
		public final boolean uppercase;
		
		//use this field if the options to params conversion is not dependent on the address part so it can be reused
		IPAddressPartStringParams<?> cachedParams; 
		
		protected StringOptions(
				int base,
				boolean expandSegments,
				WildcardOptions wildcardOptions,
				String segmentStrPrefix,
				Character separator,
				String prefix,
				String suffix,
				boolean reverse,
				boolean splitDigits,
				boolean uppercase) {
			this.expandSegments = expandSegments;
			this.wildcardOptions = wildcardOptions;
			this.base = base;
			this.segmentStrPrefix = segmentStrPrefix;
			this.separator = separator;
			this.addrSuffix = suffix;
			this.addrPrefix = prefix;
			this.reverse = reverse;
			this.splitDigits = splitDigits;
			this.uppercase = uppercase;
		}
		
		public static class Builder {
			public static final WildcardOptions DEFAULT_WILDCARD_OPTIONS = new WildcardOptions();
		
			protected WildcardOptions wildcardOptions = DEFAULT_WILDCARD_OPTIONS;
			protected boolean expandSegments;
			protected int base;
			protected String segmentStrPrefix;
			protected Character separator;
			protected String addrPrefix = "";
			protected String addrSuffix = "";
			protected boolean reverse;
			protected boolean splitDigits;
			protected boolean uppercase;
			
			public Builder() {
				this(IPv4Address.DEFAULT_TEXTUAL_RADIX, IPv4Address.SEGMENT_SEPARATOR);
			}
			
			protected Builder(int base, char separator) {
				this.base = base;
				this.separator = separator;
			}
			
			public Builder setWildcardOptions(WildcardOptions wildcardOptions) {
				this.wildcardOptions = wildcardOptions;
				return this;
			}
			
			public Builder setReverse(boolean reverse) {
				this.reverse = reverse;
				return this;
			}
			
			public Builder setUppercase(boolean uppercase) {
				this.uppercase = uppercase;
				return this;
			}
			public Builder setSplitDigits(boolean splitDigits) {
				this.splitDigits = splitDigits;
				return this;
			}
			
			public Builder setExpandedSegments(boolean expandSegments) {
				this.expandSegments = expandSegments;
				return this;
			}
			
			public Builder setRadix(int base) {
				this.base = base;
				return this;
			}
			
			/*
			 * separates the divisions of the address, typically ':' or '.', but also can be null for no separator
			 */
			public Builder setSeparator(Character separator) {
				this.separator = separator;
				return this;
			}
			
			public Builder setAddressPrefix(String prefix) {
				this.addrPrefix = prefix;
				return this;
			}
			
			/*
			 * .in-addr.arpa, .ip6.arpa, .ipv6-literal.net are examples of suffixes tacked onto the end of address strings
			 */
			public Builder setAddressSuffix(String suffix) {
				this.addrSuffix = suffix;
				return this;
			}
			
			public Builder setSegmentStrPrefix(String prefix) {
				this.segmentStrPrefix = prefix;
				return this;
			}
			
			public StringOptions toParams() {
				return new StringOptions(base, expandSegments, wildcardOptions, segmentStrPrefix, separator, addrPrefix, addrSuffix, reverse, splitDigits, uppercase);
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
			TreeMap<Integer, String> options = new TreeMap<Integer, String>();
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
