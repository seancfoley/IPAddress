package inet.ipaddr;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.math.BigInteger;
import java.util.Collection;
import java.util.Iterator;
import java.util.NoSuchElementException;
import java.util.TreeMap;

import inet.ipaddr.IPAddress.IPVersion;
import inet.ipaddr.IPAddressTypeNetwork.IPAddressCreator;
import inet.ipaddr.IPAddressTypeNetwork.IPAddressSegmentCreator;
import inet.ipaddr.format.IPAddressDivision;
import inet.ipaddr.format.IPAddressPart;
import inet.ipaddr.format.IPAddressSegmentGrouping;
import inet.ipaddr.format.util.IPAddressPartConfiguredString;
import inet.ipaddr.format.util.IPAddressPartStringCollection;
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
	
	/* for caching */
	private transient Integer networkMaskPrefixLen; //null indicates this field not initialized, -1 indicates the prefix len is null
	private transient Integer hostMaskPrefixLen; //null indicates this field not initialized, -1 indicates the prefix len is null
	
	/* also for caching */
	private transient Integer cachedMinPrefix; //null indicates this field not initialized
	private transient Integer cachedEquivalentPrefix; //null indicates this field not initialized, -1 indicates the prefix len is null
	
	/* the address bytes for the lowest value */
	private transient byte[] lowerBytes;
	
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
		return IPAddress.toSegments(bytes, segmentCount, bytesPerSegment, bitsPerSegment, creator, networkPrefixLength);
	}
	
	protected static <S extends IPAddressSegment> S[] toCIDRSegments(Integer bits, S segments[], IPAddressSegmentCreator<S> segmentCreator) {
		segments = segments.clone();
		if(bits != null) {
			for(int i = 0; i < segments.length; i++) {
				S seg = segments[i];
				int bitCount = seg.getBitCount();
				Integer segmentPrefixLength = IPAddressSection.getSegmentPrefixLength(bitCount, bits, i);
				segments[i] = IPAddressSection.cast(seg.toNetworkSegment(segmentPrefixLength, true));
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
		if(network) {
			setNetworkMaskPrefix(prefixLen);
		} else {
			setHostMaskPrefix(prefixLen);
		}
		super.initCachedValues(cachedNetworkPrefix, cachedCount);
		this.cachedMinPrefix = cachedMinPrefix;
		this.cachedEquivalentPrefix = cachedEquivalentPrefix;
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
	
	public IPAddressSection getNetworkSection(int networkPrefixLength, boolean withPrefixLength) {
		int cidrSegmentCount = getNetworkSegmentCount(networkPrefixLength);
		return getNetworkSegments(networkPrefixLength, cidrSegmentCount, withPrefixLength, getAddressCreator());
	}
	
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
	
	public IPAddressSection getHostSection(int networkPrefixLength) {
		int cidrSegmentCount = getHostSegmentCount(networkPrefixLength);
		return getHostSegments(networkPrefixLength, cidrSegmentCount, getAddressCreator());
	}
	
	//unchecked casts in the IP* classes call this method so unchecked casts happens in one place
	//I've ensured that users of the IP* classes cannot generate an unsafe unchecked cast, 
	//so all callers to this method perform valid casts
	@SuppressWarnings("unchecked")
    protected static <T> T cast(Object obj) {
		//casting to a generic type cannot be checked at runtime,
		//so the ClassCastException will happen somewhere else
        return (T) obj;
    }

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
			prefixLen = networkMaskPrefixLen;
			if(prefixLen == null) {
				prefixLen = setNetworkMaskPrefix(checkForPrefixMask(network));
			}
		} else {
			prefixLen = hostMaskPrefixLen;
			if(prefixLen == null) {
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
			prefixLen = hostMaskPrefixLen = -1;
		} else {
			hostMaskPrefixLen = prefixLen;
			networkMaskPrefixLen = -1; //cannot be both network and host mask
		}
		return prefixLen;
	}
	
	private Integer setNetworkMaskPrefix(Integer prefixLen) {
		if(prefixLen == null) {
			prefixLen = networkMaskPrefixLen = -1;
		} else {
			networkMaskPrefixLen = prefixLen;
			hostMaskPrefixLen = -1; //cannot be both network and host mask
		}
		return prefixLen;
	}
	
	protected <T extends IPAddress, R extends IPAddressSection, S extends IPAddressSegment>
			R getNetworkSegments(int networkPrefixLength, int networkSegmentCount, boolean withPrefixLength, IPAddressCreator<T, R, S> creator) {
		if(networkPrefixLength < 0 || networkPrefixLength > getBitCount()) {
			throw new IPAddressTypeException(this, networkPrefixLength, "ipaddress.error.prefixSize");
		}
		if(isNetworkSection(networkPrefixLength, withPrefixLength)) {
			return cast(this);
		}
		int segmentCount = getSegmentCount();
		int bitsPerSegment = getBitsPerSegment();
		int totalBits = segmentCount * bitsPerSegment;
		if(networkPrefixLength > totalBits) {
			return cast(this);
		}
		S result[] = creator.createAddressSegmentArray(networkSegmentCount);
		if(networkSegmentCount > 0) {
			for(int i = 0; i < networkSegmentCount; i++) {
				Integer prefix = getSegmentPrefixLength(bitsPerSegment, networkPrefixLength, i);
				result[i] = cast(getSegment(i).toNetworkSegment(prefix, withPrefixLength));
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
	
	protected <T extends IPAddress, R extends IPAddressSection, S extends IPAddressSegment> 
			R getHostSegments(int networkPrefixLength, int networkSegmentCount, IPAddressCreator<T, R, S> creator) {
		if(networkPrefixLength < 0 || networkPrefixLength > getBitCount()) {
			throw new IPAddressTypeException(this, networkPrefixLength, "ipaddress.error.prefixSize");
		}
		if(isHostSection(networkPrefixLength) || networkPrefixLength <= 0) {
			return cast(this);
		}
		int segmentCount = getSegmentCount();
		S result[] = creator.createAddressSegmentArray(networkSegmentCount);
		if(networkSegmentCount > 0) {
			int bitsPerSegment = getBitsPerSegment();
			for(int i = networkSegmentCount - 1, j = segmentCount - 1; i >= 0; i--, j--) {
				Integer prefix = getSegmentPrefixLength(bitsPerSegment, networkPrefixLength, j);
				result[i] = cast(getSegment(j).toHostSegment(prefix));
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
	
	protected <T extends IPAddress, R extends IPAddressSection, S extends IPAddressSegment> R getSubnetSegments(
			IPAddressSection maskSection,
			Integer networkPrefixLength,
			IPAddressCreator<T, R, S> creator,
			boolean verifyMask) {
		if(networkPrefixLength != null && (networkPrefixLength < 0 || networkPrefixLength > getBitCount())) {
			throw new IPAddressTypeException(this, networkPrefixLength, "ipaddress.error.prefixSize");
		}
		int i=0;
		int bitsPerSegment = getBitsPerSegment();
		for(; i < getSegmentCount(); i++) {
			Integer segmentPrefixLength = getSegmentPrefixLength(bitsPerSegment, networkPrefixLength, i);
			S seg = cast(getSegment(i));
			S mask = cast(maskSection.getSegment(i));
			if(seg.isChangedByMask(mask, segmentPrefixLength)) {
				S newSegments[] = creator.createAddressSegmentArray(getSegmentCount());
				copySegments(0, i, newSegments, 0);
				for(int j = i; j < getSegmentCount(); j++) {
					segmentPrefixLength = getSegmentPrefixLength(bitsPerSegment, networkPrefixLength, j);
					seg = cast(getSegment(j));
					mask = cast(maskSection.getSegment(j));
					if(j > i && !seg.isChangedByMask(mask, segmentPrefixLength)) {
						newSegments[j] = seg;
					} else {
						if(verifyMask && !seg.isMaskCompatibleWithRange(mask.getLowerSegmentValue(), segmentPrefixLength)) {
							throw new IPAddressTypeException(seg, mask, "ipaddress.error.maskMismatch");
						}
						int maskValue = mask.getLowerSegmentValue();
						newSegments[j] = creator.createAddressSegment(seg.getLowerSegmentValue() & maskValue, seg.getUpperSegmentValue() & maskValue, segmentPrefixLength);
					}
				}
				return creator.createSectionInternal(newSegments);
			}
		}
		return cast(this);
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
	 * Creates a subnet address using the given mask. 
	 */
	public abstract IPAddressSection toSubnet(IPAddressSection mask) throws IPAddressTypeException;
	
	/**
	 * Creates a subnet address using the given CIDR prefix bits.
	 */
	public IPAddressSection toSubnet(int networkPrefixLength) throws IPAddressTypeException {
		int bitCount = getBitCount();
		if(networkPrefixLength < 0 || networkPrefixLength > bitCount) {
			throw new IPAddressTypeException(this, networkPrefixLength, "ipaddress.error.prefixSize");
		}
		if(isPrefixed() && networkPrefixLength >= getNetworkPrefixLength()) {
			return this;
		}
		IPAddress addressMask = getNetwork().getNetworkMask(networkPrefixLength, false);
		IPAddressSection mask = addressMask.getNetworkSection(bitCount, false);
		return toSubnetImpl(mask, networkPrefixLength, false);
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
	 * Creates a subnet address using the given mask.  If networkPrefixLength is non-null, applies the prefix length as well.
	 * @throws IPAddressTypeException if the mask is not compatible, see {@link IPAddress#isMaskCompatibleWithRange(IPAddress, Integer)}
	 */
	public IPAddressSection toSubnet(IPAddressSection mask, Integer networkPrefixLength) throws IPAddressTypeException {
		IPVersion version = getIPVersion();
		if(!version.equals(mask.getIPVersion())) {
			throw new IPAddressTypeException(this, mask, "ipaddress.error.typeMismatch");
		}
		int segmentCount = getSegmentCount();
		if(mask.getSegmentCount() != segmentCount) {
			throw new IPAddressTypeException(this, mask, "ipaddress.error.sizeMismatch");
		}
		return toSubnetImpl(mask, networkPrefixLength, true);
	}
	
	private IPAddressSection toSubnetImpl(IPAddressSection mask, Integer networkPrefixLength, boolean verifyMask) {
		return getSubnetSegments(mask, networkPrefixLength, getAddressCreator(), verifyMask);
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
	
	/**
	 * Returns the smallest CIDR prefix possible (largest network),
	 * such that this address paired with that prefix represents the exact same range of addresses.
	 *
	 * @see inet.ipaddr.format.IPAddressDivision#getMaskPrefixLength(boolean)
	 * 
	 * @return
	 */
	public int getMinPrefix() {
		if(cachedMinPrefix == null) {
			int totalPrefix = getBitCount();
			for(int i = getSegmentCount() - 1; i >= 0 ; i--) {
				IPAddressSegment seg = getSegment(i);
				totalPrefix -= seg.getBitCount();
				int segPrefix = seg.getMinPrefix();
				if(segPrefix != 0) {
					totalPrefix += segPrefix;
					break;
				}
			}
			cachedMinPrefix = totalPrefix;
		}
		return cachedMinPrefix;
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
		Integer result = cachedEquivalentPrefix;
		if(result == null) {
			int totalPrefix = 0;
			for(int i = 0; i < getSegmentCount(); i++) {
				IPAddressSegment seg = getSegment(i);
				int segPrefix = seg.getMinPrefix();
				if(!seg.isRangeEquivalent(segPrefix)) {
					cachedEquivalentPrefix = -1;
					return null;
				}
				if(seg.isPrefixed()) {
					return cachedEquivalentPrefix = totalPrefix + segPrefix;
				}
				if(segPrefix < seg.getBitCount()) {
					//remaining segments must be full range or we return null
					for(i++; i < getSegmentCount(); i++) {
						IPAddressSegment laterSeg = getSegment(i);
						if(!laterSeg.isFullRange()) {
							cachedEquivalentPrefix = -1;
							return null;
						}
					}
					return cachedEquivalentPrefix = totalPrefix + segPrefix;
				}
				totalPrefix += segPrefix;
			}
			return cachedEquivalentPrefix = totalPrefix;
		}
		if(result < 0) {
			return null;
		}
		return result;
	}
	
	public IPAddressSection getLowestSection() {
		return getLowestOrHighestSection(getAddressCreator(), true);
	}
	
	public IPAddressSection getHighestSection() {
		return getLowestOrHighestSection(getAddressCreator(), false);
	}
	
	public IPAddressSegment[] getLowestSegments() {
		return getLowestOrHighest(getSegmentCreator(), true, false);
	}
	
	public IPAddressSegment[] getHighestSegments() {
		return getLowestOrHighest(getSegmentCreator(), false, false);
	}
	
	protected <S extends IPAddressSegment> S[] getLowestOrHighest(IPAddressSegmentCreator<S> segmentCreator, boolean lowest, boolean allowTheseSegments) {
		if(!isMultiple() && !isPrefixed()) {
			if(allowTheseSegments) {
				//Note that when IPAddressSection is created, 
				//we insert an IPv4AddressSegment[] or IPv6AddressSegment[] into the divisions field,
				//so this cast does in fact work, the array is of type S
				return cast(divisions);
			}
			//see above about the cast
			return cast(divisions.clone());
		}
		return createLowestOrHighest(segmentCreator, lowest);
	}

	protected <S extends IPAddressSegment> S[] createLowestOrHighest(IPAddressSegmentCreator<S> segmentCreator, boolean lowest) {
		int segmentCount = getSegmentCount();
		S segs[] = segmentCreator.createAddressSegmentArray(segmentCount);
		for(int i = 0; i < segmentCount; i++) {
			IPAddressSegment seg = getSegment(i);
			segs[i] = IPAddressSection.cast(lowest ? seg.getLowest() : seg.getHighest());
		}
		return segs;
	}
	
	protected <T extends IPAddress, R extends IPAddressSection, S extends IPAddressSegment> 
		R getSection(IPAddressCreator<T, R, S> creator, S segs[]) {
		return creator.createSectionInternal(segs);
	}
	
	protected <T extends IPAddress, R extends IPAddressSection, S extends IPAddressSegment> 
			R getLowestOrHighestSection(IPAddressCreator<T, R, S> creator, boolean lowest) {
		if(!isMultiple() && !isPrefixed()) {
			return cast(this);
		}
		S segs[] = createLowestOrHighest(creator, lowest);
		return creator.createSectionInternal(segs);
	}
	
	public abstract Iterator<? extends IPAddressSection> sectionIterator();
	
	protected class SectionIterator<T extends IPAddress, R extends IPAddressSection, S extends IPAddressSegment> implements Iterator<R> {
		private boolean doThis = !isPrefixed() && !isMultiple(); //note that a non-multiple address can have a prefix (either /32 or /128)
		protected Iterator<? extends IPAddressSegment[]> iterator = iterator();
		
		public SectionIterator() {}
		
		@Override
		public R next() {
			if(!hasNext()) {
	    		throw new NoSuchElementException();
	    	}
			if(doThis) {
	    		doThis = false;
		    	return cast(IPAddressSection.this);
	    	}
			S next[] = cast(iterator.next());
	    	IPAddressCreator<T, R, S> creator = cast(getAddressCreator());
		   	return creator.createSectionInternal(next);
	    }
		
		@Override
		public boolean hasNext() {
			return iterator.hasNext() || doThis;
		}
		
	    @Override
		public void remove() {
	    	throw new UnsupportedOperationException();
	    }
	};
	
	public Iterator<? extends IPAddressSegment[]> iterator() {
		return iterator(getSegmentCreator(), false);
	}
	
	protected <S extends IPAddressSegment> Iterator<S[]> iterator(final IPAddressSegmentCreator<S> segmentCreator, boolean skipThis) {
		if(!isMultiple()) {
			return new Iterator<S[]>() {
				boolean done = skipThis;
				
				@Override
				public boolean hasNext() {
					return !done;
				}

			    @Override
				public S[] next() {
			    	if(!hasNext()) {
			    		throw new NoSuchElementException();
			    	}
			    	done = true;
			    	return cast(getLowestSegments());
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
			
			private final Iterator<S> variations[] = cast(new Iterator[segmentCount]);
			
			private S nextSet[] = segmentCreator.createAddressSegmentArray(segmentCount);  {
				for(int i = 0; i < segmentCount; i++) {
					variations[i] = cast(getSegment(i).iterator());
					nextSet[i] = variations[i].next();
				}
				if(skipThis) {
					increment();
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
		    			for(int k = j + 1; k < segmentCount; k++) {
		    				variations[k] = cast(getSegment(k).iterator());
			    			nextSet[k] = variations[k].next();
		    			}
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
		return toCanonicalString();
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
	
	public abstract String toNormalizedString(StringOptions params);
	
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
		public String canonicalString;
		public String normalizedWildcardString;
		public String fullString;
		public String sqlWildcardString;
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
		
		protected StringOptions(
				int base,
				boolean expandSegments,
				WildcardOptions wildcardOptions,
				String segmentStrPrefix) {
			this.expandSegments = expandSegments;
			this.wildcardOptions = wildcardOptions;
			this.base = base;
			this.segmentStrPrefix = segmentStrPrefix;
		}
		
		public static class Builder {
			public static final WildcardOptions DEFAULT_WILDCARD_OPTIONS = new WildcardOptions();
		
			protected WildcardOptions wildcardOptions = DEFAULT_WILDCARD_OPTIONS;
			protected boolean expandSegments;
			protected int base = IPv4Address.DEFAULT_TEXTUAL_RADIX;
			protected String segmentStrPrefix;
			
			public Builder() {
				this(IPv4Address.DEFAULT_TEXTUAL_RADIX);
			}
			
			protected Builder(int base) {
				this.base = base;
			}
			
			public Builder setWildcardOptions(WildcardOptions wildcardOptions) {
				this.wildcardOptions = wildcardOptions;
				return this;
			}
			
			public Builder setExpandSegments(boolean expandSegments) {
				this.expandSegments = expandSegments;
				return this;
			}
			
			public Builder setRadix(int base) {
				this.base = base;
				return this;
			}
			
			public Builder setSegmentStrPrefix(String prefix) {
				this.segmentStrPrefix = prefix;
				return this;
			}
			
			public StringOptions toParams() {
				return new StringOptions(base, expandSegments, wildcardOptions, segmentStrPrefix);
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
