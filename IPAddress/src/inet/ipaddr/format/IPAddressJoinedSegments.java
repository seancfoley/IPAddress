package inet.ipaddr.format;


/**
 * A combination of two or more IP address segments
 * 
 * @author sfoley
 *
 */
public abstract class IPAddressJoinedSegments extends IPAddressDivision {
	
	private static final long serialVersionUID = 1L;

	protected final int joinedCount;
	protected final long value; //the lower value
	protected final long upperValue; //the upper value of a CIDR or other type of range, if not a range it is the same as value
	
	public IPAddressJoinedSegments(int joinedCount, int value) {
		this.value = this.upperValue = value;
		this.joinedCount = joinedCount;
		
		if(joinedCount <= 0) {
			throw new IllegalArgumentException();
		}
	}

	public IPAddressJoinedSegments(int joinedCount, long value, Integer segmentPrefixLength) {
		this(joinedCount, value, value, segmentPrefixLength);
	}

	public IPAddressJoinedSegments(int joinedCount, long lower, long upper, Integer segmentPrefixLength) {
		super(segmentPrefixLength);
		this.value = lower;
		this.upperValue = upper;
		this.joinedCount = joinedCount;
		if(joinedCount <= 0) {
			throw new IllegalArgumentException();
		}
	}
	
	public int getJoinedCount() {
		return joinedCount;
	}

	@Override
	public long getLowerValue() {
		return value;
	}

	@Override
	public long getUpperValue() {
		return upperValue;
	}
	
	@Override
	protected abstract long getDivisionNetworkMask(int bits);

	@Override
	protected abstract long getDivisionHostMask(int bits);

	protected abstract int getBitsPerSegment();

	protected abstract int getBytesPerSegment();

	@Override
	public long getMaxValue() {
		return ~(~0L << getBitCount());
	}

	@Override
	public int getBitCount() {
		return (joinedCount + 1) * getBitsPerSegment();
	}

	@Override
	public int getByteCount() {
		return (joinedCount + 1) * getBytesPerSegment();
	}
	
	@Override
	protected int getLeadingZerosAdjustment() {
		return Long.SIZE - getBitCount();
	}

	@Override
	public int getDefaultMaxChars() {
		return getCharWidth(getMaxValue(), getDefaultTextualRadix());
	}

	@Override
	protected boolean isSameValues(IPAddressDivision other) {
		if(other instanceof IPAddressJoinedSegments) {
			return isSameValues((IPAddressJoinedSegments) other);
		}
		return false;
	}
	
	protected boolean isSameValues(IPAddressJoinedSegments otherSegment) {
		//note that it is the range of values that matters, the prefix bits do not
		return  otherSegment.joinedCount == joinedCount && value == otherSegment.value && upperValue == otherSegment.upperValue;
	}
	
	@Override
	public boolean equals(Object other) {
		if(other == this) {
			return true;
		}
		if(other instanceof IPAddressJoinedSegments) {
			IPAddressJoinedSegments otherSegments = (IPAddressJoinedSegments) other;
			return isSameValues(otherSegments);
		}
		return false;
	}
	
	@Override
	public int hashCode() {
		return (int) (value | (upperValue << getBitCount()));
	}
}
