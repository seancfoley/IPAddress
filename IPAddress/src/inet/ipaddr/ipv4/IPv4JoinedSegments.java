package inet.ipaddr.ipv4;

import inet.ipaddr.format.IPAddressJoinedSegments;

/**
 * 
 * @author sfoley
 *
 */
public class IPv4JoinedSegments extends IPAddressJoinedSegments {
	
	private static final long serialVersionUID = 1L;
	private static int MAX_CHARS[] = new int[IPv4Address.SEGMENT_COUNT - 1];
	
	public IPv4JoinedSegments(int joinedCount, int value) {
		super(joinedCount, value);
		if(joinedCount >= IPv4Address.SEGMENT_COUNT) {
			throw new IllegalArgumentException();
		}
	}

	public IPv4JoinedSegments(int joinedCount, long value, Integer segmentPrefix) {
		super(joinedCount, value, segmentPrefix == null ? null : Math.min((joinedCount + 1) * IPv4Address.BITS_PER_SEGMENT, segmentPrefix));
		if(joinedCount >= IPv4Address.SEGMENT_COUNT) {
			throw new IllegalArgumentException();
		}
	}

	public IPv4JoinedSegments(int joinedCount, long lower, long upper, Integer segmentPrefix) {
		super(joinedCount, lower, upper, segmentPrefix == null ? null : Math.min((joinedCount + 1) * IPv4Address.BITS_PER_SEGMENT, segmentPrefix));
		if(joinedCount >= IPv4Address.SEGMENT_COUNT) {
			throw new IllegalArgumentException();
		}
	}
	
	@Override
	public int getDefaultMaxChars() {
		int result = MAX_CHARS[joinedCount - 1];
		if(result == 0) {
			result = MAX_CHARS[joinedCount - 1] = super.getDefaultMaxChars();
		}
		return result;
	}

	@Override
	protected long getDivisionNetworkMask(int bits) {
		return IPv4Address.network().getSegmentNetworkMask(bits, joinedCount);
	}

	@Override
	protected long getDivisionHostMask(int bits) {
		return IPv4Address.network().getSegmentHostMask(bits, joinedCount);
	}
	
	@Override
	protected int getBitsPerSegment() {
		return IPv4Address.BITS_PER_SEGMENT;
	}

	@Override
	protected int getBytesPerSegment() {
		return IPv4Address.BYTES_PER_SEGMENT;
	}

	@Override
	public int getDefaultTextualRadix() {
		return IPv4Address.DEFAULT_TEXTUAL_RADIX;
	}
}
