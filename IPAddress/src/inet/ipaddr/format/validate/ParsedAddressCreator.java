package inet.ipaddr.format.validate;

import inet.ipaddr.HostName;
import inet.ipaddr.IPAddress;
import inet.ipaddr.IPAddressSection;
import inet.ipaddr.IPAddressSegment;
import inet.ipaddr.IPAddressString;
import inet.ipaddr.ipv4.IPv4AddressSection;

/**
 * Has methods for creating addresses, segments and sections that are available only to the parser
 * 
 * @author sfoley
 *
 * @param <T>
 * @param <R>
 * @param <S>
 */
public abstract class ParsedAddressCreator<T extends IPAddress, R extends IPAddressSection, S extends IPAddressSegment> {
	
	public abstract S[] createAddressSegmentArray(int length);
	
	public abstract S createAddressSegment(int value, Integer segmentPrefixLength);

	public abstract S createAddressSegment(int lower, int upper, Integer segmentPrefixLength);
	
	/* 
	 * These methods are for internal use only.  
	 * The originating IPAddressString or Host is cached inside the created address.
	 * Also, byte arrays are not cloned, they are used by the resulting address.
	 * Also, segment arrays are not cloned, they is used by the resulting address or address section.
	 */
	
	protected abstract S createAddressSegmentInternal(int value, Integer segmentPrefixLength, String addressStr, int originalVal, boolean isStandardString, int lowerStringStartIndex, int lowerStringEndIndex);
	
	protected abstract S createAddressSegmentInternal(int lower, int upper, Integer segmentPrefixLength, String addressStr, int originalLower, int originalUpper, boolean isStandardString, boolean isStandardRangeString, int lowerStringStartIndex, int lowerStringEndIndex, int upperStringEndIndex);
	
	protected abstract T createAddressInternal(R section, String zone, IPAddressString fromString);
	
	protected abstract T createAddressInternal(R section, String zone, HostName fromHost);
	
	protected abstract T createAddressInternal(R section, IPAddressString fromString);
	
	protected abstract T createAddressInternal(R section, HostName fromHost);
	
	protected abstract R createSectionInternal(byte bytes[], Integer prefix);
	
	protected abstract R createSectionInternal(byte bytes[], String zone);
	
	protected abstract R createSectionInternal(byte bytes[]);

	protected T createAddressInternal(byte bytes[], Integer prefix, HostName fromHost) {
		return createAddressInternal(createSectionInternal(bytes, prefix), fromHost);
	}
	
	protected T createAddressInternal(byte bytes[], String zone, HostName fromHost) {
		return createAddressInternal(createSectionInternal(bytes, zone), fromHost);
	}
	
	protected T createAddressInternal(byte bytes[], HostName fromHost) {
		return createAddressInternal(createSectionInternal(bytes), fromHost);
	}
	
	protected abstract R createSectionInternal(S segments[]);
	
	protected abstract R createSectionInternal(S segments[], IPv4AddressSection mixedPart);
	
	protected T createAddressInternal(S segments[], IPAddressString fromString) {
		return createAddressInternal(createSectionInternal(segments), fromString);
	}
	
	protected T createAddressInternal(S segments[], HostName fromHost) {
		return createAddressInternal(createSectionInternal(segments), fromHost);
	}
	
	protected T createAddressInternal(S segments[], String zone, IPAddressString fromString) {
		return createAddressInternal(createSectionInternal(segments), zone, fromString);
	}
	
	protected T createAddressInternal(S segments[], String zone, HostName fromHost) {
		return createAddressInternal(createSectionInternal(segments), zone, fromHost);
	}
}