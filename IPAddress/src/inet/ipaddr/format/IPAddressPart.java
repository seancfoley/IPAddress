package inet.ipaddr.format;

import java.io.Serializable;

/**
 * A generic part of an IP address.  It is divided into a series of combinations of individual address divisions ({@link IPAddressDivision}),
 * each of those being a combination of one or more IP address segments.
 * The number of such series is the division count.
 * 
 * @author sfoley
 *
 */
public interface IPAddressPart extends Serializable {
	
	IPAddressDivision getDivision(int index);
	
	int getDivisionCount();
	
	int getByteCount();
	
	/**
	 * Returns the network prefix, which is 16 for an address like 1.2.0.0/16
	 * If there is no prefix length, returns null.
	 * @return the prefix length
	 */
	Integer getNetworkPrefixLength();
	
	/**
	 * whether this is a pat of more than one address.  In other words, it is the same part of many potential addresses.
	 */
	boolean isMultiple();
	
	default int getPrefixStringLength() {//TODO xxx move to seg grouping class xxx
		Integer networkPrefixLength = getNetworkPrefixLength();
		if(networkPrefixLength != null) {
			return IPAddressDivision.toUnsignedStringLength(networkPrefixLength, 10) + 1;
		}
		return 0;
	}
}


