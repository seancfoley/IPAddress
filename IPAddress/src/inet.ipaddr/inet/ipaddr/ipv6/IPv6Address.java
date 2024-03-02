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

package inet.ipaddr.ipv6;

import java.io.Serializable;
import java.math.BigInteger;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.List;
import java.util.Objects;
import java.util.function.Predicate;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

import inet.ipaddr.Address;
import inet.ipaddr.AddressConversionException;
import inet.ipaddr.AddressNetwork.PrefixConfiguration;
import inet.ipaddr.AddressPositionException;
import inet.ipaddr.AddressValueException;
import inet.ipaddr.IPAddress;
import inet.ipaddr.IPAddressConverter;
import inet.ipaddr.IPAddressSection.IPStringBuilderOptions;
import inet.ipaddr.IPAddressSection.IPStringOptions;
import inet.ipaddr.IPAddressSegmentSeries;
import inet.ipaddr.IPAddressString;
import inet.ipaddr.IPAddressStringParameters;
import inet.ipaddr.IncompatibleAddressException;
import inet.ipaddr.PrefixLenException;
import inet.ipaddr.format.string.IPAddressStringDivisionSeries;
import inet.ipaddr.format.util.AddressComponentRangeSpliterator;
import inet.ipaddr.format.util.AddressComponentSpliterator;
import inet.ipaddr.format.util.IPAddressPartStringCollection;
import inet.ipaddr.format.validate.Validator;
import inet.ipaddr.ipv4.IPv4Address;
import inet.ipaddr.ipv4.IPv4Address.IPv4AddressConverter;
import inet.ipaddr.ipv4.IPv4AddressNetwork;
import inet.ipaddr.ipv4.IPv4AddressNetwork.IPv4AddressCreator;
import inet.ipaddr.ipv4.IPv4AddressSection;
import inet.ipaddr.ipv6.IPv6AddressNetwork.IPv6AddressCreator;
import inet.ipaddr.ipv6.IPv6AddressSection.IPv6AddressCache;
import inet.ipaddr.ipv6.IPv6AddressSection.IPv6StringBuilderOptions;
import inet.ipaddr.ipv6.IPv6AddressSection.IPv6StringCache;
import inet.ipaddr.ipv6.IPv6AddressSection.IPv6StringCollection;
import inet.ipaddr.ipv6.IPv6AddressSection.IPv6StringOptions;
import inet.ipaddr.ipv6.IPv6AddressTrie.IPv6TrieNode.IPv6TrieKeyData;
import inet.ipaddr.mac.MACAddress;
import inet.ipaddr.mac.MACAddressNetwork;
import inet.ipaddr.mac.MACAddressNetwork.MACAddressCreator;
import inet.ipaddr.mac.MACAddressSection;
import inet.ipaddr.mac.MACAddressSegment;

/**
 * An IPv6 address, or a subnet of multiple IPv6 addresses.  Each segment can represent a single value or a range of values.
 * <p>
 * You can construct an IPv6 address from a byte array, from a BigInteger, from a {@link inet.ipaddr.Address.SegmentValueProvider}, 
 * from Inet6Address, from MACAddress, from an {@link IPv6AddressSection} of 8 segments, or from an array of 8  {@link IPv6AddressSegment} objects.
 * <p>
 * To construct one from a {@link java.lang.String} use 
 * {@link inet.ipaddr.IPAddressString#toAddress()} or  {@link inet.ipaddr.IPAddressString#getAddress()}, {@link inet.ipaddr.IPAddressString#toHostAddress()} or {@link inet.ipaddr.IPAddressString#getHostAddress()}
 * <p>
 * An IPv6 address can have an associated zone, typically either a network interface name or a positive integer.
 * An IPv6 zone distinguishes two IPv6 addresses that are the same.
 * <ul>
 * <li>They are used with link-local addresses fe80::/10 to distinguish two interfaces to the link-local network, this is known as the zone id.
 * </li><li>They are used with site-local addresses to distinguish sites, using the site id, also known as the scope id.
 * </li></ul>
 * <p>
 * A zone that consists of a scope id is called a scoped zone.
 * @custom.core
 * @author sfoley
 */
/*
 * rfc 6890 and the earlier 5156 has details on some of the special addresses
 * 
 * For some of the various pre-specified IPv6 address formats (IPv4 mapped, IPv4 translated, IPv4 compatible, etc), 
 * see gestioip.net/docu/ipv6_address_examples.html
 * 
 * A nice summary of IPV6 formats at https://technet.microsoft.com/en-us/library/cc757359(v=ws.10).aspx
 * https://technet.microsoft.com/en-us/library/dd379548(v=ws.10).aspx
 */
public class IPv6Address extends IPAddress implements Iterable<IPv6Address> {

	private static final long serialVersionUID = 4L;

	public static final char SEGMENT_SEPARATOR = ':';
	public static final char ZONE_SEPARATOR = '%';
	public static final char ALTERNATIVE_ZONE_SEPARATOR = '\u00a7';//'§'; javadoc whines about this char 

	public static final char UNC_SEGMENT_SEPARATOR = '-';
	public static final char UNC_ZONE_SEPARATOR = 's';
	public static final char UNC_RANGE_SEPARATOR = ALTERNATIVE_RANGE_SEPARATOR;
	public static final String UNC_RANGE_SEPARATOR_STR = String.valueOf(UNC_RANGE_SEPARATOR);

	public static final String UNC_SUFFIX = ".ipv6-literal.net";

	public static final String REVERSE_DNS_SUFFIX = ".ip6.arpa";
	public static final String REVERSE_DNS_SUFFIX_DEPRECATED = ".ip6.int";

	public static final int BITS_PER_SEGMENT = 16;
	public static final int BYTES_PER_SEGMENT = 2;
	public static final int SEGMENT_COUNT = 8;
	public static final int MIXED_REPLACED_SEGMENT_COUNT = 2; //IPv4Address.BYTE_COUNT / BYTES_PER_SEGMENT;
	public static final int MIXED_ORIGINAL_SEGMENT_COUNT = 6; //SEGMENT_COUNT - MIXED_REPLACED_SEGMENT_COUNT
	public static final int BYTE_COUNT = 16;
	public static final int BIT_COUNT = 128;
	public static final int DEFAULT_TEXTUAL_RADIX = 16;
	public static final int BASE_85_RADIX = 85;
	public static final int MAX_VALUE_PER_SEGMENT = 0xffff;

	/* 
	 * An IPv6 zone distinguishes two IPv6 addresses that are the same.
	 * They are used with link-local addresses fe80::/10 and distinguishes two interfaces to the link-local network, this is known as the zone id.
	 * They are used with site-local addresses to distinguish sites, using the site id, also known as the scope id.
	 * 
	 * A zone that consists of a scope id is called a scoped zone.
	 */
	private final IPv6Zone zone;

	/**
	 * A reference to a scope id by number or a network interface by name.
	 * <p>
	 * An IPv6 zone distinguishes two IPv6 addresses that are the same.
	 * They are used with link-local addresses fe80::/10 to distinguish two interfaces to the link-local network, this is known as the zone id.
	 * They are used with site-local addresses to distinguish sites, using the site id, also known as the scope id.
	 * <p>
	 * A zone that consists of a scope id is called a scoped zone.
	 * <p>
	 * An IPv6 zone will reference an interface by a scoped identifier number or by interface name based on how it was constructed.
	 * If constructed with a numeric identifier, whether integer or string, it will always reference by scoped identifier.
	 * Otherwise, it will always reference by interface name.
	 * <p>
	 * Once constructed, it will always reference using the same method, either interface name or scope id.  
	 * To reference by the other method you must use a different IPv6Zone instance.
	 * <p>
	 * Even though it will always reference using the same method, 
	 * you can use the IPv6Zone instance to look up the scope id if the instance references by interface name,
	 * or to look up the associated interface if the instance references by scope id.
	 * 
	 * 
	 * @custom.core
	 * @author scfoley
	 *
	 */
	public static class IPv6Zone implements Serializable {

		private static final long serialVersionUID = 1L;
		
		String zoneStr;
		private int scopeId;
		private transient NetworkInterface networkInterface;
		private Boolean referencesInterface;
		
		/**
		 * Constructs a zone that will use the given zone string, 
		 * either a non-negative integer indicating a scope identifier, 
		 * or the name of a network interface.
		 * <p>
		 * A scope identifier is indicated by a sequence of decimal digits.
		 * <p>
		 * To create an InetAddress by pairing this zone with an IPv6Address instance,
		 * an interface name must reference an existing interface, otherwise the InetAddress cannot be created.
		 * <p>
		 * See {@link java.net.NetworkInterface}  to get a list of existing interfaces or to look up interfaces by name.
		 * 
		 * @param zoneStr
		 */
		public IPv6Zone(String zoneStr) {
			if(zoneStr == null) {
				throw new NullPointerException();
			}
			this.zoneStr = zoneStr.trim();
			scopeId = -1;
		}
		
		/**
		 * Constructs a zone that will use a scope identifier with the address.
		 * 
		 * @param scopeId
		 */
		public IPv6Zone(int scopeId) {
			if(scopeId < 0) {
				throw new IllegalArgumentException();
			}
			this.scopeId = scopeId;
			referencesInterface = Boolean.FALSE;
		}
		
		/**
		 * Constructs a zone that will use an interface name with the address.
		 * 
		 * @param networkInterface
		 */
		public IPv6Zone(NetworkInterface networkInterface) {
			if(networkInterface == null) {
				throw new NullPointerException();
			}
			this.networkInterface = networkInterface;
			referencesInterface = Boolean.TRUE;
			scopeId = -1;
			zoneStr = networkInterface.getName();
		}
		
		/**
		 * Whether this zone references a network interface.
		 * 
		 * @return
		 */
		public boolean referencesIntf() {
			if(referencesInterface == null) {
				scopeId = checkIfScope(zoneStr);
				referencesInterface = scopeId < 0;
			}
			return referencesInterface;
		}
		
		/**
		 * Whether this zone references a scope identifier.
		 * 
		 * @return
		 */
		public boolean referencesScopeId() {
			return !referencesIntf();
		}

		/**
		 * If this zone references a network interface, returns that interface, 
		 * or null if no interface with the given name exists on the system.
		 * 
		 * If this zone references a scope id, returns the associated interface.
		 * 
		 * @return
		 */
		public NetworkInterface getAssociatedIntf() {
			try {
				if(referencesIntf()) {
					if(networkInterface == null) {
						networkInterface = NetworkInterface.getByName(zoneStr);
					}
				} else {
					if(networkInterface == null) {
						Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
						top:
						while(interfaces.hasMoreElements()) {
							NetworkInterface nif = interfaces.nextElement();
							Enumeration<InetAddress> addrs = nif.getInetAddresses();
							while(addrs.hasMoreElements()) {
								InetAddress addr = addrs.nextElement();
								if(addr instanceof Inet6Address) {
									Inet6Address inetAddr = (Inet6Address) addr;
									if(inetAddr.getScopeId() == scopeId) {
										networkInterface = nif;
										break top;
									}
								}
							}
						}
					}
				}
			} catch(SocketException e) {}
			return networkInterface;
		}
		
		/**
		 * Returns the MAC address of the associated interface
		 * 
		 * @return
		 */
		public MACAddress getAssociatedIntfMacAddr() {
			NetworkInterface intf = getAssociatedIntf();
			try {
				if(intf != null) {
					byte bytes[] = intf.getHardwareAddress();
					if(bytes != null) {
						return new MACAddress(bytes);
					}
				}
			} catch(SocketException e) {}
			return null;
		}

		/**
		 * If this zone references a scoped identifier, returns that identifier.
		 * <p>
		 * If this zone references a network interface, returns the scope identifier for the addresses of that interface,
		 * or -1 if the referenced interface cannot be found on the system, or no single scope identifier was assigned.
		 * 
		 * @return
		 */
		public int getAssociatedScopeId() {
			if(referencesIntf()) {
				if(scopeId == -1) {
					NetworkInterface nif = getAssociatedIntf();
					if(nif != null) {
						Enumeration<InetAddress> addrs = nif.getInetAddresses();
						int newScopeId = -1;
						while(addrs.hasMoreElements()) {
							InetAddress addr = addrs.nextElement();
							if(addr instanceof Inet6Address) {
								Inet6Address inetAddr = (Inet6Address) addr;
								int sid = inetAddr.getScopeId();
								if(sid != 0) {
									if(newScopeId != -1 && sid != newScopeId) {
										// multiple scope ids for the interface
										newScopeId = -1;
										break;
									}
									newScopeId = sid;
								}
							}
						}
						if(newScopeId != -1) {
							this.scopeId = newScopeId;
						}
					}
				}
			}
			return scopeId;
		}
		
		@Override
		public int hashCode() {
			return toString().hashCode();
		}
		
		@Override
		public boolean equals(Object o) {
			return o instanceof IPv6Zone && toString().equals(o.toString());
		}
		
		public String getName() {
			if(zoneStr == null) {
				if(referencesIntf()) {
					zoneStr = networkInterface.getName();
				} else {
					zoneStr = IPv6AddressSegment.toUnsignedString(scopeId, 10,
							new StringBuilder(IPv6AddressSegment.toUnsignedStringLength(scopeId, 10))).toString();
				}
			}
			return zoneStr;
		}
	
		@Override
		public String toString() {
			return getName();
		}
		
		static int checkIfScope(String zoneStr) {
			long digits = 0;
			for(int i = 0, len = zoneStr.length(); i < len; i++) {
				char c = zoneStr.charAt(i);
				int digit = Character.digit(c, 10);
				if(digit < 0) {
					return -1;
				}
				digits = (digits * 10) + digit;
				if(digits > Integer.MAX_VALUE) {
					return -1;
				}
			}
			return (int) digits;
		}
	}

	private transient IPv6StringCache stringCache;
	
	private transient IPv6TrieKeyData cachedTrieKeyData;

	transient IPv6AddressCache addressCache;

	IPv6Address(IPv6AddressSection section, CharSequence zone, boolean checkZone) throws AddressValueException {
		this(section, checkZone ? 
					checkZone(zone) : 
					(zone != null && zone.length() > 0 ? 
							new IPv6Zone(zone.toString()) :
							null));
	}
	
	/**
	 * Constructs an IPv6 address or subnet.
	 * @throws AddressValueException if segment count is not 8 or zone is invalid
	 * @param section
	 * @param zone
	 */
	public IPv6Address(IPv6AddressSection section, IPv6Zone zone) throws AddressValueException {
		super(section);
		if(section.getSegmentCount() != SEGMENT_COUNT) {
			throw new AddressValueException("ipaddress.error.ipv6.invalid.segment.count", section.getSegmentCount());
		}
		if(section.addressSegmentIndex != 0) {
			throw new AddressPositionException(section.addressSegmentIndex);
		}
		this.zone = zone;
	}
	
	/**
	 * @deprecated use {@link #IPv6Address(IPv6AddressSection, IPv6Zone)}
	 * @throws AddressValueException if segment count is not 8 or zone is invalid
	 * @param section
	 * @param zone
	 */
	@Deprecated
	public IPv6Address(IPv6AddressSection section, CharSequence zone) throws AddressValueException {
		this(section, zone, true);
	}
	

	public IPv6Address(IPv6AddressSection section) throws AddressValueException {
		this(section, (CharSequence) null);
	}

	/**
	 * Constructs an IPv6 address or subnet.
	 * @throws AddressValueException if segment count is not 8
	 * @param segments the address segments
	 */
	public IPv6Address(IPv6AddressSegment[] segments) throws AddressValueException {
		this(segments, null, null);
	}

	/**
	 * Constructs an IPv6 address or a set of addresses.
	 * 
	 * @throws AddressValueException if segment count is not 8
	 * @param segments the address segments
	 * @param networkPrefixLength
	 * @throws AddressValueException if network prefix length invalid
	 */
	public IPv6Address(IPv6AddressSegment[] segments, Integer networkPrefixLength) throws AddressValueException {
		this(segments, networkPrefixLength, null);
	}

	/**
	 * Constructs an IPv6 address or a set of addresses.
	 * 
	 * @deprecated use {@link #IPv6Address(IPv6AddressSegment[], IPv6Zone)}
	 * @param segments the address segments
	 * @param zone the zone or scope id
	 * 
	 * @throws AddressValueException if segment count is not 8 or the zone invalid
	 */
	@Deprecated
	public IPv6Address(IPv6AddressSegment[] segments, CharSequence zone) throws AddressValueException {
		this(segments, checkZone(zone));
	}

	/**
	 * Constructs an IPv6 address or a set of addresses.
	 * 
	 * @param segments the address segments
	 * @param zone the zone or scope id
	 * 
	 * @throws AddressValueException if segment count is not 8 or the zone invalid
	 */
	public IPv6Address(IPv6AddressSegment[] segments, IPv6Zone zone) throws AddressValueException {
		this(segments, null, zone);
	}

	private IPv6Address(IPv6AddressSegment[] segments, Integer networkPrefixLength, IPv6Zone zone) throws AddressValueException {
		super(thisAddress -> ((IPv6Address) thisAddress).getDefaultCreator().createSection(segments, networkPrefixLength));
		if(segments.length != SEGMENT_COUNT) {
			throw new AddressValueException("ipaddress.error.ipv6.invalid.segment.count", segments.length);
		}
		this.zone = zone;
	}

	/**
	 * Constructs an IPv6 address.
	 *
	 * @param inet6Address the java.net address object
	 */
	public IPv6Address(Inet6Address inet6Address) {
		this(inet6Address, inet6Address.getAddress(), null, getZone(inet6Address));
	}
	
	/**
	 * Constructs an IPv6 address.
	 *
	 * @param inet6Address the java.net address object
	 */
	public IPv6Address(Inet6Address inet6Address, Integer networkPrefixLength) {
		this(inet6Address, inet6Address.getAddress(), networkPrefixLength, getZone(inet6Address));
	}
	
	private IPv6Address(Inet6Address inet6Address, byte[] bytes, Integer networkPrefixLength, IPv6Zone zone) throws AddressValueException {
		super(thisAddress -> ((IPv6Address) thisAddress).getDefaultCreator().createSection(bytes, 0, bytes.length, IPv6Address.SEGMENT_COUNT, networkPrefixLength));
		this.zone = zone;
		getSection().setInetAddress(inet6Address);
	}

	/**
	 * Constructs an IPv6 address.
	 * <p>
	 * The byte array can be a 16 byte IPv6 address, but may have additional zero-valued bytes, or it may be fewer than 16 bytes.
	 *
	 * @deprecated use {@link #IPv6Address(byte[], IPv6Zone)}
	 * @throws AddressValueException if bytes not equivalent to a 16 byte address
	 * @param bytes the 16 byte IPv6 address in network byte order - if longer than 16 bytes the additional bytes must be zero (and are ignored), if shorter than 16 bytes then the bytes are sign-extended to 16 bytes.
	 * @throws AddressValueException if byte range invalid or zone invalid
	 */
	@Deprecated
	public IPv6Address(byte[] bytes, CharSequence zone) throws AddressValueException {
		this(bytes, checkZone(zone));
	}
	
	/**
	 * Constructs an IPv6 address.
	 * <p>
	 * The byte array can be a 16 byte IPv6 address, but may have additional zero-valued bytes, or it may be fewer than 16 bytes.
	 *
	 * @throws AddressValueException if bytes not equivalent to a 16 byte address
	 * @param bytes the 16 byte IPv6 address in network byte order - if longer than 16 bytes the additional bytes must be zero (and are ignored), if shorter than 16 bytes then the bytes are sign-extended to 16 bytes.
	 * @throws AddressValueException if byte range invalid or zone invalid
	 */
	public IPv6Address(byte[] bytes, IPv6Zone zone) throws AddressValueException {
		this(bytes, null, zone);
	}
	
	/**
	 * Constructs an IPv6 address.
	 * <p>
	 * The byte array can be a 16 byte IPv6 address, but may have additional zero-valued bytes, or it may be fewer than 16 bytes.
	 *
	 * @throws AddressValueException if bytes not equivalent to a 16 byte address
	 * @param bytes the 16 byte IPv6 address in network byte order - if longer than 16 bytes the additional bytes must be zero (and are ignored), if shorter than 16 bytes then the bytes are sign-extended to 16 bytes.
	 */
	public IPv6Address(byte[] bytes) throws AddressValueException {
		this(bytes, null, null);
	}
	
	/**
	 * Constructs an IPv6 address or subnet.
	 * <p>
	 * Similar to {@link #IPv6Address(byte[])} except that you can specify the start and end of the address in the given byte array.
	 * @throws AddressValueException if byte range invalid
	 */
	public IPv6Address(byte[] bytes, int byteStartIndex, int byteEndIndex) throws AddressValueException {
		this(bytes, byteStartIndex, byteEndIndex, null, null);
	}
	
	/**
	 * Constructs an IPv6 address or subnet.
	 * <p>
	 * The byte array can be a 16 byte IPv6 address, but may have additional zero-valued bytes, or it may be fewer than 16 bytes.
	 * <p>
	 * When networkPrefixLength is non-null, depending on the prefix configuration (see {@link inet.ipaddr.AddressNetwork#getPrefixConfiguration()},
	 * this object may represent either a single address with that network prefix length, or the prefix subnet block containing all addresses with the same network prefix.
	 * <p>
	 * @param bytes the 16 byte IPv6 address in network byte order - if longer than 16 bytes the additional bytes must be zero (and are ignored), if shorter than 16 bytes then the bytes are sign-extended to 16 bytes.
	 * @param networkPrefixLength the CIDR prefix, which can be null for no prefix length
	 * @throws AddressValueException if bytes not equivalent to a 16 byte address
	 */
	public IPv6Address(byte[] bytes, Integer networkPrefixLength) throws AddressValueException {
		this(bytes, networkPrefixLength, null);
	}
	
	/**
	 * Constructs an IPv6 address or subnet.
	 * <p>
	 * Similar to {@link #IPv6Address(byte[], Integer)} except that you can specify the start and end of the address in the given byte array.
	 */
	public IPv6Address(byte[] bytes, int byteStartIndex, int byteEndIndex, Integer networkPrefixLength) throws AddressValueException {
		this(bytes, byteStartIndex, byteEndIndex, networkPrefixLength, null);
	}
	
	/**
	 * Constructs an IPv6 address.  
	 * <p>
	 * The byte representation from {@link BigInteger#toByteArray()} is used, and the byte array follows the rules according to {@link #IPv6Address(byte[])}.
	 * Either it must be exactly 16 bytes, or if larger then any extra bytes must be significant leading zeros, 
	 * or if smaller it is sign-extended to the required 16 byte length.
	 * <p>
	 * This means that you can end up with the same address from two different values of BigInteger, one positive and one negative.
	 * For instance, -1 and ffffffffffffffffffffffffffffffff are represented by the two's complement byte arrays [ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff] 
	 * and [0,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff] respectively.
	 * Both create the address ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff
	 * <p>
	 * In fact, the two's complement byte array [ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff] can be shortened to [ff], the former being the sign-extension of the latter.
	 * So the byte array [ff] also creates the address ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff.
	 * <p>
	 * When using positive integers you end up with the results you expect, the magnitude of the big integer becomes the address.
	 * <p>
	 * When ranging over all 16-byte arrays and constructing BigInteger from those arrays, you range over all possible addresses.
	 * <p>
	 * @throws AddressValueException if value is outside the range of potential values
	 * @param val must be an IPv6 address value.
	 * @throws AddressValueException if val is invalid
	 */
	public IPv6Address(BigInteger val) throws AddressValueException {
		this(val, null, (IPv6Zone) null);
	}
	
	/**
	 * Constructs an IPv6 address.  
	 * <p>
	 * The byte representation from {@link BigInteger#toByteArray()} is used, and the byte array follows the rules according to {@link #IPv6Address(byte[])}.
	 * Either it must be exactly 16 bytes, or if larger then any extra bytes must be significant leading zeros, 
	 * or if smaller it is sign-extended to the required 16 byte length.
	 * <p>
	 * When networkPrefixLength is non-null, depending on the prefix configuration (see {@link inet.ipaddr.AddressNetwork#getPrefixConfiguration()},
	 * this object may represent either a single address with that network prefix length, or the prefix subnet block containing all addresses with the same network prefix.
	 * 
	 * @param val
	 * @param networkPrefixLength
	 * @throws AddressValueException if val is invalid
	 */
	public IPv6Address(BigInteger val, Integer networkPrefixLength) throws AddressValueException {
		this(val, networkPrefixLength, (IPv6Zone) null);
	}
	
	/**
	 * Constructs an IPv6 address.
	 * <p>
	 * The byte representation from {@link BigInteger#toByteArray()} is used, and the byte array follows the rules according to {@link #IPv6Address(byte[])}.
	 * Either it must be exactly 16 bytes, or if larger then any extra bytes must be significant leading zeros, 
	 * or if smaller it is sign-extended to the required 16 byte length.
	 * <p>
	 * @deprecated use {@link #IPv6Address(BigInteger, IPv6Zone)}
	 * @param val
	 * @param zone
	 * @throws AddressValueException if val is invalid or if zone is invalid
	 */
	@Deprecated
	public IPv6Address(BigInteger val, CharSequence zone) throws AddressValueException {
		this(val, checkZone(zone));
	}
	
	/**
	 * Constructs an IPv6 address.
	 * <p>
	 * The byte representation from {@link BigInteger#toByteArray()} is used, and the byte array follows the rules according to {@link #IPv6Address(byte[])}.
	 * Either it must be exactly 16 bytes, or if larger then any extra bytes must be significant leading zeros, 
	 * or if smaller it is sign-extended to the required 16 byte length.
	 * <p>
	 * @param val
	 * @param zone
	 * @throws AddressValueException if val is invalid or if zone is invalid
	 */
	public IPv6Address(BigInteger val, IPv6Zone zone) throws AddressValueException {
		this(val, null, zone);
	}
	
	/**
	 * Constructs an IPv6 address or subnet.
	 * <p>
	 * When networkPrefixLength is non-null, depending on the prefix configuration (see {@link inet.ipaddr.AddressNetwork#getPrefixConfiguration()},
	 * this object may represent either a single address with that network prefix length, or the prefix subnet block containing all addresses with the same network prefix.
	 * <p>
	 * 
	 * @deprecated use {@link #IPv6Address(BigInteger, Integer, IPv6Zone)}
	 * @param val must be an IPv6 address value
	 * @param networkPrefixLength the CIDR prefix length, which can be null for no prefix length
	 * @param zone the zone or scope id
	 * @throws AddressValueException if value is outside the range of potential values, or if zone is invalid
	 */
	@Deprecated
	public IPv6Address(BigInteger val, Integer networkPrefixLength, CharSequence zone) throws AddressValueException {	
		this(val, networkPrefixLength, checkZone(zone));
	}
	
	/**
	 * Constructs an IPv6 address or subnet.
	 * <p>
	 * When networkPrefixLength is non-null, depending on the prefix configuration (see {@link inet.ipaddr.AddressNetwork#getPrefixConfiguration()},
	 * this object may represent either a single address with that network prefix length, or the prefix subnet block containing all addresses with the same network prefix.
	 * <p>
	 * 
	 * @param val must be an IPv6 address value
	 * @param networkPrefixLength the CIDR prefix length, which can be null for no prefix length
	 * @param zone the zone or scope id
	 * @throws AddressValueException if value is outside the range of potential values, or if zone is invalid
	 */
	public IPv6Address(BigInteger val, Integer networkPrefixLength, IPv6Zone zone) throws AddressValueException {	
		super(thisAddress -> ((IPv6Address) thisAddress).getDefaultCreator().createSectionInternal(val.toByteArray(), IPv6Address.SEGMENT_COUNT, networkPrefixLength, false));
		this.zone = zone;
	}
	
	private IPv6Address(byte[] bytes, Integer networkPrefixLength, IPv6Zone zone) throws AddressValueException {
		this(bytes, 0, bytes.length, networkPrefixLength, zone);
	}
	
	private IPv6Address(byte[] bytes, int byteStartIndex, int byteEndIndex, Integer networkPrefixLength, IPv6Zone zone) throws AddressValueException {
		super(thisAddress -> ((IPv6Address) thisAddress).getDefaultCreator().createSection(bytes, byteStartIndex, byteEndIndex, IPv6Address.SEGMENT_COUNT, networkPrefixLength));
		this.zone = zone;
	}

	/**
	 * Constructs an IPv6 address.
	 * <p>
	 * The highBytes form the more significant 4 bytes of the address.
	 * 
	 * @param highBytes the 4 more significant bytes in network byte order
	 * @param lowBytes the 4 least significant bytes in network byte order
	 * @throws AddressValueException if zone invalid
	 */
	public IPv6Address(long highBytes, long lowBytes, IPv6Zone zone) throws AddressValueException {
		this(highBytes, lowBytes, null, zone);
	}

	/**
	 * Constructs an IPv6 address.
	 * <p>
	 * The highBytes form the more significant 4 bytes of the address.
	 *
	 * @param highBytes the 4 more significant bytes in network byte order
	 * @param lowBytes the 4 least significant bytes in network byte order
	 */
	public IPv6Address(long highBytes, long lowBytes) throws AddressValueException {
		this(highBytes, lowBytes, null, null);
	}

	/**
	 * Constructs an IPv6 address or subnet.
	 * <p>
	 * The highBytes form the more significant 4 bytes of the address.
	 * <p>
	 * When networkPrefixLength is non-null, depending on the prefix configuration (see {@link inet.ipaddr.AddressNetwork#getPrefixConfiguration()},
	 * this object may represent either a single address with that network prefix length, or the prefix subnet block containing all addresses with the same network prefix.
	 * <p>
	 * @param highBytes the 4 more significant bytes in network byte order
	 * @param lowBytes the 4 least significant bytes in network byte order
	 * @param networkPrefixLength the CIDR prefix, which can be null for no prefix length
	 */
	public IPv6Address(long highBytes, long lowBytes, Integer networkPrefixLength) throws AddressValueException {
		this(highBytes, lowBytes, networkPrefixLength, null);
	}

	private IPv6Address(long highBytes, long lowBytes, Integer networkPrefixLength, IPv6Zone zone) throws AddressValueException {
		super(thisAddress -> ((IPv6Address) thisAddress).getDefaultCreator().createSection(highBytes, lowBytes, IPv6Address.SEGMENT_COUNT, networkPrefixLength));
		this.zone = zone;
	}

	/**
	 * Constructs an IPv6 address or subnet.
	 * <p>
	 * When networkPrefixLength is non-null, depending on the prefix configuration (see {@link inet.ipaddr.AddressNetwork#getPrefixConfiguration()},
	 * this object may represent either a single address with that network prefix length, or the prefix subnet block containing all addresses with the same network prefix.
	 * <p>
	 * 
	 * @param lowerValueProvider supplies the 2 byte lower values for each segment
	 * @param upperValueProvider supplies the 2 byte upper values for each segment
	 * @param networkPrefixLength the CIDR network prefix length, which can be null for no prefix
	 */
	public IPv6Address(SegmentValueProvider lowerValueProvider, SegmentValueProvider upperValueProvider, Integer networkPrefixLength) throws AddressValueException {
		this(lowerValueProvider, upperValueProvider, networkPrefixLength, null);
	}

	/**
	 * Constructs an IPv6 address or subnet.
	 * 
	 * @param lowerValueProvider supplies the 2 byte lower values for each segment
	 * @param upperValueProvider supplies the 2 byte upper values for each segment
	 */
	public IPv6Address(SegmentValueProvider lowerValueProvider, SegmentValueProvider upperValueProvider) {
		this(lowerValueProvider, upperValueProvider, null, null);
	}
	
	/**
	 * Constructs an IPv6 address.
	 * <p>
	 * When networkPrefixLength is non-null, depending on the prefix configuration (see {@link inet.ipaddr.AddressNetwork#getPrefixConfiguration()},
	 * this object may represent either a single address with that network prefix length, or the prefix subnet block containing all addresses with the same network prefix.
	 * <p>
	 * 
	 * @param valueProvider supplies the 2 byte value for each segment
	 * @param networkPrefixLength the CIDR network prefix length, which can be null for no prefix
	 */
	public IPv6Address(SegmentValueProvider valueProvider, Integer networkPrefixLength) throws AddressValueException {
		this(valueProvider, valueProvider, networkPrefixLength);
	}
	
	/**
	 * Constructs an IPv6 address.
	 * 
	 * @param valueProvider supplies the 2 byte value for each segment
	 */
	public IPv6Address(SegmentValueProvider valueProvider) {
		this(valueProvider, (Integer) null);
	}
	
	/**
	 * Constructs an IPv6 address.
	 *
	 * @deprecated use {@link #IPv6Address(Address.SegmentValueProvider, Address.SegmentValueProvider, IPv6Zone)}
	 * @param lowerValueProvider supplies the 2 byte lower values for each segment
	 * @param upperValueProvider supplies the 2 byte upper values for each segment
	 * @throws AddressValueException if zone is invalid
	 */
	@Deprecated
	public IPv6Address(SegmentValueProvider lowerValueProvider, SegmentValueProvider upperValueProvider, CharSequence zone) throws AddressValueException {
		this(lowerValueProvider, upperValueProvider, checkZone(zone));
	}
	
	/**
	 * Constructs an IPv6 address.
	 *
	 * @param lowerValueProvider supplies the 2 byte lower values for each segment
	 * @param upperValueProvider supplies the 2 byte upper values for each segment
	 * @throws AddressValueException if zone is invalid
	 */
	public IPv6Address(SegmentValueProvider lowerValueProvider, SegmentValueProvider upperValueProvider, IPv6Zone zone) throws AddressValueException {
		this(lowerValueProvider, upperValueProvider, null, zone);
	}
	
	private IPv6Address(SegmentValueProvider lowerValueProvider, SegmentValueProvider upperValueProvider, Integer networkPrefixLength, IPv6Zone zone) throws AddressValueException {
		super(thisAddress -> ((IPv6Address) thisAddress).getDefaultCreator().createFullSectionInternal(lowerValueProvider, upperValueProvider, networkPrefixLength));
		this.zone = zone;
	}
	
	/**
	 * Constructs an IPv6 address from a modified EUI-64 (Extended Unique Identifier) address section and an IPv6 address section network prefix.
	 * <p>
	 * If the supplied MAC section is an 8 byte EUI-64, then it must match the required EUI-64 format of xx-xx-ff-fe-xx-xx
	 * with the ff-fe section in the middle.
	 * 
	 * If the supplied section is a 6 byte MAC-48 or EUI-48, then the ff-fe pattern will be inserted.
	 * <p>
	 * If the supplied section neither 6 nor 8 bytes, or if the 8-byte section does not have required EUI-64 format of xx-xx-ff-fe-xx-xx,
	 * {@link IncompatibleAddressException} will be thrown.
	 * <p>
	 * The constructor will toggle the MAC U/L (universal/local) bit as required with EUI-64.
	 * <p>
	 * Only the first 8 bytes (4 segments) of the IPv6Address are used to construct the address.
	 * <p>
	 * Any prefix length in the MAC address is ignored, while a prefix length in the IPv6 address is preserved but only up to the first 4 segments.
	 * 
	 * @throws IncompatibleAddressException if the MACAddress is an 8 byte MAC address incompatible with EUI-64 IPv6 format
	 * @param prefix an address from which the first four segments will be used as the same initial segments in the returned address
	 * @param eui
	 */
	public IPv6Address(IPv6Address prefix, MACAddress eui) throws IncompatibleAddressException {
		this(prefix.getSection(), eui.getSection());
	}
	
	/**
	 * Constructs an IPv6 address from a modified EUI-64 (Extended Unique Identifier) address section and an IPv6 address section network prefix.
	 * <p>
	 * If the supplied MAC section is an 8 byte EUI-64, then it must match the required EUI-64 format of xx-xx-ff-fe-xx-xx
	 * with the ff-fe section in the middle.
	 * 
	 * If the supplied section is a 6 byte MAC-48 or EUI-48, then the ff-fe pattern will be inserted.
	 * <p>
	 * If the supplied section neither 6 nor 8 bytes, or if the 8-byte section does not have required EUI-64 format of xx-xx-ff-fe-xx-xx,
	 * {@link IncompatibleAddressException} will be thrown.
	 * <p>
	 * The constructor will toggle the MAC U/L (universal/local) bit as required with EUI-64.
	 * <p>
	 * The IPv6 address section must be 8 bytes.
	 * <p>
	 * Any prefix length in the MAC address is ignored, while a prefix length in the IPv6 address is preserved but only up to the first 4 segments.
	 * @throws IncompatibleAddressException if the MACAddress is an 8 byte MAC address incompatible with EUI-64 IPv6 format
	 * @throws AddressValueException  if the IPv6 section is the wrong size or structure
	 * @param section
	 * @param eui
	 */
	public IPv6Address(IPv6AddressSection section, MACAddress eui) throws IncompatibleAddressException, AddressValueException  {
		this(section, eui.getSection());
	}
	
	/**
	 * Constructs an IPv6 address from a modified EUI-64 (Extended Unique Identifier) address and an IPv6 address section network prefix.
	 * <p>
	 * If the supplied address is an 8 byte EUI-64, then it must match the required EUI-64 format of xx-xx-ff-fe-xx-xx
	 * with the ff-fe section in the middle.
	 * 
	 * If the supplied address is a 6 byte MAC-48 or EUI-48, then the ff-fe pattern will be inserted.
	 * <p>
	 * The constructor will toggle the MAC U/L (universal/local) bit as required with EUI-64.
	 * <p>
	 * The IPv6 address section must be 8 bytes.
	 * <p>
	 * Any prefix length in the MAC address is ignored, while a prefix length in the IPv6 address is preserved but only up to the first 4 segments.
	 * @throws IncompatibleAddressException if the MACAddress is an 8 byte MAC address incompatible with EUI-64 IPv6 format
	 * @throws AddressValueException  if the MACAddress or IPv6 sections are the wrong size or structure
	 * @param section
	 * @param eui
	 */
	public IPv6Address(IPv6AddressSection section, MACAddressSection eui) throws IncompatibleAddressException, AddressValueException  {
		this(section, eui, (IPv6Zone) null);
	}
	
	/**
	 * Constructs an IPv6 address from a modified EUI-64 (Extended Unique Identifier) address and an IPv6 address section network prefix.
	 * 
	 * @deprecated use {@link #IPv6Address(IPv6AddressSection, MACAddressSection, IPv6Zone)}
	 * @param section
	 * @param eui
	 * @param zone
	 * @throws IncompatibleAddressException  if the MACAddress is an 8 byte MAC address incompatible with EUI-64 IPv6 format
	 * @throws AddressValueException  if the MACAddress or IPv6 sections are the wrong size or structure, or if zone is invalid
	 */
	@Deprecated
	public IPv6Address(IPv6AddressSection section, MACAddressSection eui, CharSequence zone) throws IncompatibleAddressException, AddressValueException  {
		this(section, eui, checkZone(zone));
	}
	
	/**
	 * Constructs an IPv6 address from a modified EUI-64 (Extended Unique Identifier) address and an IPv6 address section network prefix.
	 * 
	 * @param section
	 * @param eui
	 * @param zone
	 * @throws IncompatibleAddressException  if the MACAddress is an 8 byte MAC address incompatible with EUI-64 IPv6 format
	 * @throws AddressValueException  if the MACAddress or IPv6 sections are the wrong size or structure, or if zone is invalid
	 */
	public IPv6Address(IPv6AddressSection section, MACAddressSection eui, IPv6Zone zone) throws IncompatibleAddressException, AddressValueException  {
		super(thisAddress -> toFullEUI64Section(section, eui, ((IPv6Address) thisAddress).getDefaultCreator(), ((IPv6Address) thisAddress).getMACNetwork().getAddressCreator()));
		this.zone = zone;
	}
	
	static IPv6Zone checkZone(CharSequence zone) throws AddressValueException {
		if(zone == null) {
			return null;
		}
		String zoneStr = zone.toString().trim();
		if(zone.length() == 0) {
			return null;
		}
		int invalidIndex = Validator.validateZone(zoneStr);
		if(invalidIndex >= 0) {
			throw new AddressValueException("ipaddress.error.invalid.zone", invalidIndex);
		}
		return new IPv6Zone(zoneStr);
	}

	IPv6AddressCreator getDefaultCreator() {
		return getNetwork().getAddressCreator();
	}

	IPv6AddressCreator getCreator() {
		IPv6AddressCreator defaultCreator = getDefaultCreator();
		if(!hasZone()) {
			return defaultCreator;
		}
		IPv6AddressCreator creator = new IPv6AddressCreator(getNetwork(), defaultCreator.cache) {// using a lambda for this one results in a big performance hit, so we use anonymous class

			private static final long serialVersionUID = 4L;

			@Override
			protected IPv6Address createAddressInternal(IPv6AddressSegment segments[]) {
				IPv6AddressCreator creator = getDefaultCreator();
				return creator.createAddress(segments, zone); /* address creation */
			}

			@Override
			public IPv6Address createAddress(IPv6AddressSection section) {
				IPv6AddressCreator creator = getDefaultCreator();
				return creator.createAddress(section, zone); /* address creation */
			}
		};
		creator.useSegmentCache = defaultCreator.useSegmentCache;
		return creator;
	}

	private static IPv6Zone getZone(Inet6Address inet6Address) {
		NetworkInterface networkInterface = inet6Address.getScopedInterface();
		if(networkInterface != null) {
			return new IPv6Zone(networkInterface);
		}
		int scopeId = inet6Address.getScopeId();
		if(scopeId != 0) {
			return new IPv6Zone(scopeId);
		}
		return null;
	}

	private static IPv6AddressSection toFullEUI64Section(IPv6AddressSection section, MACAddressSection eui, IPv6AddressCreator creator, MACAddressCreator macCreator) throws AddressValueException, IncompatibleAddressException {
		boolean euiIsExtended = eui.isExtended();
		if(eui.addressSegmentIndex != 0) {
			throw new AddressPositionException(eui, eui.addressSegmentIndex);
		}
		if(section.addressSegmentIndex != 0) {
			throw new AddressPositionException(section, section.addressSegmentIndex);
		}
		if(section.getSegmentCount() < 4) {
			throw new AddressValueException(section, "ipaddress.mac.error.not.eui.convertible");
		}
		if(eui.getSegmentCount() != (euiIsExtended ? MACAddress.EXTENDED_UNIQUE_IDENTIFIER_64_SEGMENT_COUNT : MACAddress.EXTENDED_UNIQUE_IDENTIFIER_48_SEGMENT_COUNT)) {
			throw new AddressValueException(eui, "ipaddress.mac.error.not.eui.convertible");
		}
		IPv6AddressSegment segments[] = creator.createSegmentArray(8);
		section.getSegments(0, 4, segments, 0);
		Integer prefLength = section.getNetworkPrefixLength();
		Integer prefixLength = prefLength != null && (prefLength <= 64) ? prefLength : null;
		toEUI64Segments(segments, 4, eui, 0, eui.isExtended(), creator, macCreator, prefixLength);
		return creator.createSectionInternal(segments);
	}
	
	static IPv6AddressSegment[] toEUI64Segments(
			IPv6AddressSegment segments[],
			int ipv6StartIndex,
			MACAddressSection eui,
			int euiStartIndex,
			boolean isExtended,
			IPv6AddressCreator creator,
			MACAddressCreator macCreator,
			Integer prefixLength) 
					throws IncompatibleAddressException {
		int euiSegmentIndex = 0;
		int euiSegmentCount = eui.getSegmentCount();
		MACAddressSegment seg0, seg1, seg2, seg3, seg4, seg5, seg6, seg7;
		seg0 = (euiStartIndex == 0 && euiSegmentIndex < euiSegmentCount) ? eui.getSegment(euiSegmentIndex++) : null;
		seg1 = (euiStartIndex <= 1 && euiSegmentIndex < euiSegmentCount) ? eui.getSegment(euiSegmentIndex++) : null;
		seg2 = (euiStartIndex <= 2 && euiSegmentIndex < euiSegmentCount) ? eui.getSegment(euiSegmentIndex++) : null;
		seg3 = (euiStartIndex <= 3 && euiSegmentIndex < euiSegmentCount) ? eui.getSegment(euiSegmentIndex++) : null;
		seg4 = (euiStartIndex <= 4 && euiSegmentIndex < euiSegmentCount) ? eui.getSegment(euiSegmentIndex++) : null;
		seg5 = (euiStartIndex <= 5 && euiSegmentIndex < euiSegmentCount) ? eui.getSegment(euiSegmentIndex++) : null;
		seg6 = (euiStartIndex <= 6 && euiSegmentIndex < euiSegmentCount) ? eui.getSegment(euiSegmentIndex++) : null;
		seg7 = (euiStartIndex <= 7 && euiSegmentIndex < euiSegmentCount) ? eui.getSegment(euiSegmentIndex) : null;
		boolean isNotNull;

		MACAddressSegment zeroSegment = macCreator.createSegment(0);
		MACAddressSegment ffSegment = macCreator.createSegment(0xff);
		MACAddressSegment feSegment = macCreator.createSegment(0xfe);

		Integer currentPrefix = null;
		if(prefixLength != null) {
			//since the prefix comes from the ipv6 section and not the MAC section, any segment prefix for the MAC section is 0 or null
			//prefixes across segments have the pattern: null, null, ..., null, 0-16, 0, 0, ..., 0
			//So if the overall prefix is 0, then the prefix of every segment is 0
			currentPrefix = 0;
		}
		if((isNotNull = (seg0 != null)) || seg1 != null) {
			if(isNotNull) {
				if(seg1 == null) {
					seg1 = zeroSegment;
				}
			} else {
				seg0 = zeroSegment;
			}
			segments[ipv6StartIndex++] = join(creator, seg0, seg1, true /* only this first one gets the flipped bit */, currentPrefix);
		}
		
		//join 2 and 3 
		if(isExtended) {
			if((isNotNull = (seg2 != null)) || seg3 != null) {
				if(!isNotNull) {
					seg2 = zeroSegment;
					if(!seg3.matches(0xff)) {
						throw new IncompatibleAddressException(eui, "ipaddress.mac.error.not.eui.convertible");
					}
				}
				segments[ipv6StartIndex++] = join(creator, seg2, ffSegment, currentPrefix);
			}
			if((isNotNull = (seg4 != null)) || seg5 != null) {
				if(isNotNull) {
					if(!seg4.matches(0xfe)) {
						throw new IncompatibleAddressException(eui, "ipaddress.mac.error.not.eui.convertible");
					}
					if(seg5 == null) {
						seg5 = zeroSegment;
					}
				}
				segments[ipv6StartIndex++] = join(creator, feSegment, seg5, currentPrefix);
			}
		} else {
			if(seg2 != null) {
				segments[ipv6StartIndex++] = join(creator, seg2, ffSegment, currentPrefix);
			}
			if(seg3 != null) {
				segments[ipv6StartIndex++] = join(creator, feSegment, seg3, currentPrefix);
			}
			if((isNotNull = (seg4 != null)) || seg5 != null) {
				if(isNotNull) {
					if(seg5 == null) {
						seg5 = zeroSegment;
					}
				} else {
					seg4 = zeroSegment;
				}
				segments[ipv6StartIndex++] = join(creator, seg4, seg5, currentPrefix);
			}
		}
		if((isNotNull = (seg6 != null)) || seg7 != null) {
			if(isNotNull) {
				if(seg7 == null) {
					seg7 = zeroSegment;
				}
			} else {
				seg6 = zeroSegment;
			}
			segments[ipv6StartIndex] = join(creator, seg6, seg7, currentPrefix);
		}
		return segments;
	} 
	
	private static IPv6AddressSegment join(IPv6AddressCreator creator, MACAddressSegment macSegment0, MACAddressSegment macSegment1, Integer prefixLength) {
		return join(creator, macSegment0, macSegment1, false, prefixLength);
	}
	
	private static IPv6AddressSegment join(IPv6AddressCreator creator, MACAddressSegment macSegment0, MACAddressSegment macSegment1, boolean flip, Integer prefixLength) {
		if(macSegment0.isMultiple()) {
			// if the high segment has a range, the low segment must match the full range, 
			// otherwise it is not possible to create an equivalent range when joining
			if(!macSegment1.isFullRange()) {
				throw new IncompatibleAddressException(macSegment0, macSegment1, "ipaddress.error.invalidMACIPv6Range");
			}
		}
		int lower0 = macSegment0.getSegmentValue();
		int upper0 = macSegment0.getUpperSegmentValue();
		if(flip) {
			int mask2ndBit = 0x2;
			if(!macSegment0.matchesWithMask(mask2ndBit & lower0, mask2ndBit)) {
				throw new IncompatibleAddressException(macSegment0, "ipaddress.mac.error.not.eui.convertible");
			}
			lower0 ^= mask2ndBit;//flip the universal/local bit
			upper0 ^= mask2ndBit;
		}
		return creator.createSegment(
				(lower0 << 8) | macSegment1.getSegmentValue(), 
				(upper0 << 8) | macSegment1.getUpperSegmentValue(),
				prefixLength);
	}

	@Override
	public IPv6AddressNetwork getNetwork() {
		return defaultIpv6Network();
	}
	
	public MACAddressNetwork getMACNetwork() {
		return defaultMACNetwork();
	}
	
	public IPv4AddressNetwork getIPv4Network() {
		return defaultIpv4Network();
	}

	@Override
	public IPv6AddressSection getSection() {
		return (IPv6AddressSection) super.getSection();
	}

	@Override
	public IPv6AddressSection getSection(int index) {
		return getSection().getSection(index);
	}

	@Override
	public IPv6AddressSection getSection(int index, int endIndex) {
		return getSection().getSection(index, endIndex);
	}
	
	@Override
	public IPv6AddressSegment getDivision(int index) {
		return getSegment(index);
	}
	
	@Override
	public IPv6AddressSegment getSegment(int index) {
		return getSection().getSegment(index);
	}
	
	@Override
	public IPv6AddressSegment[] getSegments() {
		return getSection().getSegments();
	}

	public boolean isEUI64() {
		return getSection().isEUI64();
	}

	public MACAddress toEUI(boolean extended) {
		MACAddressSection section = getSection().toEUI(extended);
		if(section == null) {
			return null;
		}
		MACAddressCreator creator = getMACNetwork().getAddressCreator();
		return creator.createAddress(section);
	}

	@Override
	public IPAddressStringDivisionSeries[] getParts(IPStringBuilderOptions options) {
		return getParts(IPv6StringBuilderOptions.from(options));
	}
	
	public IPAddressStringDivisionSeries[] getParts(IPv6StringBuilderOptions options) {
		IPAddressStringDivisionSeries parts[] = getSection().getParts(options);
		IPv4Address ipv4Addr = getConverted(options);
		if(ipv4Addr != null) {
			IPAddressStringDivisionSeries ipv4Parts[] = ipv4Addr.getParts(options.ipv4ConverterOptions);
			IPAddressStringDivisionSeries tmp[] = parts;
			parts = new IPAddressStringDivisionSeries[tmp.length + ipv4Parts.length];
			System.arraycopy(tmp, 0, parts, 0, tmp.length);
			System.arraycopy(ipv4Parts,  0, parts, tmp.length, ipv4Parts.length);
		}
		return parts;
	}
	
	@Override
	public int getSegmentCount() {
		return SEGMENT_COUNT;
	}
	
	@Override
	public int getByteCount() {
		return BYTE_COUNT;
	}
	
	@Override
	public int getBitCount() {
		return BIT_COUNT;
	}
	
	void cache(IPv6Address lower, IPv6Address upper) {
		if((lower != null || upper != null) && getSection().getSingleLowestOrHighestSection() == null) {
			getSection().cache(lower != null ? lower.getSection() : null, upper != null ? upper.getSection() : null);
			IPv6AddressCache cache = addressCache;
			if(cache == null || (lower != null && cache.lower == null) || (upper != null && cache.upper == null)) {
				synchronized(this) {
					cache = addressCache;
					boolean create = (cache == null);
					if(create) {
						addressCache = cache = new IPv6AddressCache();
						cache.lower = lower;
						cache.upper = upper;
					} else {
						if(cache.lower == null) {
							cache.lower = lower;
						}
						if(cache.upper == null) {
							cache.upper = upper;
						}
					}
				}
			}
		}
	}

	private IPv6Address getLowestOrHighest(boolean lowest, boolean excludeZeroHost) {
		IPv6AddressSection currentSection = getSection();
		IPv6AddressSection sectionResult = currentSection.getLowestOrHighestSection(lowest, excludeZeroHost);
		if(sectionResult == currentSection) {
			return this;
		} else if(sectionResult == null) {
			return null;
		}
		IPv6Address result = null;
		IPv6AddressCache cache = addressCache;
		if(cache == null || 
			(result = lowest ? (excludeZeroHost ? cache.lowerNonZeroHost : cache.lower) : cache.upper) == null) {
			synchronized(this) {
				cache = addressCache;
				boolean create = (cache == null);
				if(create) {
					addressCache = cache = new IPv6AddressCache();
				} else {
					if(lowest) {
						if(excludeZeroHost) {
							create = (result = cache.lowerNonZeroHost) == null;
						} else {
							create = (result = cache.lower) == null;
						}
					} else {
						create = (result = cache.upper) == null;
					}
				}
				if(create) {
					result = getCreator().createAddress(sectionResult);
					if(lowest) {
						if(excludeZeroHost) {
							 cache.lowerNonZeroHost = result;
						} else {
							cache.lower = result;
						}
					} else {
						cache.upper = result;
					}
				}
			}
		}
		return result;
	}
	
	@Override
	public IPv6Address getLowerNonZeroHost() {
		return getLowestOrHighest(true, true);
	}
	
	@Override
	public IPv6Address getLower() {
		return getLowestOrHighest(true, false);
	}
	
	@Override
	public IPv6Address getUpper() {
		return getLowestOrHighest(false, false);
	}

	/**
	 * Returns a pair of longs with the lower address value in the range of this individual address or subnet.
	 * The high bits are in the first element, the low bits in the second.
	 * 
	 * @return
	 */
	public long[] longValues() {
		return getSection().longValues();
	}

	/**
	 * Returns a pair of longs with the upper address value in the range of this individual address or subnet.
	 * The high bits are in the first element, the low bits in the second.
	 * 
	 * @return
	 */
	public long[] upperLongValues() {
		return getSection().upperLongValues();
	}

	IPv6TrieKeyData getTrieKeyCache() {
		IPv6TrieKeyData keyData = cachedTrieKeyData;
		if(keyData == null) {
			keyData = new IPv6TrieKeyData();
			Integer prefLen = getPrefixLength();
			keyData.prefixLength = prefLen;
			long vals[] = longValues();
			keyData.uint64HighVal = vals[0];
			keyData.uint64LowVal = vals[1];
			if(prefLen != null) {
				int bits = prefLen;
				IPv6Address mask = getNetwork().getNetworkMask(bits, false);
				vals = mask.longValues();
				keyData.mask64HighVal = vals[0];
				keyData.mask64LowVal = vals[1];
				if(bits > 63) {
					keyData.nextBitMask64Val = 0x8000000000000000L >>> (bits - 64);
				} else {
					keyData.nextBitMask64Val = 0x8000000000000000L >>> bits;
				}
			}
			cachedTrieKeyData = keyData;
		}
		return keyData;
	}

	/**
	 * Replaces segments starting from startIndex and ending before endIndex with the same number of segments starting at replacementStartIndex from the replacement section
	 * 
	 * @param startIndex
	 * @param endIndex
	 * @param replacement
	 * @param replacementIndex
	 * @throws IndexOutOfBoundsException
	 * @return
	 */
	public IPv6Address replace(int startIndex, int endIndex, IPv6Address replacement, int replacementIndex) {
		return checkIdentity(getSection().replace(startIndex, endIndex, replacement.getSection(), replacementIndex, replacementIndex + (endIndex - startIndex)));
	}

	/**
	 * Replaces segments starting from startIndex with as many segments as possible from the replacement section
	 * 
	 * @param startIndex
	 * @param replacement
	 * @throws IndexOutOfBoundsException
	 * @return
	 */
	public IPv6Address replace(int startIndex, IPv6AddressSection replacement) {
		int replacementCount = Math.min(IPv6Address.SEGMENT_COUNT - startIndex, replacement.getSegmentCount());
		return checkIdentity(getSection().replace(startIndex, startIndex + replacementCount, replacement, 0, replacementCount));
	}

	@Override
	public IPv6Address reverseBits(boolean perByte) {
		return getCreator().createAddress(getSection().reverseBits(perByte));
	}

	@Override
	public IPv6Address reverseBytes() {
		return checkIdentity(getSection().reverseBytes());
	}

	@Override
	public IPv6Address reverseBytesPerSegment() {
		return checkIdentity(getSection().reverseBytesPerSegment());
	}

	@Override
	public IPv6Address reverseSegments() {
		return checkIdentity(getSection().reverseSegments());
	}

	@Override
	public Iterator<IPv6AddressSegment[]> segmentsNonZeroHostIterator() {
		return getSection().segmentsNonZeroHostIterator();
	}

	@Override
	public Iterator<IPv6AddressSegment[]> segmentsIterator() {
		return getSection().segmentsIterator();
	}

	@Override
	public AddressComponentRangeSpliterator<IPv6Address, IPv6AddressSegment[]> segmentsSpliterator() {
		return getSection().segmentsSpliterator(this, getCreator());
	}

	@Override
	public Stream<IPv6AddressSegment[]> segmentsStream() {
		return StreamSupport.stream(segmentsSpliterator(), false);
	}

	@Override
	public Iterator<IPv6Address> prefixBlockIterator() {
		return getSection().prefixIterator(this, getCreator(), true);
	}

	@Override
	public AddressComponentSpliterator<IPv6Address> prefixBlockSpliterator() {
		return getSection().prefixSpliterator(this, getCreator(), true);
	}

	@Override
	public Stream<IPv6Address> prefixBlockStream() {
		return StreamSupport.stream(prefixBlockSpliterator(), false);
	}

	@Override
	public Iterator<IPv6Address> prefixBlockIterator(int prefixLength) {
		return getSection().prefixIterator(this, getCreator(), true, prefixLength);
	}

	@Override
	public AddressComponentSpliterator<IPv6Address> prefixBlockSpliterator(int prefixLength) {
		return getSection().prefixSpliterator(this, getCreator(), true, prefixLength);
	}

	@Override
	public Stream<IPv6Address> prefixBlockStream(int prefixLength) {
		return StreamSupport.stream(prefixBlockSpliterator(prefixLength), false);
	}

	@Override
	public Iterator<IPv6Address> prefixIterator() {
		return getSection().prefixIterator(this, getCreator(), false);
	}

	@Override
	public AddressComponentSpliterator<IPv6Address> prefixSpliterator() {
		return getSection().prefixSpliterator(this, getCreator(), false);
	}

	@Override
	public Stream<IPv6Address> prefixStream() {
		return StreamSupport.stream(prefixSpliterator(), false);
	}

	@Override
	public Iterator<IPv6Address> prefixIterator(int prefixLength) {
		return getSection().prefixIterator(this, getCreator(), false, prefixLength);
	}

	@Override
	public AddressComponentSpliterator<IPv6Address> prefixSpliterator(int prefixLength) {
		return getSection().prefixSpliterator(this, getCreator(), false, prefixLength);
	}

	@Override
	public Stream<IPv6Address> prefixStream(int prefixLength) {
		return StreamSupport.stream(prefixSpliterator(prefixLength), false);
	}

	@Override
	public Iterator<IPv6Address> blockIterator(int segmentCount) {
		return getSection().blockIterator(this, getCreator(), segmentCount);
	}
	
	@Override
	public AddressComponentSpliterator<IPv6Address> blockSpliterator(int segmentCount) {
		return getSection().blockSpliterator(this, getCreator(), segmentCount);
	}
	
	@Override
	public Stream<IPv6Address> blockStream(int segmentCount) {
		return StreamSupport.stream(blockSpliterator(segmentCount), false);
	}

	@SuppressWarnings("unchecked")
	@Override
	public Iterator<IPv6Address> sequentialBlockIterator() {
		return (Iterator<IPv6Address>) super.sequentialBlockIterator();
	}

	@SuppressWarnings("unchecked")
	@Override
	public AddressComponentSpliterator<IPv6Address> sequentialBlockSpliterator() {
		return (AddressComponentSpliterator<IPv6Address>) super.sequentialBlockSpliterator();
	}

	@SuppressWarnings("unchecked")
	@Override
	public Stream<IPv6Address> sequentialBlockStream() {
		return (Stream<IPv6Address>) super.sequentialBlockStream();
	}

	@Override
	public Iterator<IPv6Address> iterator() {
		return getSection().iterator(this, getCreator(), null);
	}

	@Override
	public AddressComponentSpliterator<IPv6Address> spliterator() {
		return getSection().spliterator(this, getCreator(), false);
	}

	@Override
	public Stream<IPv6Address> stream() {
		return StreamSupport.stream(spliterator(), false);
	}

	@Override
	public Iterator<IPv6Address> nonZeroHostIterator() {
		Predicate<IPv6AddressSegment[]> excludeFunc = null;
		if(includesZeroHost()) {
			int prefLength = getNetworkPrefixLength();
			excludeFunc = segments -> getSection().isZeroHost(segments, prefLength);
		}
		return getSection().iterator(this, getCreator(), excludeFunc);
	}

	@Override
	public Iterable<IPv6Address> getIterable() {
		return this;
	}

	public IPv6Address increment(BigInteger increment) {
		return checkIdentity(getSection().increment(increment));
	}

	@Override
	public IPv6Address increment(long increment) {
		return checkIdentity(getSection().increment(increment));
	}
	
	@Override
	public IPv6Address incrementBoundary(long increment) {
		return checkIdentity(getSection().incrementBoundary(increment));
	}

	/**
	 * If this address is IPv4 convertible, returns that address.
	 * Otherwise, returns null.
	 * <p>
	 * You can also use {@link #isIPv4Convertible()} to determine convertibility.  Both use an instance of {@link IPAddressConverter.DefaultAddressConverter} which uses IPv4-mapped address mappings from rfc 4038.
	 * <p>
	 * Override this method and {@link IPv6Address#isIPv4Convertible()} if you wish to map IPv6 to IPv4 according to the mappings defined by
	 * in {@link IPv6Address#isIPv4Compatible()}, {@link IPv6Address#isIPv4Mapped()}, {@link IPv6Address#is6To4()} or by some other mapping.
	 * <p>
	 * For the reverse mapping, see {@link IPv4Address#toIPv6()} 
	 */
	@Override
	public IPv4Address toIPv4() {
		IPAddressConverter conv = DEFAULT_ADDRESS_CONVERTER;
		return conv.toIPv4(this);
	}
	
	@Override
	public IPv6Address toIPv6() {
		return this;
	}
	
	@Override
	public boolean isIPv6() {
		return true;
	}
	
	/**
	 * Determines whether this address can be converted to IPv4. 
	 * Override this method to convert in your own way.
	 * The default behaviour is to use isIPv4Mapped()
	 * 
	 * You should also override {@link #toIPv4()} to match the conversion.
	 * 
	 * @return
	 */
	@Override
	public boolean isIPv4Convertible() {
		IPAddressConverter conv = DEFAULT_ADDRESS_CONVERTER;
		return conv.isIPv4Convertible(this);
	}
	
	@Override
	public boolean isIPv6Convertible() {
		return true;
	}

	/**
	 * ::ffff:x:x/96 indicates IPv6 address mapped to IPv4
	 */
	public IPv4AddressSection toMappedIPv4Segments() {
		if(isIPv4Mapped()) {
			return getSection().getEmbeddedIPv4AddressSection();
		}
		return null;
	}

	/**
	 * Returns the second and third segments as an {@link IPv4Address}.
	 * 
	 * This can be used for IPv4 or for IPv6 6to4 addresses convertible to IPv4.
	 * 
	 * @return the address
	 */
	public IPv4Address get6To4IPv4Address() {
		return getEmbeddedIPv4Address(2);
	}

	/**
	 * Returns the embedded {@link IPv4Address} in the lowest (least-significant) two segments.
	 * This is used by IPv4-mapped, IPv4-compatible, ISATAP addresses and 6over4 addresses
	 * 
	 * @return the embedded {@link IPv4Address}
	 */
	public IPv4Address getEmbeddedIPv4Address() {
		IPv4AddressCreator creator = getIPv4Network().getAddressCreator();
		return creator.createAddress(getSection().getEmbeddedIPv4AddressSection()); /* address creation */
	}
	
	/**
	 * Produces an IPv4 address from any sequence of 4 bytes in this IPv6 address.
	 * 
	 * @param byteIndex the byte index to start
	 * @throws IndexOutOfBoundsException if the index is less than zero or bigger than 7
	 * @return
	 */
	public IPv4Address getEmbeddedIPv4Address(int byteIndex) {
		if(byteIndex == IPv6Address.MIXED_ORIGINAL_SEGMENT_COUNT * IPv6Address.BYTES_PER_SEGMENT) {
			return getEmbeddedIPv4Address();
		}
		IPv4AddressCreator creator = getIPv4Network().getAddressCreator();
		return creator.createAddress(getSection().getEmbeddedIPv4AddressSection(byteIndex, byteIndex + IPv4Address.BYTE_COUNT)); /* address creation */
	}
	
	@Override
	public boolean isLocal() {
		if(isMulticast()) {
			/*
			 [RFC4291][RFC7346]
			 11111111|flgs|scop 
				scope 4 bits
				 1  Interface-Local scope
		         2  Link-Local scope
		         3  Realm-Local scope
		         4  Admin-Local scope
		         5  Site-Local scope
		         8  Organization-Local scope
		         E  Global scope
			 */
			IPv6AddressSegment firstSeg = getSegment(0);
			if(firstSeg.matchesWithMask(8, 0xf)) {
				return true;
			}
			if(firstSeg.getValueCount() <= 5 && 
					(firstSeg.getSegmentValue() & 0xf) >= 1 && (firstSeg.getUpperSegmentValue() & 0xf) <= 5) {
				//all values fall within the range from interface local to site local
				return true;
			}
			
			//source specific multicast
			//rfc4607 and https://www.iana.org/assignments/multicast-addresses/multicast-addresses.xhtml
			//FF3X::8000:0 - FF3X::FFFF:FFFF	Reserved for local host allocation	[RFC4607]
			if(firstSeg.matchesWithPrefixMask(0xff30, 12) && getSegment(6).matchesWithPrefixMask(0x8000, 1)) {
				return true;
			}
		}
		return isLinkLocal() || isSiteLocal() || isUniqueLocal() || isAnyLocal();
	}
	
	/**
	 * @see java.net.InetAddress#isLinkLocalAddress()
	 */
	@Override
	public boolean isLinkLocal() {
		IPv6AddressSegment firstSeg = getSegment(0);
		return (isMulticast() && firstSeg.matchesWithMask(2, 0xf)) || // ffx2::/16
				//1111 1110 10 .... fe8x currently only in use
				firstSeg.matchesWithPrefixMask(0xfe80, 10);
	}
	
	/**
	 * @see java.net.InetAddress#isSiteLocalAddress()
	 */
	public boolean isSiteLocal() {
		IPv6AddressSegment firstSeg = getSegment(0);
		return (isMulticast() && firstSeg.matchesWithMask(5, 0xf)) ||  // ffx5::/16
				//1111 1110 11 ...
				firstSeg.matchesWithPrefixMask(0xfec0, 10); // deprecated RFC 3879
	}
	
	public boolean isUniqueLocal() {
		//RFC 4193
		return getSegment(0).matchesWithPrefixMask(0xfc00, 7);
	}
	
	/**
	 * Whether the address is IPv4-mapped
	 * 
	 * ::ffff:x:x/96 indicates IPv6 address mapped to IPv4
	 */
	public boolean isIPv4Mapped() {
		//::ffff:x:x/96 indicates IPv6 address mapped to IPv4
		if(getSegment(5).matches(IPv6Address.MAX_VALUE_PER_SEGMENT)) {
			for(int i = 0; i < 5; i++) {
				if(!getSegment(i).isZero()) {
					return false;
				}
			}
			return true;
		}
		return false;
	}
	
	/**
	 * Whether the address is IPv4-compatible
	 * 
	 * @see java.net.Inet6Address#isIPv4CompatibleAddress()
	 */
	public boolean isIPv4Compatible() {
		return getSegment(0).isZero() && getSegment(1).isZero() && getSegment(2).isZero() &&
				getSegment(3).isZero() && getSegment(4).isZero() && getSegment(5).isZero();
	}
	
	/**
	 * Whether the address is IPv6 to IPv4 relay
	 * @see #get6To4IPv4Address()
	 */
	public boolean is6To4() {
		//2002::/16
		return getSegment(0).matches(0x2002);
	}
	
	/**
	 * Whether the address is 6over4
	 */
	public boolean is6Over4() {
		return getSegment(0).matches(0xfe80) && 
				getSegment(1).isZero() && getSegment(2).isZero() &&
				getSegment(3).isZero() && getSegment(4).isZero() &&
				getSegment(5).isZero();
	}
	
	/**
	 * Whether the address is Teredo
	 */
	public boolean isTeredo() {
		//2001::/32
		return getSegment(0).matches(0x2001) && getSegment(1).isZero();
	}

	/**
	 * Whether the address is ISATAP
	 */
	public boolean isIsatap() {
		// 0,1,2,3 is fe80::
		// 4 can be 0200
		return getSegment(0).matches(0xfe80) &&
				getSegment(1).isZero() &&
				getSegment(2).isZero() &&
				getSegment(3).isZero() &&
				(getSegment(4).isZero() || getSegment(4).matches(0x200)) && 
				getSegment(5).matches(0x5efe);
	}
	
	/**
	 * 
	 * @return Whether the address is IPv4 translatable as in rfc 2765
	 */
	public boolean isIPv4Translatable() { //rfc 2765  
		//::ffff:0:x:x/96 indicates IPv6 addresses translated from IPv4
		return getSegment(4).matches(0xffff) && 
				getSegment(5).isZero() &&
				getSegment(0).isZero() &&
				getSegment(1).isZero() &&
				getSegment(2).isZero() &&
				getSegment(3).isZero();
	}
	
	/**
	 * Whether the address has the well-known prefix for IPv4 translatable addresses as in rfc 6052 and 6144
	 * @return
	 */
	public boolean isWellKnownIPv4Translatable() { //rfc 6052 rfc 6144
		//64:ff9b::/96 prefix for auto ipv4/ipv6 translation
		if(getSegment(0).matches(0x64) && getSegment(1).matches(0xff9b)) {
			for(int i=2; i<=5; i++) {
				if(!getSegment(i).isZero()) {
					return false;
				}
			}
			return true;
		}
		return false;
	}
	
	@Override
	public boolean isMulticast() {
		// 11111111...
		return getSegment(0).matchesWithPrefixMask(0xff00, 8);
	}

	/**
	 * @see java.net.InetAddress#isLoopbackAddress()
	 */
	@Override
	public boolean isLoopback() {
		//::1
		int i=0;
		for(; i < getSegmentCount() - 1; i++) {
			if(!getSegment(i).isZero()) {
				return false;
			}
		}
		return getSegment(i).matches(1);
	}
	
	@Override
	public IPv6Address intersect(IPAddress other) throws AddressConversionException {
		IPv6AddressSection thisSection = getSection();
		IPv6Address otherAddr = convertArg(other);
		IPv6AddressSection section = thisSection.intersect(otherAddr.getSection());
		if(section == null) {
			return null;
		}
		//if they have the same zone, then use it in the intersection, otherwise ignore the zones
		IPv6AddressCreator creator = isSameZone(otherAddr) ? getCreator() : getDefaultCreator();
		IPv6Address result = creator.createAddress(section);
		return result;
	}
	
	@Override
	public IPv6Address[] subtract(IPAddress other) throws AddressConversionException {
		IPv6AddressSection thisSection = getSection();
		IPv6AddressSection sections[] = thisSection.subtract(convertArg(other).getSection());
		if(sections == null) {
			return null;
		}
		IPv6Address result[] = new IPv6Address[sections.length];
		for(int i = 0; i < result.length; i++) {
			result[i] = getCreator().createAddress(sections[i]); /* address creation */
		}
		return result;
	}

	private IPv6Address checkIdentity(IPv6AddressSection newSection) {
		if(newSection == getSection()) {
			return this;
		}
		return getCreator().createAddress(newSection);
	}
	
	@Override
	public IPv6Address adjustPrefixBySegment(boolean nextSegment) {
		return checkIdentity(getSection().adjustPrefixBySegment(nextSegment));
	}
	
	@Override
	public IPv6Address adjustPrefixBySegment(boolean nextSegment, boolean zeroed) {
		return checkIdentity(getSection().adjustPrefixBySegment(nextSegment, zeroed));
	}

	@Override
	public IPv6Address adjustPrefixLength(int adjustment) {
		return checkIdentity(getSection().adjustPrefixLength(adjustment));
	}

	@Override
	public IPv6Address adjustPrefixLength(int adjustment, boolean zeroed) {
		return checkIdentity(getSection().adjustPrefixLength(adjustment, zeroed));
	}

	@Override
	public IPv6Address setPrefixLength(int prefixLength) throws PrefixLenException {
		return setPrefixLength(prefixLength, true);
	}

	@Override
	public IPv6Address setPrefixLength(int prefixLength, boolean zeroed) throws PrefixLenException {
		return checkIdentity(getSection().setPrefixLength(prefixLength, zeroed));
	}

	@Override
	public IPv6Address setPrefixLength(int prefixLength, boolean zeroed, boolean zeroHostIsBlock) throws PrefixLenException {
		return checkIdentity(getSection().setPrefixLength(prefixLength, zeroed, zeroHostIsBlock));
	}

	@Deprecated
	@Override
	public IPv6Address applyPrefixLength(int networkPrefixLength) throws PrefixLenException {
		return checkIdentity(getSection().applyPrefixLength(networkPrefixLength));
	}

	@Override @Deprecated
	public IPv6Address removePrefixLength() {
		return removePrefixLength(true);
	}
	
	@Override
	public IPv6Address withoutPrefixLength() {
		return removePrefixLength(false);
	}
	
	@Override @Deprecated
	public IPv6Address removePrefixLength(boolean zeroed) {
		return checkIdentity(getSection().removePrefixLength(zeroed));
	}

	@Override
	protected IPv6Address convertArg(IPAddress arg) throws AddressConversionException {
		IPv6Address converted = arg.toIPv6();
		if(converted == null) {
			throw new AddressConversionException(this, arg);
		}
		return converted;
	}
	
	@Override
	public IPv6Address toZeroHost() {
		return toZeroHost(false);
	}

	@Override
	protected IPv6Address toZeroHost(boolean boundariesOnly) {
		if(!isPrefixed()) {
			IPv6AddressNetwork network = getNetwork();
			PrefixConfiguration config = network.getPrefixConfiguration();
			IPv6Address addr = network.getNetworkMask(0, !config.allPrefixedAddressesAreSubnets());
			if(config.zeroHostsAreSubnets()) {
				addr = addr.getLower();
			}
			return addr;
		}
		if(includesZeroHost() && isSingleNetwork()) {
			return getLower();//cached
		}
		return checkIdentity(getSection().createZeroHost(boundariesOnly));
	}

	@Override
	public IPv6Address toZeroHost(int prefixLength) {
		if(isPrefixed() && prefixLength == getNetworkPrefixLength()) {
			return toZeroHost();
		}
		return checkIdentity(getSection().toZeroHost(prefixLength));
	}
	
	@Override
	public IPv6Address toZeroNetwork() {
		if(!isPrefixed()) {
			return getNetwork().getHostMask(getBitCount());
		}
		return checkIdentity(getSection().createZeroNetwork());
	}

	@Override
	public IPv6Address toMaxHost() {
		if(!isPrefixed()) {
			IPv6Address resultNoPrefix = getNetwork().getHostMask(0);
			if(getNetwork().getPrefixConfiguration().allPrefixedAddressesAreSubnets()) {
				return resultNoPrefix;
			}
			return resultNoPrefix.setPrefixLength(0);
		}
		if(includesMaxHost() && isSingleNetwork()) {
			return getUpper();
		}
		return checkIdentity(getSection().createMaxHost());
	}
	
	@Override
	public IPv6Address toMaxHost(int prefixLength) {
		if(isPrefixed() && prefixLength == getNetworkPrefixLength()) {
			return toMaxHost();
		}
		return checkIdentity(getSection().toMaxHost(prefixLength));
	}
	
	@Override
	public IPv6Address mask(IPAddress mask, boolean retainPrefix) throws IncompatibleAddressException, AddressConversionException {
		return checkIdentity(getSection().mask(convertArg(mask).getSection(), retainPrefix));
	}

	@Override
	public IPv6Address mask(IPAddress mask) throws IncompatibleAddressException, AddressConversionException {
		return mask(mask, false);
	}

	@Override
	public IPv6Address maskNetwork(IPAddress mask, int networkPrefixLength) throws IncompatibleAddressException, PrefixLenException, AddressConversionException {
		return checkIdentity(getSection().maskNetwork(convertArg(mask).getSection(), networkPrefixLength));
	}
	
	@Override
	public IPv6Address bitwiseOr(IPAddress mask, boolean retainPrefix) throws IncompatibleAddressException, AddressConversionException {
		return checkIdentity(getSection().bitwiseOr(convertArg(mask).getSection(), retainPrefix));
	}
	
	@Override
	public IPv6Address bitwiseOr(IPAddress mask) throws IncompatibleAddressException, AddressConversionException {
		return bitwiseOr(mask, false);
	}
	
	@Override
	public IPv6Address bitwiseOrNetwork(IPAddress mask, int networkPrefixLength) throws IncompatibleAddressException, PrefixLenException, AddressConversionException {
		return checkIdentity(getSection().bitwiseOrNetwork(convertArg(mask).getSection(), networkPrefixLength));
	}

	@Override
	public IPv6Address getHostMask() {
		return (IPv6Address) super.getHostMask();
	}

	@Override
	public IPv6Address getNetworkMask() {
		return (IPv6Address) super.getNetworkMask();
	}

	@Override
	public IPv6AddressSection getNetworkSection() {
		return getSection().getNetworkSection();
	}
	
	@Override
	public IPv6AddressSection getNetworkSection(int networkPrefixLength) throws PrefixLenException {
		return getSection().getNetworkSection(networkPrefixLength);
	}
	
	@Override
	public IPv6AddressSection getNetworkSection(int networkPrefixLength, boolean withPrefixLength) throws PrefixLenException {
		return getSection().getNetworkSection(networkPrefixLength, withPrefixLength);
	}
	
	@Override
	public IPv6AddressSection getHostSection(int networkPrefixLength) throws PrefixLenException {
		return getSection().getHostSection(networkPrefixLength);
	}
	
	@Override
	public IPv6AddressSection getHostSection() {
		return getSection().getHostSection();
	}
	
	@Override
	public IPv6Address toPrefixBlock() {
		Integer prefixLength = getNetworkPrefixLength();
		if(prefixLength == null || getNetwork().getPrefixConfiguration().allPrefixedAddressesAreSubnets()) {
			return this;
		}
		return toPrefixBlock(prefixLength);
	}

	@Override
	public IPv6Address toPrefixBlock(int networkPrefixLength) throws PrefixLenException {
		return checkIdentity(getSection().toPrefixBlock(networkPrefixLength));
	}

	@Override
	public IPv6Address assignPrefixForSingleBlock() {
		return (IPv6Address) super.assignPrefixForSingleBlock();
	}

	@Override
	public IPv6Address assignMinPrefixForBlock() {
		return (IPv6Address) super.assignMinPrefixForBlock();
	}

	@Override
	public IPv6Address coverWithPrefixBlock() {
		return (IPv6Address) IPv6AddressSection.coverWithPrefixBlock(this, getLower(), getUpper());
	}

	@Override
	public IPv6Address coverWithPrefixBlock(IPAddress other) throws AddressConversionException {
		return IPv6AddressSection.coverWithPrefixBlock(
				this.removeZone(),
				convertArg(other).removeZone(),
				IPv6Address::getLower,
				IPv6Address::getUpper, 
				Address.ADDRESS_LOW_VALUE_COMPARATOR::compare);
	}

	/**
	 * Produces an array of prefix blocks that cover the same set of addresses as this.
	 * <p>
	 * Unlike {@link #spanWithPrefixBlocks(IPAddress)} this method only includes addresses that are a part of this subnet.
	 */
	@Override
	public IPv6Address[] spanWithPrefixBlocks() {
		if(isSequential()) {
			if(isSinglePrefixBlock()) {
				return new IPv6Address[] {removeZone()};
			}
			return spanWithPrefixBlocks(this);
		}
		@SuppressWarnings("unchecked")
		ArrayList<IPv6Address> list = (ArrayList<IPv6Address>) removeZone().spanWithBlocks(true);
		return list.toArray(new IPv6Address[list.size()]);
	}
	
	@Override
	public IPv6Address[] spanWithPrefixBlocks(IPAddress other) throws AddressConversionException {
		return IPAddress.getSpanningPrefixBlocks(
				removeZone(),
				convertArg(other).removeZone(),
				IPv6Address::getLower,
				IPv6Address::getUpper,
				Address.ADDRESS_LOW_VALUE_COMPARATOR::compare,
				IPv6Address::assignPrefixForSingleBlock,
				IPv6Address::withoutPrefixLength,
				getCreator()::createAddressArray);
	}
	
	/**
	 * Produces an array of blocks that are sequential that cover the same set of addresses as this.
	 * <p>
	 * This array can be shorter than that produced by {@link #spanWithPrefixBlocks()} and is never longer.
	 * <p>
	 * Unlike {@link #spanWithSequentialBlocks(IPAddress)} this method only includes addresses that are a part of this subnet.
	 */
	@Override
	public IPv6Address[] spanWithSequentialBlocks() throws AddressConversionException {
		if(isSequential()) {
			return new IPv6Address[] { withoutPrefixLength().removeZone() };
		}
		@SuppressWarnings("unchecked")
		ArrayList<IPv6Address> list = (ArrayList<IPv6Address>) removeZone().spanWithBlocks(false);
		return list.toArray(new IPv6Address[list.size()]);
	}

	@Override
	public IPv6Address[] spanWithSequentialBlocks(IPAddress other) throws AddressConversionException {
		return IPAddress.getSpanningSequentialBlocks(
				this.removeZone(),
				convertArg(other).removeZone(),
				IPv6Address::getLower,
				IPv6Address::getUpper,
				Address.ADDRESS_LOW_VALUE_COMPARATOR::compare,
				IPv6Address::withoutPrefixLength,
				getDefaultCreator());
	}

	@Override
	public IPv6AddressSeqRange spanWithRange(IPAddress other) throws AddressConversionException {
		return toSequentialRange(other);
	}

	@Override
	public IPv6Address[] mergeToPrefixBlocks(IPAddress ...addresses) throws AddressConversionException {
		if(addresses.length == 0) {
			if(isSinglePrefixBlock()) {
				return new IPv6Address[] {removeZone()};
			}
		}
		IPAddress[] converted = getConverted(addresses);
		List<IPAddressSegmentSeries> blocks = getMergedPrefixBlocks(converted);
		return blocks.toArray(new IPv6Address[blocks.size()]);
	}

	private IPAddress[] getConverted(IPAddress... addresses) {
		IPAddress converted[] = new IPAddress[addresses.length + 1];
		for(int i = 0, j = 1; i < addresses.length; i = j++) {
			converted[j] = convertArg(addresses[i]).removeZone();
		}
		converted[0] = removeZone();
		return converted;
	}
	
	@Override
	public IPv6Address[] mergeToSequentialBlocks(IPAddress ...addresses) throws AddressConversionException {
		if(addresses.length == 0) {
			if(isSequential()) {
				return new IPv6Address[] {removeZone()};
			}
		}
		addresses = addresses.clone();
		for(int i = 0; i < addresses.length; i++) {
			addresses[i] = convertArg(addresses[i]).removeZone();
		}
		
		IPAddress[] converted = getConverted(addresses);
		List<IPAddressSegmentSeries> blocks = getMergedSequentialBlocks(converted, getDefaultCreator());
		return blocks.toArray(new IPv6Address[blocks.size()]);
	}

	/**
	 * Returns whether {@link #getZone()} returns a non-null value
	 * 
	 * @return
	 */
	public boolean hasZone() {
		return zone != null;
	}

	/**
	 * The zone or scope id string, which as a string is typically appended to an address with a '%', eg fe80::71a3:2b00:ddd3:753f%16
	 * 
	 * If there is no zone or scope id, returns null.
	 * <p>
	 * See {@link #getIPv6Zone()}
	 * 
	 * @return
	 */
	public String getZone() {
		return getZoneString();
	}

	/**
	 * Returns a new address with the same address values but with the supplied zone.
	 * If the supplied zone is null, equivalent to calling {@link #removeZone()}
	 * 
	 * @param newZone
	 * @return
	 */
	public IPv6Address setZone(IPv6Zone newZone) {
		if(newZone == null) {
			return removeZone();
		}
		return getDefaultCreator().createAddress(getSection(), newZone); /* address creation */
	}
	
	/**
	 * Returns the zone or scope id, consisting of a network interface name or a positive integer scope identifier.
	 * 
	 * If there is no zone or scope id, returns null
	 * <p>
	 * An IPv6 zone distinguishes two IPv6 addresses that are the same.
	 * They are used with link-local addresses fe80::/10 and distinguishes two interfaces to the link-local network, this is known as the zone id.
	 * They are used with site-local addresses to distinguish sites, using the site id, also known as the scope id.
	 * 
	 * A zone that consists of a scope id is called a scoped zone.
	 * 
	 * See {@link #getZone()}
	 * 
	 * @return
	 */
	public IPv6Zone getIPv6Zone() {
		return zone;
	}

	/**
	 * Returns the equivalent address but with no zone.
	 * 
	 * @return
	 */
	public IPv6Address removeZone() {
		if(hasZone()) {
			return getDefaultCreator().createAddress(getSection()); /* address creation */
		}
		return this;
	}

	protected boolean hasNoValueCache() {
		if(addressCache == null) {
			synchronized(this) {
				if(addressCache == null) {
					addressCache = new IPv6AddressCache();
					return true;
				}
			}
		}
		return false;
	}
	
	/**
	 * Converts the lowest value of this address and the associated zone to an Inet6Address. 
	 * <p>
	 * Address with a zone should check for null.
	 * <p>
	 * This will return null if this IPv6 Address has a zone (available from {@link #getIPv6Zone()}),
	 * that zone references a network interface ({@link IPv6Zone#referencesInterface} is true) 
	 * and that network interface (from {@link IPv6Zone#getAssociatedIntf()}) is an IPv4-only interface,
	 * or that interface is not entirely link-local and this address is link-local, 
	 * or that interface is not entirely site-local and this address is site-local.
	 * <p>
	 * This will return null if this IPv6 Address has a zone (available from {@link #getIPv6Zone()}) and:
	 * <ul>
	 * <li>the zone is a scoped id and the address is a global IPv6 address.</li>
	 * <li>the zone specifies an interface that does not exist on this host.</li>
	 * <li>the zone specifies an interface that is IPv4 only.</li>
	 * <li>the zone specifies an interface that is not entirely link-local and this address is link-local.</li>
	 * <li>the zone specifies an interface that is not entirely site-local and this address is site-local.</li>
	 * </ul>
	 * In those cases, the corresponding Java SDK methods such as {@link Inet6Address#getByAddress(String, byte[], NetworkInterface)} 
	 * will throw UnknownHostException when constructed with the same network interface.
	 * <p>
	 * If this address is IPv4-mapped, then any associated zone will be discarded, 
	 * because it is not possible to create an IPv4-mapped Inet6Address with a zone.
	 */
	@Override
	public Inet6Address toInetAddress() {
		if(hasZone()) {
			//we cache the address in here and not in the address section if there is a zone
			Inet6Address result;
			if(hasNoValueCache() || (result = addressCache.inetAddress) == null) {
				addressCache.inetAddress = result = (Inet6Address) toInetAddressImpl();
			}
			return result;
		}
		return (Inet6Address) super.toInetAddress();
	}
	
	@Override
	public Inet6Address toUpperInetAddress() {
		return (Inet6Address) super.toUpperInetAddress();
	}

	@Override
	protected Inet6Address toInetAddressImpl() {
		Inet6Address result;
		byte bytes[] = getSection().getBytesInternal();
		try {
			if(hasZone()) {
				if(zone.referencesScopeId()) {
					result = Inet6Address.getByAddress(null, bytes, zone.getAssociatedScopeId());
				} else if(zone.referencesIntf() && zone.getAssociatedIntf() != null) {
					result = Inet6Address.getByAddress(null, bytes, zone.getAssociatedIntf());
				} else {
					// When the original zone was provided as a string, we use that here.
					// There is no related function that takes a string as third arg, so we reconstruct the address string.
					//
					// When interface name is not known as an interface on the current host, this throws UnknownHostException
					//
					// We need to drop the prefix, and we also need to use the lower address so no wildcards
					//
					// Note that this call to getLower() assumes we want the lower address.  
					// Since toUpperInetAddress calls getUpper().toInetAddress, this works.
					IPv6Address adjusted = getLower().withoutPrefixLength();
					InetAddress resultIP = InetAddress.getByName(adjusted.toNormalizedString());
					if(resultIP instanceof Inet6Address) {
						result = (Inet6Address) resultIP;
					} else {
						// the InetAddress code is throwing away the interface name because the address is IPv4-mapped
						// so the only way to get an IPv6 address, any address at all in fact, requires that we throw it away
						result = Inet6Address.getByAddress(null, bytes, null);
					}
				}
			} else {
				result = Inet6Address.getByAddress(null, bytes, null);
			}
		} catch(UnknownHostException e) {
			result = null;
		}
		return result;
	}
	
	@Override
	@Deprecated
	public IPv6AddressSeqRange toSequentialRange(IPAddress other) {
		return new IPv6AddressSeqRange(this, convertArg(other));
	}

	@Override
	public IPv6AddressSeqRange toSequentialRange() {
		IPv6Address thiz = removeZone().withoutPrefixLength();
		return new IPv6AddressSeqRange(thiz.getLower(), thiz.getUpper(), true);
	}
	
	@Override
	public int hashCode() {
		int result = super.hashCode();
		if(hasZone()) {
			result *= zone.getName().hashCode();
		}
		return result;
	}
	
	@Override
	public boolean isSameAddress(Address other) {
		return other instanceof IPv6Address && super.isSameAddress(other) && isSameZone((IPv6Address) other);
	}
	
	private boolean isSameZone(IPv6Address otherIPv6Address) {
		return Objects.equals(zone, otherIPv6Address.zone);
	}

	/**
	 * 
	 * @param other
	 * @return whether this subnet overlaps with the given address
	 */
	@Override
	public boolean overlaps(Address other) {
		if(super.overlaps(other)) {
			//must check the zone too
			if(other != this) {
				IPv6Address otherAddr = (IPv6Address) other;
				if(hasZone() || otherAddr.hasZone()) {
					//if it has a zone, then it does not overlap addresses from other zones
					return isSameZone(otherAddr);
				}
			}
			return true;
		}
		return false;
	}

	/**
	 * 
	 * @param other
	 * @return whether this subnet contains the given address
	 */
	@Override
	public boolean contains(Address other) {
		if(super.contains(other)) {
			//must check the zone too
			if(other != this) {
				IPv6Address otherAddr = (IPv6Address) other;
				if(hasZone() || otherAddr.hasZone()) {
					//if it has a zone, then it does not contain addresses from other zones
					return isSameZone(otherAddr);
				}
			}
			return true;
		}
		return false;
	}
	
	@Override
	public BigInteger enumerate(Address other) {
		if(other instanceof IPv6Address) {
			return IPv6AddressSection.enumerate(getSection(), other.getSection());
		}
		return null;
	}
	
	@Override
	public BigInteger enumerate(IPAddress other) {
		if(other.isIPv6()) {
			return IPv6AddressSection.enumerate(getSection(), other.getSection());
		}
		return null;
	}

	//////////////// string creation below ///////////////////////////////////////////////////////////////////////////////////////////

	@Override
	protected IPAddressStringParameters createFromStringParams() {
		return new IPAddressStringParameters.Builder().
				getIPv4AddressParametersBuilder().setNetwork(getIPv4Network()).getParentBuilder().
				getIPv6AddressParametersBuilder().setNetwork(getNetwork()).getParentBuilder().toParams();
	}
	
	private boolean hasNoStringCache() {
		if(stringCache == null) {
			synchronized(this) {
				if(stringCache == null) {
					if(hasZone()) {
						stringCache = new IPv6StringCache();
						return true;
					} else {
						//when there is no zone, the section and address strings are the same, so we use the same cache
						IPv6AddressSection section = getSection();
						boolean result = section.hasNoStringCache();
						stringCache = section.getStringCache();
						return result;
					}
				}
			}
		}
		return false;
	}
	
	/**
	 * Produces a string in which the lower 4 bytes are expressed as an IPv4 address and the remaining upper bytes are expressed in IPv6 format.
	 * 
	 * This the mixed IPv6/IPv4 format described in RFC 1884 https://tools.ietf.org/html/rfc1884
	 * 
	 * @return
	 */
	public String toMixedString() {
		String result;
		if(hasNoStringCache() || (result = stringCache.mixedString) == null) {
			if(hasZone()) {
				stringCache.mixedString = result = toNormalizedString(IPv6StringCache.mixedParams);
			} else {
				result = getSection().toMixedString();//the cache is shared so no need to update it here
			}
		}
		return result;
	}
	
	/**
	 * This produces a canonical string.
	 * 
	 * RFC 5952 describes canonical representations.
	 * http://en.wikipedia.org/wiki/IPv6_address#Recommended_representation_as_text
	 * http://tools.ietf.org/html/rfc5952
	 * 
	 * If this has a prefix length, that will be included in the string.
	 */
	@Override
	public String toCanonicalString() {
		String result;
		if(hasNoStringCache() || (result = stringCache.canonicalString) == null) {
			if(hasZone()) {
				stringCache.canonicalString = result = toNormalizedString(IPv6StringCache.canonicalParams);
			} else {
				result = getSection().toCanonicalString();//the cache is shared so no need to update it here
			}
		}
		return result;
	}

	@Override
	public String toFullString() {
		String result;
		if(hasNoStringCache() || (result = stringCache.fullString) == null) {
			if(hasZone()) {
				stringCache.fullString = result = toNormalizedString(IPv6StringCache.fullParams);
			} else {
				result = getSection().toFullString();//the cache is shared so no need to update it here
			}
		}
		return result;
	}

	/**
	 * Creates the normalized string for an address without having to create the address objects first.
	 * 
	 * @param lowerValueProvider
	 * @param upperValueProvider
	 * @param prefixLength
	 * @param zone
	 * @param network use {@link #defaultIpv6Network()} if there is no custom network in use
	 * @return
	 */
	public static String toNormalizedString(IPv6AddressNetwork network, SegmentValueProvider lowerValueProvider, SegmentValueProvider upperValueProvider, Integer prefixLength, CharSequence zone) {
		return toNormalizedString(network.getPrefixConfiguration(), lowerValueProvider, upperValueProvider, prefixLength, SEGMENT_COUNT, BYTES_PER_SEGMENT, BITS_PER_SEGMENT, MAX_VALUE_PER_SEGMENT, SEGMENT_SEPARATOR, DEFAULT_TEXTUAL_RADIX, zone);
	}

	/**
	 * The normalized string returned by this method is consistent with java.net.Inet6address.
	 * 
	 * IPs are not compressed nor mixed in this representation.  If this has a prefix length, that will be included in the string.
	 */
	@Override
	public String toNormalizedString() {
		String result;
		if(hasNoStringCache() || (result = stringCache.normalizedString) == null) {
			if(hasZone()) {
				stringCache.normalizedString = result = toNormalizedString(IPv6StringCache.normalizedParams);
			} else {
				result = getSection().toNormalizedString();//the cache is shared so no need to update it here
			}
		}
		return result;
	}
	
	/**
	 * This compresses the maximum number of zeros and/or host segments with the IPv6 compression notation '::'
	 */
	@Override
	public String toCompressedString() {
		String result;
		if(hasNoStringCache() || (result = stringCache.compressedString) == null) {
			if(hasZone()) {
				stringCache.compressedString = result = toNormalizedString(IPv6StringCache.compressedParams);
			} else {
				result = getSection().toCompressedString();//the cache is shared so no need to update it here
			}
		}
		return result;
	}
	
	@Override
	public String toSubnetString() {
		return toPrefixLengthString();
	}
	
	//note this string is used by hashCode
	@Override
	public String toNormalizedWildcardString() {
		String result;
		if(hasNoStringCache() || (result = stringCache.normalizedWildcardString) == null) {
			if(hasZone()) {
				stringCache.normalizedWildcardString = result = toNormalizedString(IPv6StringCache.wildcardNormalizedParams);
			} else {
				result = getSection().toNormalizedWildcardString();//the cache is shared so no need to update it here
			}
		}
		return result;
	}
	
	/**
	 * The base 85 string is described by RFC 1924
	 * @return
	 */
	public String toBase85String() throws IncompatibleAddressException {
		//first we see if we obtained this address from a base 85 string
		//in the case of a prefix, applying the prefix changes the value
		IPAddressString originator = getAddressfromString();
		if(originator != null && (!isPrefixed() || getNetworkPrefixLength() == IPv6Address.BIT_COUNT) && 
				originator.isBase85IPv6()) {
			return originator.toString();
		}
		String result;
		if(hasNoStringCache() || (result = stringCache.base85String) == null) {
			if(hasZone()) {
				stringCache.base85String = result = getSection().toBase85String(getZone());
			} else {
				result = getSection().toBase85String();//the cache is shared so no need to update it here
			}
		}
		return result;
	}
	
	@Override
	public String toCanonicalWildcardString() {
		String result;
		if(hasNoStringCache() || (result = stringCache.canonicalWildcardString) == null) {
			if(hasZone()) {
				stringCache.canonicalWildcardString = result = toNormalizedString(IPv6StringCache.wildcardCanonicalParams);
			} else {
				result = getSection().toCanonicalWildcardString();//the cache is shared so no need to update it here
			}
		}
		return result;
	}
	
	@Override
	public String toCompressedWildcardString() {
		String result;
		if(hasNoStringCache() || (result = stringCache.compressedWildcardString) == null) {
			if(hasZone()) {
				stringCache.compressedWildcardString = result = toNormalizedString(IPv6StringCache.wildcardCompressedParams);
			} else {
				result = getSection().toCompressedWildcardString();//the cache is shared with the section, so no need to update it here
			}
		}
		return result;
	}
	
	@Override
	public String toSQLWildcardString() {
		String result;
		if(hasNoStringCache() || (result = stringCache.sqlWildcardString) == null) {
			if(hasZone()) {
				stringCache.sqlWildcardString = result = toNormalizedString(IPv6StringCache.sqlWildcardParams);
			} else {
				result = getSection().toSQLWildcardString();//the cache is shared so no need to update it here
			}
		}
		return result;
	}
	
	@Override
	public String toHexString(boolean with0xPrefix) throws IncompatibleAddressException {
		String result;
		if(hasNoStringCache() || (result = (with0xPrefix ? stringCache.hexStringPrefixed : stringCache.hexString)) == null) {
			if(hasZone()) {
				result = getSection().toHexString(with0xPrefix, zone.getName());
				if(with0xPrefix) {
					stringCache.hexStringPrefixed = result;
				} else {
					stringCache.hexString = result;
				}
			} else {
				result = getSection().toHexString(with0xPrefix);//the cache is shared so no need to update it here
			}
		}
		return result;
	}
	
	private String getZoneString() {
		return hasZone() ? zone.getName() : null;
	}
	
	@Override
	public String toBinaryString() throws IncompatibleAddressException {
		String result;
		if(hasNoStringCache() || (result = stringCache.binaryString) == null) {
			if(hasZone()) {
				result = getSection().toBinaryString(zone.getName());
				stringCache.binaryString = result;
			} else {
				result = getSection().toBinaryString();//the cache is shared so no need to update it here
			}
		}
		return result;
	}
	
	@Override
	public String toSegmentedBinaryString() {
		String result;
		if(hasNoStringCache() || (result = stringCache.segmentedBinaryString) == null) {
			if(hasZone()) {
				result = getSection().toSegmentedBinaryString(zone.getName());
				stringCache.segmentedBinaryString = result;
			} else {
				result = getSection().toSegmentedBinaryString();//the cache is shared so no need to update it here
			}
		}
		return result;
	}
	
	@Override
	public String toOctalString(boolean with0Prefix) throws IncompatibleAddressException {
		String result;
		if(hasNoStringCache() || (result = (with0Prefix ? stringCache.octalStringPrefixed : stringCache.octalString)) == null) {
			if(hasZone()) {
				result = getSection().toOctalString(with0Prefix, zone.getName());
				if(with0Prefix) {
					stringCache.octalStringPrefixed = result;
				} else {
					stringCache.octalString = result;
				}
			} else {
				result = getSection().toOctalString(with0Prefix);//the cache is shared so no need to update it here
			}
		}
		return result;
	}

	@Override
	public String toPrefixLengthString() {
		String result;
		if(hasNoStringCache() || (result = stringCache.networkPrefixLengthString) == null) {
			if(hasZone()) {
				stringCache.networkPrefixLengthString = result = toNormalizedString(IPv6StringCache.networkPrefixLengthParams);
			} else {
				result = getSection().toPrefixLengthString();//the cache is shared so no need to update it here
			}
		}
		return result;
	}
	
	@Override
	public String toConvertedString() {
		if(isIPv4Convertible()) {
			return toMixedString();
		}
		return toNormalizedString();
	}
	
	@Override
	public String toNormalizedString(IPStringOptions params) {
		return getSection().toNormalizedString(params, getZoneString());
	}
	
	public String toNormalizedString(IPv6StringOptions params) {
		return getSection().toNormalizedString(params, getZoneString());
	}

	/**
	 * Constructs a string representing this address according to the given parameters
	 * 
	 * @param keepMixed if this address was constructed from a string with mixed representation (a:b:c:d:e:f:1.2.3.4), whether to keep it that way (ignored if makeMixed is true in the params argument)
	 * @param params the parameters for the address string
	 */
	public String toNormalizedString(boolean keepMixed, IPv6StringOptions params) {
		if(keepMixed && fromString != null && getAddressfromString().isMixedIPv6() && !params.makeMixed()) {
			params = new IPv6StringOptions(
					params.base,
					params.expandSegments,
					params.wildcardOption,
					params.wildcards,
					params.segmentStrPrefix,
					true,
					params.ipv4Opts,
					params.compressOptions,
					params.separator,
					params.zoneSeparator,
					params.addrLabel,
					params.addrSuffix,
					params.reverse,
					params.splitDigits,
					params.uppercase);
		}
		return toNormalizedString(params);
	}
	
	@Override
	public String toUNCHostName() {
		String result;
		if(hasNoStringCache() || (result = stringCache.uncString) == null) {
			//it seems for unc hosts we not only replace the zone character % with s and the segment separator : with -,
			//we do the same for any such characters appearing in the zone itself as well
			//see https://blogs.msdn.microsoft.com/oldnewthing/20100915-00/?p=12863/
			String newZone;
			if(hasZone()) {
				newZone = zone.getName().replace(IPv6Address.ZONE_SEPARATOR, IPv6Address.UNC_ZONE_SEPARATOR).replace(IPv6Address.SEGMENT_SEPARATOR, IPv6Address.UNC_SEGMENT_SEPARATOR);
			} else {
				newZone = null;
			}
			stringCache.uncString = result = getSection().toNormalizedString(IPv6StringCache.uncParams, newZone);
		}
		return result;
	}
	
	@Override
	public IPAddressPartStringCollection toStandardStringCollection() {
		return toStringCollection(IPv6StringBuilderOptions.STANDARD_OPTS);
	}

	@Override
	public IPAddressPartStringCollection toAllStringCollection() {
		return toStringCollection(IPv6StringBuilderOptions.ALL_OPTS);
	}
	
	@Override
	public IPAddressPartStringCollection toStringCollection(IPStringBuilderOptions opts) {
		return toStringCollection(IPv6StringBuilderOptions.from(opts));
	}

	private IPv4Address getConverted(IPv6StringBuilderOptions opts) {
		if(!hasZone() && opts.includes(IPv6StringBuilderOptions.IPV4_CONVERSIONS)) {//we cannot convert to ipv4 if there is a zone
			IPv4AddressConverter converter = opts.converter;
			return converter.toIPv4(this);
		}
		return null;
	}
	
	public IPAddressPartStringCollection toStringCollection(IPv6StringBuilderOptions opts) {
		IPv6StringCollection coll = getSection().toStringCollection(opts, getZoneString());
		IPv4Address ipv4Addr = getConverted(opts);
		if(ipv4Addr != null) {
			IPAddressPartStringCollection ipv4StringCollection = ipv4Addr.toStringCollection(opts.ipv4ConverterOptions);
			coll.addAll(ipv4StringCollection);
		}
		return coll;
	}
	
	/**
	 * @custom.core
	 * @author sfoley
	 *
	 */
	public interface IPv6AddressConverter {
		/**
		 * If the given address is IPv6, or can be converted to IPv6, returns that {@link IPv6Address}.  Otherwise, returns null.
		 */
		IPv6Address toIPv6(IPAddress address);
	}
}
