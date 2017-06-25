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

package inet.ipaddr.format.validate;

import java.io.Serializable;
import java.net.InetAddress;
import java.net.UnknownHostException;

import inet.ipaddr.HostName;
import inet.ipaddr.HostNameException;
import inet.ipaddr.HostNameParameters;
import inet.ipaddr.IPAddress;
import inet.ipaddr.IPAddressNetwork;
import inet.ipaddr.IPAddressString;
import inet.ipaddr.ipv4.IPv4Address;
import inet.ipaddr.ipv6.IPv6Address;

/**
 * The result of parsing a valid host name.
 * 
 * @author sfoley
 *
 */
public class ParsedHost implements Serializable {

	private static final long serialVersionUID = 1L;

	public final AddressProvider addressProvider;
	
	private String normalizedLabels[];
	private int separatorIndices[];
	private boolean normalizedFlags[];
	
	public final ParsedAddressQualifier labelsQualifier;
	
	String host;
	private final String originalStr;
	
	public ParsedHost(String originalStr, AddressProvider valueProvider) {
		this.addressProvider = valueProvider;
		this.labelsQualifier = null;
		this.originalStr = originalStr;
	}
	
	ParsedHost(String originalStr, int separatorIndices[], boolean normalizedFlags[], ParsedAddressQualifier labelsQualifier) {
		this.addressProvider = null;
		this.labelsQualifier = labelsQualifier;
		this.normalizedFlags = normalizedFlags;
		this.separatorIndices = separatorIndices;
		this.originalStr = originalStr;
	}
	
	public IPAddressString asGenericAddressString() {
		if(addressProvider != null) {
			if(addressProvider.isAllAddresses()) {
				return IPAddressString.ALL_ADDRESSES;
			} else if(addressProvider.isPrefixOnly()) {
				return IPAddressNetwork.getPrefix(addressProvider.getNetworkPrefixLength());
			} else if(addressProvider.isEmpty()) {
				return IPAddressString.EMPTY_ADDRESS;
			}
		}
		return null;
	}

	public String[] getNormalizedLabels() {
		String labels[] = normalizedLabels;
		if(labels == null) {
			synchronized(this) {
				labels = normalizedLabels;
				if(labels == null) {
					if(addressProvider != null) {
						IPAddress addr = addressProvider.getAddress();
						if(addr == null) {
							if(addressProvider.isEmpty()) {
								return new String[0];
							}
							return new String[] {asGenericAddressString().toString()};
						}
						return addr.getSegmentStrings();
					} else {
						labels = new String[separatorIndices.length];
						for(int i = 0, lastSep = -1; i < labels.length; i++) {
							int index = separatorIndices[i];
							if(normalizedFlags != null && !normalizedFlags[i]) {
								StringBuilder second = new StringBuilder((index - lastSep) - 1);
								for(int j = lastSep + 1; j < index; j++) {
									char c = originalStr.charAt(j);
									second.append((c >= 'A' && c <= 'Z') ? (char) (c + ('a' - 'A')) : c);
								}
								labels[i] = second.toString();
							} else {
								labels[i] = originalStr.substring(lastSep + 1, index);
							}
							lastSep = index;
						}
						separatorIndices = null;
						normalizedFlags = null;
					}
					normalizedLabels = labels;
				}
			}
		}
		return labels;
	}
	
	public String getHost() {
		String str = host;
		if(str == null) {
			if(originalStr.length() > 0) {
				synchronized(this) {
					str = host;
					if(str == null) {
						StringBuilder builder = new StringBuilder(originalStr.length());
						String labels[] = normalizedLabels;
						if(labels == null) {
							int labelIndex = 0;
							boolean isNormalized = normalizedFlags[0];
							for(int j = 0; j < originalStr.length(); j++) {
								char c = originalStr.charAt(j);
								if(c == HostName.LABEL_SEPARATOR) {
									isNormalized = normalizedFlags[++labelIndex];
									builder.append(c);
								} else if(c == IPAddress.PREFIX_LEN_SEPARATOR) {
									break;
								} else if(isNormalized || c < 'A' || c > 'Z') {
									builder.append(c);
								} else {
									builder.append((char) (c + ('a' - 'A')));
								}
							}
						} else {
							builder.append(normalizedLabels[0]);
							for(int i = 1; i < normalizedLabels.length; i++) {
								builder.append(HostName.LABEL_SEPARATOR).append(normalizedLabels[i]);
							}
						}
						str = builder.toString();
					}
				}
			} else {
				str = originalStr;
			}
			host = str;
		}
		return str;
	}

	public boolean isIPv6Address() {
		return addressProvider != null && addressProvider.isIPv6();
	}

	public IPAddress resolveAddress(HostName originatingHost, HostNameParameters options) throws HostNameException, UnknownHostException {
		IPAddress result;
		if(addressProvider != null) {
			result = addressProvider.getAddress();
		} else {
			String strHost = getHost();
			if(strHost.length() == 0 && !options.emptyIsLoopback) {
				result = null;
			} else {
				InetAddress inetAddress = InetAddress.getByName(strHost);
				byte bytes[] = inetAddress.getAddress();
				if(bytes.length == IPv6Address.BYTE_COUNT) {
					String zone = labelsQualifier.getZone();
					ParsedAddressCreator<IPv6Address, ?, ?> creator = IPv6Address.network().getAddressCreator();
					result = createAddress(originatingHost, bytes, zone, creator);
				} else {
					ParsedAddressCreator<IPv4Address, ?, ?> creator = IPv4Address.network().getAddressCreator();
					result = createAddress(originatingHost, bytes, null, creator);
				}
			}
		}
		return result;
	}
	
	private <T extends IPAddress> T createAddress(HostName originatingHost, byte bytes[], String zone, ParsedAddressCreator<T, ?, ?> creator) throws HostNameException {
		Integer networkPrefixLength = labelsQualifier.getNetworkPrefixLength();
		if(networkPrefixLength == null) {
			IPAddress mask = labelsQualifier.getMask();
			if(mask != null) {
				byte maskBytes[] = mask.getBytes();
				if(maskBytes.length != bytes.length) {
					throw new HostNameException(originalStr, "ipaddress.error.ipMismatch");
				}
				for(int i = 0; i < bytes.length; i++) {
					bytes[i] &= maskBytes[i];
				}
				networkPrefixLength = mask.getMaskPrefixLength(true);
			}
		}
		return creator.createAddressInternal(bytes, networkPrefixLength, zone, originatingHost); /* address creation */
	}
}
