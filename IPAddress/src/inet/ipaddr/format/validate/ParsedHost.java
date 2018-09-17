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

package inet.ipaddr.format.validate;

import java.io.Serializable;

import inet.ipaddr.AddressStringException;
import inet.ipaddr.HostName;
import inet.ipaddr.IPAddress;
import inet.ipaddr.IPAddress.IPVersion;
import inet.ipaddr.IPAddressNetwork;
import inet.ipaddr.IPAddressSection;
import inet.ipaddr.IPAddressString;

/**
 * The result of parsing a valid host name.
 * 
 * @author sfoley
 *
 */
public class ParsedHost implements Serializable {

	private static final long serialVersionUID = 4L;

	private static final EmbeddedAddress NO_EMBEDDED_ADDRESS = new EmbeddedAddress();
	static final ParsedHostIdentifierStringQualifier NO_QUALIFIER = new ParsedHostIdentifierStringQualifier();
	
	private String normalizedLabels[];
	private int separatorIndices[];
	private boolean normalizedFlags[];
	
	private final ParsedHostIdentifierStringQualifier labelsQualifier;
	private String service;
	
	private EmbeddedAddress embeddedAddress;
	
	String host;
	private final String originalStr;
	
	public ParsedHost(String originalStr, IPAddressProvider valueProvider) {
		this(originalStr, null, null, NO_QUALIFIER, new EmbeddedAddress());
		embeddedAddress.addressProvider = valueProvider;
	}
	
	public ParsedHost(String originalStr, IPAddressProvider valueProvider, ParsedHostIdentifierStringQualifier portQualifier) {
		this(originalStr, null, null, portQualifier, new EmbeddedAddress());
		embeddedAddress.addressProvider = valueProvider;
	}

	ParsedHost(String originalStr, int separatorIndices[], boolean normalizedFlags[], ParsedHostIdentifierStringQualifier labelsQualifier) {
		this(originalStr, separatorIndices, normalizedFlags, labelsQualifier, null);
	}
	
	ParsedHost(String originalStr, int separatorIndices[], boolean normalizedFlags[], ParsedHostIdentifierStringQualifier labelsQualifier, EmbeddedAddress embeddedAddress) {
		this.labelsQualifier = labelsQualifier;
		this.normalizedFlags = normalizedFlags;
		this.separatorIndices = separatorIndices;
		this.originalStr = originalStr;
		this.embeddedAddress = embeddedAddress == null ? NO_EMBEDDED_ADDRESS : embeddedAddress;
	}
	
	static class EmbeddedAddress implements Serializable {
		
		private static final long serialVersionUID = 4L;
		
		boolean isUNCIPv6Literal;
		boolean isReverseDNS;
		
		AddressStringException addressStringException;
		
		IPAddressProvider addressProvider;
	}
	
	public boolean isIPv6Address() {
		return hasEmbeddedAddress() && getAddressProvider().isProvidingIPv6();
	}
	
	public Integer getPort() {
		return labelsQualifier.getPort();
	}
	
	public String getService() {
		String serv = service;
		if(serv == null) {	
			CharSequence sv = labelsQualifier.getService();
			if(sv != null) {
				service = serv = sv.toString();
			}
		}
		return serv;
	}
	
	public Integer getNetworkPrefixLength() {
		return labelsQualifier.getNetworkPrefixLength();
	}
	
	public Integer getEquivalentPrefixLength() {
		return labelsQualifier.getEquivalentPrefixLength();
	}
	
	public IPAddress getMask() {
		return labelsQualifier.getMask();
	}
	
	public IPAddressProvider getAddressProvider() {
		return embeddedAddress.addressProvider;
	}
	
	private boolean hasEmbeddedAddress() {
		return embeddedAddress.addressProvider != null;
	}
	
	public boolean isAddressString() {
		return getAddressProvider() != null;
	}
	
	public IPAddress asAddress(IPVersion version) {
		if(hasEmbeddedAddress()) {
			return getAddressProvider().getProviderAddress(version);
		}
		return null;
	}
	
	public IPAddress asAddress() {
		if(hasEmbeddedAddress()) {
			return getAddressProvider().getProviderAddress();
		}
		return null;
	}
	
	public IPAddressString asGenericAddressString() {
		if(hasEmbeddedAddress()) {
			IPAddressProvider addressProvider = getAddressProvider();
			if(addressProvider.isProvidingAllAddresses()) {
				return new IPAddressString(IPAddress.SEGMENT_WILDCARD_STR, addressProvider.getParameters());
			} else if(addressProvider.isProvidingPrefixOnly()) {
				return new IPAddressString(IPAddressNetwork.getPrefixString(addressProvider.getProviderNetworkPrefixLength()), addressProvider.getParameters());
			} else if(addressProvider.isProvidingEmpty()) {
				return new IPAddressString("", addressProvider.getParameters());
			} else {
				IPAddress addr = addressProvider.getProviderAddress();
				return addr.toAddressString();
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
					if(hasEmbeddedAddress()) {
						IPAddressProvider addressProvider = getAddressProvider();
						IPAddress addr = addressProvider.getProviderAddress();
						if(addr == null) {
							if(addressProvider.isProvidingEmpty()) {
								return new String[0];
							}
							return new String[] {asGenericAddressString().toString()};
						}
						IPAddressSection section = addr.getSection();
						labels = section.getSegmentStrings();
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
						if(hasEmbeddedAddress()) {
							IPAddressProvider addressProvider = getAddressProvider();
							IPAddress addr = addressProvider.getProviderAddress();
							if(addr == null) {
								//note that this means prefix only (/16 or /64) is a valid host
								return asGenericAddressString().toString();
							}
							//port was stripped out 
							//mask and prefix removed by toNormalizedWildcardString
							//getSection() removes zone
							return addr.getSection().toCanonicalWildcardString();
						} else {
							StringBuilder builder = new StringBuilder(originalStr.length());
							String labels[] = getNormalizedLabels();
							builder.append(labels[0]);
							for(int i = 1; i < labels.length; i++) {
								builder.append(HostName.LABEL_SEPARATOR).append(labels[i]);
							}
							str = builder.toString();
						}
					}
				}
			} else {
				str = originalStr;
			}
			host = str;
		}
		return str;
	}
	
	public AddressStringException getAddressStringException() {
		return embeddedAddress.addressStringException;
	}
	
	public boolean isUNCIPv6Literal() {
		return embeddedAddress.isUNCIPv6Literal;
	}
	
	public boolean isReverseDNS() {
		return embeddedAddress.isReverseDNS;
	}
}
