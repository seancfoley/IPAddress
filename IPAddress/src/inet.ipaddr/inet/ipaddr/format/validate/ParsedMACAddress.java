/*
 * Copyright 2018 Sean C Foley
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

import inet.ipaddr.IncompatibleAddressException;
import inet.ipaddr.MACAddressString;
import inet.ipaddr.mac.MACAddress;
import inet.ipaddr.mac.MACAddressNetwork.MACAddressCreator;
import inet.ipaddr.mac.MACAddressSection;
import inet.ipaddr.mac.MACAddressSegment;

/**
 * The result from parsing a valid MAC address string.  This can be converted into an {@link MACAddress} instance.
 * 
 * @author sfoley
 *
 */
class ParsedMACAddress extends MACAddressParseData implements MACAddressProvider {

	private static final long serialVersionUID = 4L;

	private final MACAddressString originator;
	private MACAddress address;
	
	ParsedMACAddress(
			MACAddressString from, 
			CharSequence addressString) {
		super(addressString);
		this.originator = from;
	}

	private MACAddressCreator getMACAddressCreator() {
		return originator.getValidationOptions().getNetwork().getAddressCreator();
	}

	@Override
	public MACAddress getAddress() {
		if(address == null) {
			synchronized(this) {
				if(address == null) {
					address = createAddress();
					releaseSegmentData();
				}
			}
		}
		return address;
	}
	
	MACAddress createAddress()  {
		ParsedAddressCreator<? extends MACAddress, MACAddressSection, ?, ?> creator = getMACAddressCreator();
		return creator.createAddressInternal(createSection(), originator);
	}

	private MACAddressSection createSection()  {
		CharSequence addressString = str;
		AddressParseData addressParseData = getAddressParseData();
		int actualInitialSegmentCount = addressParseData.getSegmentCount();
		MACAddressCreator creator = getMACAddressCreator();
		MACFormat format = getFormat();
		
		int finalSegmentCount, initialSegmentCount;
		if(format == null) {
			initialSegmentCount = finalSegmentCount = 
					isExtended() ? MACAddress.EXTENDED_UNIQUE_IDENTIFIER_64_SEGMENT_COUNT : MACAddress.MEDIA_ACCESS_CONTROL_SEGMENT_COUNT;
		} else if(format == MACFormat.DOTTED) {
			initialSegmentCount = isExtended() ? MACAddress.MEDIA_ACCESS_CONTROL_DOTTED_64_SEGMENT_COUNT : MACAddress.MEDIA_ACCESS_CONTROL_DOTTED_SEGMENT_COUNT;
			if(actualInitialSegmentCount <= MACAddress.MEDIA_ACCESS_CONTROL_DOTTED_SEGMENT_COUNT && !isExtended()) {
				finalSegmentCount = MACAddress.MEDIA_ACCESS_CONTROL_SEGMENT_COUNT;
			} else {
				finalSegmentCount = MACAddress.EXTENDED_UNIQUE_IDENTIFIER_64_SEGMENT_COUNT;
			}
		} else {
			if(addressParseData.isSingleSegment() || isDoubleSegment()) {
				finalSegmentCount = isExtended() ? MACAddress.EXTENDED_UNIQUE_IDENTIFIER_64_SEGMENT_COUNT : MACAddress.MEDIA_ACCESS_CONTROL_SEGMENT_COUNT;
			} else if(actualInitialSegmentCount <= MACAddress.MEDIA_ACCESS_CONTROL_SEGMENT_COUNT && !isExtended()) {
				finalSegmentCount = MACAddress.MEDIA_ACCESS_CONTROL_SEGMENT_COUNT;
			} else {
				finalSegmentCount = MACAddress.EXTENDED_UNIQUE_IDENTIFIER_64_SEGMENT_COUNT;
			}
			initialSegmentCount = finalSegmentCount;
		}
		int missingCount = initialSegmentCount - actualInitialSegmentCount;
		boolean expandedSegments = (missingCount <= 0);
		MACAddressSegment segments[] = creator.createSegmentArray(finalSegmentCount);
		for(int i = 0, normalizedSegmentIndex = 0; i < actualInitialSegmentCount; i++) {
			long lower = addressParseData.getValue(i, AddressParseData.KEY_LOWER);
			long upper = addressParseData.getValue(i, AddressParseData.KEY_UPPER);
			if(format == MACFormat.DOTTED) {//aaa.bbb.ccc.ddd
				//aabb is becoming aa.bb
				int lowerHalfLower = (((int) lower) >>> 8);
				int lowerHalfUpper = (((int) upper) >>> 8);
				int adjustedLower2 = ((int) lower) & 0xff;
				int adjustedUpper2 = ((int) upper) & 0xff;
				if(lowerHalfLower != lowerHalfUpper && adjustedUpper2 - adjustedLower2 != 0xff) {
					throw new IncompatibleAddressException(addressString, "ipaddress.error.invalid.joined.ranges");
				}
				segments[normalizedSegmentIndex++] = createSegment(
						addressString,
						lowerHalfLower,
						lowerHalfUpper,
						false,
						addressParseData,
						i,
						creator);
				segments[normalizedSegmentIndex] = createSegment(
						addressString,
						adjustedLower2,
						adjustedUpper2,
						false,
						addressParseData,
						i,
						creator);
			} else {
				if(addressParseData.isSingleSegment() || isDoubleSegment()) {
					boolean useStringIndicators = true;
					int count = (i == actualInitialSegmentCount - 1) ? missingCount : (MACAddress.ORGANIZATIONAL_UNIQUE_IDENTIFIER_SEGMENT_COUNT - 1);
					missingCount -= count;
					boolean isRange = (lower != upper);
					boolean previousAdjustedWasRange = false;
					while(count >= 0) { //add the missing segments
						int newLower, newUpper;
						if(isRange) {
							int segmentMask = MACAddress.MAX_VALUE_PER_SEGMENT;
							int shift = count << 3;
							newLower = (int) (lower >>> shift) & segmentMask;
							newUpper = (int) (upper >>> shift) & segmentMask;
							if(previousAdjustedWasRange && newUpper - newLower != MACAddress.MAX_VALUE_PER_SEGMENT) {
								//any range extending into upper segments must have full range in lower segments
								//otherwise there is no way for us to represent the address
								//so we need to check whether the lower parts cover the full range
								//eg cannot represent 0.0.0x100-0x10f or 0.0.1-1ff, but can do 0.0.0x100-0x1ff or 0.0.0-1ff
								throw new IncompatibleAddressException(addressString, "ipaddress.error.invalid.joined.ranges");
							}
							previousAdjustedWasRange = newLower != newUpper;
							
							//we may be able to reuse our strings on the final segment
							//for previous segments, strings can be reused only when the value is 0, which we do not need to cache.  Any other value changes when shifted.  
							if(count == 0 && newLower == lower) {
								if(newUpper != upper) {
									addressParseData.setFlag(i, AddressParseData.KEY_STANDARD_RANGE_STR, false);
									//segFlags[AddressParseData.STANDARD_RANGE_STR_INDEX] = false;
								}
							} else {
								useStringIndicators = false;
							}
						} else {
							newLower = newUpper = (int) (lower >> (count << 3)) & MACAddress.MAX_VALUE_PER_SEGMENT;
							if(count != 0 || newLower != lower) {
								useStringIndicators = false;
							}
						}
						segments[normalizedSegmentIndex] = createSegment(
							addressString,
							newLower,
							newUpper,
							useStringIndicators,
							addressParseData,
							i,
							creator);
						++normalizedSegmentIndex;
						count--;
					}
					continue;
				} //end joined segments
				segments[normalizedSegmentIndex] = createSegment(
						addressString,
						(int) lower,
						(int) upper,
						true,
						addressParseData,
						i,
						creator);
			}
			if(!expandedSegments) {
				//check for any missing segments that we should account for here
				if(addressParseData.isWildcard(i)) {
					boolean expandSegments = true;
					for(int j = i + 1; j < actualInitialSegmentCount; j++) {
						if(addressParseData.isWildcard(j)) {//another wildcard further down
							expandSegments = false;
							break;
						}
					}
					if(expandSegments) {
						expandedSegments = true;
						int count = missingCount;
						while(count-- > 0) { //add the missing segments
							if(format == MACFormat.DOTTED) {
								MACAddressSegment seg = createSegment(
										addressString,
										0,
										MACAddress.MAX_VALUE_PER_SEGMENT,
										false,
										addressParseData,
										i,
										creator);
								segments[++normalizedSegmentIndex] = seg;
								segments[++normalizedSegmentIndex] = seg;
							} else {
								segments[++normalizedSegmentIndex] = createSegment(
									addressString,
									0,
									MACAddress.MAX_VALUE_PER_SEGMENT,
									false,
									addressParseData,
									i,
									creator);
							}
						}
					}
				}
			}
			normalizedSegmentIndex++;
		}
		ParsedAddressCreator<?, MACAddressSection, ?, MACAddressSegment> addressCreator = creator;
		MACAddressSection result = addressCreator.createSectionInternal(segments);
		return result;
	}
		
	private <S extends MACAddressSegment> S createSegment(
			CharSequence addressString,
			int val,
			int upperVal,
			boolean useFlags,
			AddressParseData parseData,
			int parsedSegIndex,
			ParsedAddressCreator<?, ?, ?, S> creator) {
		if(val != upperVal) {
			return createRangeSegment(addressString, val, upperVal, useFlags, parseData, parsedSegIndex, creator);
		}
		S result;
		if(!useFlags) {
			result = creator.createSegment(val, val, null);
		} else {
			result = creator.createSegmentInternal(
				val,
				null,//prefix length
				addressString,
				val,
				parseData.getFlag(parsedSegIndex, AddressParseData.KEY_STANDARD_STR),
				parseData.getIndex(parsedSegIndex, AddressParseData.KEY_LOWER_STR_START_INDEX),
				parseData.getIndex(parsedSegIndex, AddressParseData.KEY_LOWER_STR_END_INDEX));
		}
		return result;
	}
	
	private <S extends MACAddressSegment> S createRangeSegment(
			CharSequence addressString,
			int lower,
			int upper,
			boolean useFlags,
			AddressParseData parseData,
			int parsedSegIndex,
			ParsedAddressCreator<?, ?, ?, S> creator) {
		S result;
		if(!useFlags) {
			result = creator.createSegment(lower, upper, null);
		} else {
			result = creator.createSegmentInternal(
				lower,
				upper,
				null,
				addressString,
				lower,
				upper,
				parseData.getFlag(parsedSegIndex, AddressParseData.KEY_STANDARD_STR),
				parseData.getFlag(parsedSegIndex, AddressParseData.KEY_STANDARD_RANGE_STR),
				parseData.getIndex(parsedSegIndex, AddressParseData.KEY_LOWER_STR_START_INDEX),
				parseData.getIndex(parsedSegIndex, AddressParseData.KEY_LOWER_STR_END_INDEX),
				parseData.getIndex(parsedSegIndex, AddressParseData.KEY_UPPER_STR_END_INDEX));
		}
		return result;
	}
}