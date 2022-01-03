//
// Copyright 2020-2022 Sean C Foley
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package ipaddr

type IPAddressSeqRangeIterator interface {
	HasNext
	Next() *IPAddressSeqRange
}

type singleRangeIterator struct {
	original *IPAddressSeqRange
}

func (it *singleRangeIterator) HasNext() bool {
	return it.original != nil
}

func (it *singleRangeIterator) Next() (res *IPAddressSeqRange) {
	if it.HasNext() {
		res = it.original
		it.original = nil
	}
	return
}

type rangeIterator struct {
	rng                 *IPAddressSeqRange
	creator             func(*IPAddress, *IPAddress) *IPAddressSeqRange
	prefixBlockIterator IPAddressIterator
	prefixLength        BitCount
	notFirst            bool
}

func (it *rangeIterator) HasNext() bool {
	return it.prefixBlockIterator.HasNext()
}

func (it *rangeIterator) Next() (res *IPAddressSeqRange) {
	if it.HasNext() {
		next := it.prefixBlockIterator.Next()
		if !it.notFirst {
			it.notFirst = true
			// next is a prefix block
			lower := it.rng.GetLower()
			prefLen := it.prefixLength
			if it.HasNext() {
				if !lower.IncludesZeroHostLen(prefLen) {
					return it.creator(lower, next.GetUpper())
				}
			} else {
				upper := it.rng.GetUpper()
				if !lower.IncludesZeroHostLen(prefLen) || !upper.IncludesMaxHostLen(prefLen) {
					return it.creator(lower, upper)
				}
			}
		} else if !it.HasNext() {
			upper := it.rng.GetUpper()
			if !upper.IncludesMaxHostLen(it.prefixLength) {
				return it.creator(next.GetLower(), upper)
			}
		}
		return next.toSequentialRangeUnchecked()
	}
	return
}

type IPv4AddressSeqRangeIterator interface {
	HasNext
	Next() *IPv4AddressSeqRange
}

type ipv4RangeIterator struct {
	IPAddressSeqRangeIterator
}

func (iter ipv4RangeIterator) Next() *IPv4AddressSeqRange {
	return iter.IPAddressSeqRangeIterator.Next().ToIPv4()
}

type IPv6AddressSeqRangeIterator interface {
	HasNext
	Next() *IPv6AddressSeqRange
}

type ipv6RangeIterator struct {
	IPAddressSeqRangeIterator
}

func (iter ipv6RangeIterator) Next() *IPv6AddressSeqRange {
	return iter.IPAddressSeqRangeIterator.Next().ToIPv6()
}
