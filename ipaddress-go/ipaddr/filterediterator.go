//
// Copyright 2020-2021 Sean C Foley
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

type filteredAddrIterator struct {
	skip func(*Address) bool
	iter AddressIterator
	next *Address
}

func (it *filteredAddrIterator) Next() (res *Address) {
	res = it.next
	for {
		next := it.iter.Next()
		if next == nil || !it.skip(next) {
			it.next = next
			break
		}
	}
	return res
}

func (it *filteredAddrIterator) HasNext() bool {
	return it.next != nil
}

func NewFilteredAddrIterator(iter AddressIterator, skip func(*Address) bool) AddressIterator {
	res := &filteredAddrIterator{skip: skip, iter: iter}
	res.Next()
	return res
}

type filteredIPAddrIterator struct {
	skip func(*IPAddress) bool
	iter IPAddressIterator
	next *IPAddress
}

func (it *filteredIPAddrIterator) Next() (res *IPAddress) {
	res = it.next
	for {
		next := it.iter.Next()
		if next == nil || !it.skip(next) {
			it.next = next
			break
		}
	}
	return res
}

func (it *filteredIPAddrIterator) HasNext() bool {
	return it.next != nil
}

func NewFilteredIPAddrIterator(iter IPAddressIterator, skip func(*IPAddress) bool) IPAddressIterator {
	res := &filteredIPAddrIterator{skip: skip, iter: iter}
	res.Next()
	return res
}
