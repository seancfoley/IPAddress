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
