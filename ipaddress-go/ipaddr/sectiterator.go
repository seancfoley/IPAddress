package ipaddr

type SegmentsIterator interface {
	iteratorBase
	Next() []*AddressDivision
}

type singleSegmentsIterator struct {
	original []*AddressDivision
}

func (it *singleSegmentsIterator) HasNext() bool {
	return it.original != nil
}

func (it *singleSegmentsIterator) Next() (res []*AddressDivision) {
	if it.HasNext() {
		res = it.original
		it.original = nil
	}
	return
}

type multiSegmentsIterator struct {
	done       bool
	variations []SegmentIterator
	nextSet    []*AddressDivision

	segIteratorProducer,
	hostSegIteratorProducer func(int) SegmentIterator

	networkSegmentIndex,
	hostSegmentIndex int

	excludeFunc func([]*AddressDivision) bool
}

func (it *multiSegmentsIterator) HasNext() bool {
	return !it.done
}

func (it *multiSegmentsIterator) updateVariations(start int) {
	i := start
	nextSet := it.nextSet
	variations := it.variations
	segIteratorProducer := it.segIteratorProducer
	for ; i < it.hostSegmentIndex; i++ {
		variations[i] = segIteratorProducer(i)
		nextSet[i] = variations[i].Next().ToAddressDivision()
	}
	if i == it.networkSegmentIndex {
		variations[i] = it.hostSegIteratorProducer(i)
		nextSet[i] = variations[i].Next().ToAddressDivision()
	}
}

func (it *multiSegmentsIterator) init() {
	it.updateVariations(0)
	nextSet := it.nextSet
	variations := it.variations
	divCount := len(variations)
	hostSegIteratorProducer := it.hostSegIteratorProducer
	// for regular iterators (not prefix block), networkSegmentIndex is last segment (count - 1)
	for i := it.networkSegmentIndex + 1; i < divCount; i++ {
		variations[i] = hostSegIteratorProducer(i)
		nextSet[i] = variations[i].Next().ToAddressDivision()
	}
	excludeFunc := it.excludeFunc
	if excludeFunc != nil && excludeFunc(it.nextSet) {
		it.increment()
	}
}

func (it *multiSegmentsIterator) Next() (res []*AddressDivision) {
	if it.HasNext() {
		res = it.increment()
	}
	return
}

func (it *multiSegmentsIterator) increment() (res []*AddressDivision) {
	var previousSegs []*AddressDivision
	// the current set of segments already holds the next iteration,
	// this searches for the set of segments to follow.
	variations := it.variations
	nextSet := it.nextSet
	for j := it.networkSegmentIndex; j >= 0; j-- { //for regular iterators (not prefix block), networkSegmentIndex is last segment (count - 1)
		for variations[j].HasNext() {
			if previousSegs == nil {
				previousSegs = cloneDivs(nextSet)
			}
			nextSet[j] = variations[j].Next().ToAddressDivision()
			it.updateVariations(j + 1)
			excludeFunc := it.excludeFunc
			if excludeFunc != nil && excludeFunc(nextSet) {
				// try again, starting over
				j = it.networkSegmentIndex
			} else {
				return previousSegs
			}
		}
	}
	it.done = true
	if previousSegs == nil {
		// never found set of candidate segments
		return nextSet
	}
	// found a candidate to follow, but was rejected.
	// nextSet has that rejected candidate,
	// so we must return the set that was created prior to that.
	return previousSegs
}

// this iterator function used by addresses and segment arrays, for iterators that are not prefix or prefix block iterators
func allSegmentsIterator(
	divCount int,
	segSupplier func() []*AddressDivision,
	segIteratorProducer func(int) SegmentIterator,
	excludeFunc func([]*AddressDivision) bool /* can be nil */) SegmentsIterator {
	return segmentsIterator(divCount, segSupplier, segIteratorProducer, excludeFunc, divCount-1, divCount, nil)
}

// used to produce regular iterators with or without zero-host values, and prefix block iterators
func segmentsIterator(
	divCount int,
	segSupplier func() []*AddressDivision,
	segIteratorProducer func(int) SegmentIterator,
	excludeFunc func([]*AddressDivision) bool, // can be nil
	networkSegmentIndex,
	hostSegmentIndex int,
	hostSegIteratorProducer func(int) SegmentIterator) SegmentsIterator { // returns Iterator<S[]>
	if segSupplier != nil {
		return &singleSegmentsIterator{segSupplier()}
	}
	iterator := &multiSegmentsIterator{
		variations:              make([]SegmentIterator, divCount),
		nextSet:                 make([]*AddressDivision, divCount),
		segIteratorProducer:     segIteratorProducer,
		hostSegIteratorProducer: hostSegIteratorProducer,
		networkSegmentIndex:     networkSegmentIndex,
		hostSegmentIndex:        hostSegmentIndex,
		excludeFunc:             excludeFunc,
	}
	iterator.init()
	return iterator
}

type SectionIterator interface {
	HasNext() bool
	Next() *AddressSection
}

type singleSectionIterator struct {
	original *AddressSection
}

func (it *singleSectionIterator) HasNext() bool {
	return it.original != nil
}

func (it *singleSectionIterator) Next() (res *AddressSection) {
	if it.HasNext() {
		res = it.original
		it.original = nil
	}
	return
}

type multiSectionIterator struct {
	creator      ParsedAddressCreator
	iterator     SegmentsIterator
	prefixLength PrefixLen
}

func (it *multiSectionIterator) HasNext() bool {
	return it.iterator.HasNext()
}

func (it *multiSectionIterator) Next() (res *AddressSection) {
	if it.HasNext() {
		segs := it.iterator.Next()
		res = createIteratedSection(it.creator, segs, it.prefixLength)
	}
	return
}

func sectIterator(
	useOriginal bool,
	original *AddressSection,
	creator ParsedAddressCreator,
	iterator SegmentsIterator,
	prefixLength PrefixLen) SectionIterator {
	if useOriginal {
		return &singleSectionIterator{original: original}
	}
	return &multiSectionIterator{
		creator:      creator,
		iterator:     iterator,
		prefixLength: prefixLength,
	}
}

type IPSectionIterator interface {
	iteratorBase
	Next() *IPAddressSection
}

type ipSectionIterator struct {
	SectionIterator
}

func (iter ipSectionIterator) Next() *IPAddressSection {
	return iter.SectionIterator.Next().ToIPAddressSection()
}

type IPv4SectionIterator interface {
	iteratorBase
	Next() *IPv4AddressSection
}

type ipv4SectionIterator struct {
	SectionIterator
}

func (iter ipv4SectionIterator) Next() *IPv4AddressSection {
	return iter.SectionIterator.Next().ToIPv4AddressSection()
}

type IPv6SectionIterator interface {
	iteratorBase
	Next() *IPv6AddressSection
}

type ipv6SectionIterator struct {
	SectionIterator
}

func (iter ipv6SectionIterator) Next() *IPv6AddressSection {
	return iter.SectionIterator.Next().ToIPv6AddressSection()
}

type MACSectionIterator interface {
	iteratorBase
	Next() *MACAddressSection
}

type macSectionIterator struct {
	SectionIterator
}

func (iter macSectionIterator) Next() *MACAddressSection {
	return iter.SectionIterator.Next().ToMACAddressSection()
}

func createIteratedSection(creator ParsedAddressCreator, next []*AddressDivision, prefixLength PrefixLen) *AddressSection {
	return creator.createPrefixedSectionInternalSingle(next, prefixLength)
}

////////

// TODO continue with section and address iterators, need to hook up them all to the methods in here
// address blockIterator combines addrIterator with segmentsIterator
// address prefixIterator the same, covering both prefix and prefix block
// section blockIterator combines sectIterator with segmentsIterator
// section prefixIterator the same, covering both prefix and prefix block
//
// So that covers them all for ipv4/6 (2 pref iterators, 1 block)
// mac has just the two pref iterators
// sequential range iterator uses segmentsIterator, and in fact the prefix and prefix block iterators use it too
//
// this baby is at the core of them all!
//
