package ipaddrold

// a boolean type that has three states: not set, true, false
type cachedBoolean struct {
	val *bool
}

func (b cachedBoolean) isSet() bool {
	return b.val != nil
}

func (b cachedBoolean) isTrue() bool {
	return b.isSet() && *b.val
}

func (b cachedBoolean) isFalse() bool {
	return b.isSet() && !*b.val
}

func (b cachedBoolean) setValue(val bool) {
	b.val = &val
}

//TODO do the cacheBits thing here too
type PrefixLen int

func (p PrefixLen) Value() int {
	return int(p)
}
