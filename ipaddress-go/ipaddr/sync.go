package ipaddr

import (
	"sync"
	"sync/atomic"
)

// A flag is set just once by just one goroutine
type atomicFlag struct {
	val uint32
}

func (a *atomicFlag) isSet() bool {
	return atomic.LoadUint32(&a.val) != 0
}

func (a *atomicFlag) isSetNoSync() bool {
	return a.val == 0
}

func (a *atomicFlag) set() {
	atomic.StoreUint32(&a.val, 1)
}

//func (a *atomicFlag) unset() {
//	atomic.StoreUint32(&a.val, 0)
//}

type CreationLock struct {
	created    atomicFlag // to check if created
	createLock sync.Mutex // acquire to create
}

func (lock *CreationLock) isItemCreated() bool {
	return lock.created.isSet()
}

func (lock *CreationLock) create(creator func()) (ret bool) {
	lock.createLock.Lock()
	if !lock.created.isSetNoSync() {
		creator()
		ret = true
		lock.created.set()
	}
	lock.createLock.Unlock()
	return
}
