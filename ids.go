package main

import (
	"strconv"
	"sync/atomic"
	"time"
)

// essentially random 0-65535
var _id = uint64(uint16(time.Now().UnixNano()))

func FreeId() string {
	id := atomic.AddUint64(&_id, 1)

	return strconv.FormatUint(id, 16)
}
