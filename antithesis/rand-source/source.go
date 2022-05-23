package source

/*
	The command line must specify a library path (using CGO_LDFLAGS). CGO_CFLAGS
	need not be set, since the Antithesis random functions are declared
	inline, below. In the unlikely event that any of these changes, this file
	must also be changed. Inlining these declarations has proven to be less brittle
	than imposing a compile-time requirement on "instrumentation.h".

	Flags for CGO are collected, so the blank declarations have no effect.
	However, they can be modified in build scripts to be built into customer code.

	The C headers define the various integer types, as well as the free() function.
	The dependency on -lstdc++ is mysterious to us, but necessary.
*/

// #cgo LDFLAGS: -lpthread -ldl -lc -lm -lvoidstar
// #cgo CFLAGS:
// #include <stdlib.h>
// #include <stdbool.h>
// u_int64_t fuzz_get_random();
import "C"

import (
	"math/rand"
)

// ---

type Source struct{}

func (s Source) Seed(seed int64) {
	// ignored
}

func (s Source) Int63() int64 {
	return int64(s.Uint64() >> 1)
}

func (s Source) Uint64() uint64 {
	return (uint64)(C.fuzz_get_random())
}

func NewSource() *rand.Rand {
	return rand.New(Source{})
}
