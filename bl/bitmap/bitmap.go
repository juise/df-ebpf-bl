package bitmap

func New() []uint32 {
	// IPv4 has 32 bit length, 4 octets. Each octet 8 bits, each bit could contain up to 256.
	// To map all 256 values of each octet, we need 256 bits, so each octet is built on top of 8 unit32's.
	// Thus 4 octets * 256 bits / 32 bits = 32
	return make([]uint32, 32) // totally, 1024 bits
}

func SetBit(bitmap []uint32, octet int, i int) {
	// each octet is built on top of 8 uint32's
	bitmap[(8*octet)+(i/32)] = bitmap[(8*octet)+(i/32)] | (1 << (i % 32))
}

func ClearBit(bitmap []uint32, octet int, i int) {
	// each octet is built on top of 8 uint32's
	bitmap[(8*octet)+(i/32)] = bitmap[(8*octet)+(i/32)] & ^(1 << (i % 32))
}

func CheckBit(bitmap []uint32, octet int, i int) bool {
	// each octet is built on top of 8 uint32's
	return bitmap[(8*octet)+(i/32)]&(1<<(i%32)) > 0
}

//func New() []uint8 {
//	// IPv4 has 32 bit length, 4 octets. Each octet 8 bits, each bit could contain up to 256.
//	// To map all 256 values of each octet, we need 256 bits, so each octet is built on top of 8 unit32's.
//	// Thus 4 octets * 256 bits / 32 bits = 32
//	//return make([]uint32, 32) // totally, 1024 bits
//	return make([]uint8, 128 + 4) // totally, 1024 bits
//}
//
//func SetBit(bitmap []uint8, octet int, i int) {
//	// each octet is built on top of 32 + 1 uint8's
//	bitmap[(33 * octet) + (i / 8)] = bitmap[(33 * octet) + (i / 8)] | (1 << (i % 8))
//}
//
//func ClearBit(bitmap []uint8, octet int, i int) {
//	// each octet is built on top of 8 uint32's
//	bitmap[(33 * octet) + (i / 8)] = bitmap[(33 * octet) + (i / 8)] & ^(1 << (i % 8))
//}
//
//func CheckBit(bitmap []uint8, octet int, i int) bool {
//	// each octet is built on top of 8 uint32's
//	return bitmap[(33 * octet) + (i / 8)] & (1 << (i % 8)) > 0
//}
//
//
