#include <iostream>
#include <endian.h>
#include <stdint.h>

using namespace std;

static inline uint16_t my_be16toh(uint16_t v) {
	return ((v&0xff)<<8) | ((v&0xff00)>>8);
}

static inline uint32_t my_be32toh(uint32_t v) {
	return (((uint32_t)my_be16toh(v&0x0000ffffU))<<16) | (uint32_t)my_be16toh((v&0xffff0000U)>>16); 
}

static inline uint64_t my_be64toh(uint64_t v) {
	return (((uint64_t)my_be32toh(v&0x00000000ffffffffU))<<32) | (uint64_t)my_be32toh((v&0xffffffff00000000U)>>32);
}

int main() {
	for(uint64_t i = 0; i < UINT64_MAX; ++i) {
		if(my_be16toh(i) != be16toh(i))
			cout<< "16 wrong => " << i << endl;
		if(my_be32toh(i) != be32toh(i))
			cout<< "32 wrong => " << i << endl;
		if(my_be64toh(i) != be64toh(i))
			cout<< "64 wrong => " << i << endl;
		if(i % 100000000 == 0)
			cout << "current => " <<  i << endl;
	}
	return 0;
}

