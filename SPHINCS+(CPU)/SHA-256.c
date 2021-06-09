#include "type.h"

static const u8 IV[DIGEST] = { 
	0x6a, 0x09, 0xe6, 0x67, 0xbb, 0x67, 0xae, 0x85,
	0x3c, 0x6e, 0xf3, 0x72, 0xa5, 0x4f, 0xf5, 0x3a,
	0x51, 0x0e, 0x52, 0x7f, 0x9b, 0x05, 0x68, 0x8c,
	0x1f, 0x83, 0xd9, 0xab, 0x5b, 0xe0, 0xcd, 0x19
};

int Hash_Block(IN u8* state, IN u8* in, IN u64 xLen) {

	u64 Len = (u64)(state[39]) | (((u64)(state[38])) << 8) |
		(((u64)(state[37])) << 16) | (((u64)(state[36])) << 24) |
		(((u64)(state[35])) << 32) | (((u64)(state[34])) << 40) |
		(((u64)(state[33])) << 48) | (((u64)(state[32])) << 56);

	return SUCCESS;
}

/**
* @brief      중복적으로 사용하는 SEED 값 해시 블록 연산 초기화
* @param      pubkey			공개 키 SEED
* @return     실행 결과
*/
int init_Hash_fuuc(IN u8* pubkey)
{
	u8 BLOCK[HASHBLOCK];
	u32 i = 0;

	for (i = 0; i < DIGEST; i++)
		BLOCK[i] = pubkey[i];
	for (i = DIGEST; i < HASHBLOCK; i++)
		BLOCK[i] = 0;


	for (int i = 0; i < DIGEST; i++)
		state_seed[i] = IV[i];
	for (i = DIGEST; i < 40; i++) {
		state_seed[i] = 0;
	}


}