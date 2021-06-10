#include "type.h"

void SHA256_addr(u8* out, u8* key, u32* addr) {
	u8 buffer[DIGEST + 22];
	u8 output[DIGEST];

	memcpy(buffer, key, DIGEST);
	memcpy(buffer + DIGEST, addr, 22);

	OP_SHA256(buffer, DIGEST + 22, output);
	memcpy(out, output, DIGEST);
}

void wots_gen_sk(u8* sk, u8* sk_seed, u32* wots_addr) {
	set_hash_addr(wots_addr, 0);
	SHA256_addr(sk, sk_seed, wots_addr);
}

void tHash(u8* out, u8* in, u32 inblocks, u8* pk_seed,  u32* addr){
	u8* buffer = (u8*)malloc(22 + (DIGEST * inblocks));
	if (buffer == NULL)
		return;
	u8* output[DIGEST];
	u8 sha2_state[40];

	memcpy(sha2_state, state_seed, 40 * sizeof(u8));
	memcpy(buffer, addr, 22 * sizeof(u8));
	memcpy(buffer + 22, in, inblocks * DIGEST);
	SHA256_inc_final(output, sha2_state, in, 22 + (DIGEST * inblocks));
	memcpy(out, output, DIGEST);
	free(buffer);
}

void chain(u8* out, u8* in, u32 startPoint, u32 steps, u8* pk_seed, u32* addr) {
	u32 cnt = 0;
	memcpy(out, in, DIGEST);
	for (cnt = startPoint; cnt < (startPoint + steps) && cnt < WOTS_W; cnt++) {
		set_hash_addr(addr, cnt);
		tHash(out, out, 1, pk_seed, addr);
	}
}

void wots_gen_pk(u8* pk, u8* sk_seed, u8* pk_seed, u32 addr[8]){
	u32 i = 0;
	for (i = 0; i < WOTS_LEN; i++) {
		set_chain_addr(addr, i);
		wots_gen_sk(pk + (i * DIGEST), sk_seed, addr);
		chain(pk + (i * DIGEST), pk + (i * DIGEST), 0, WOTS_W -1, pk_seed, addr);
	}

}

int wots_gen_leaf(u8* leaf, u8* sk_seed, u8* pk_seed, u32 addr_idx, u32 Tree_addr[8])
{
	u8 pk_buf[WOTS_BYTE];
	u32 wots_addr[8];
	u32 wots_pk_addr[8];

	set_type(wots_addr, 0);
	set_type(wots_pk_addr, 1);
	copy_subtree_addr(wots_addr, Tree_addr);
	set_keypair_addr(wots_addr, addr_idx);
	wots_gen_pk(pk_buf, sk_seed, pk_seed, wots_addr);
	copy_keypair_addr(wots_pk_addr, wots_addr);
	//thash
	tHash(leaf, pk_buf, WOTS_LEN, pk_seed, wots_pk_addr);
	return SUCCESS;
}