#include "type.h"

void wots_gen_pk(u8* pk, u8* sk_seed, u8* pk_seed, u32 addr[8]){
	u32 i = 0;
	for (i = 0; i < WOTS_LEN; i++) {
		set_chain_addr(addr, i);
		wots_gen_sk();
		gen_chain();
	}

}

int wots_gen_leaf(u8* leaf, u8* sk_seed, u8* pk_seed, u32 addr_idx, u32 Tree_addr[8])
{
	u8 pk_buf[WOTS_BYTE];
	u32 wots_addr[8];
	u32 wots_pk_addr[8];

	set_type(wots_addr, 0);
	set_type(wots_pk_addr, 1);
	memcpy(wots_addr, Tree_addr, 9);
	set_keypair_addr(wots_addr, addr_idx);
	//wots_gen_pk
	copy_keypair_addr(wots_pk_addr, wots_addr);
	//thash
}