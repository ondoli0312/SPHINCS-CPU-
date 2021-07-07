#include "type.h"
#include "SHA-256.h"

/**
* @brief      랜덤 값 생성
* @param      result			출력 저장 배열
* @param      xLen				출력 길이
* @return     실행 결과
*/
int randombytes(OUT u8* result, IN u64 xLen)
{
	for (int i = 0; i < xLen; i++) {
		result[i] = i ;
	}
	return SUCCESS;
}

int generateKey_TreeHash(u8* output, const u8* sk_seed, const u8* pk_seed, 
	u32 leaf_index, u32 idx_offset, u32* tree_addr)
{
	u8 stack[(SUBTREE_H + 1) * DIGEST];
	u8 heights[(1 << SUBTREE_H) + 1];
	u32 offset = 0;
	u32 idx = 0;
	u32 tree_idx = 0;

	for (idx = 0; idx < (u32)(1 << SUBTREE_H); idx++) {
		wots_gen_leaf(stack + (offset * DIGEST), sk_seed, pk_seed, idx + idx_offset, tree_addr);
		offset += 1;
		heights[offset - 1] = 0;

		while (offset >= 2 && (heights[offset - 1] == heights[offset - 2])) 
		{
			tree_idx = (idx >> (heights[offset - 1] + 1));
			set_tree_height(tree_addr, heights[offset - 1] + 1);
			set_tree_index(tree_addr, tree_idx + (idx_offset >> (heights[offset - 1] + 1))); 
			tHash(stack + (offset - 2) * DIGEST, stack + (offset - 2) * DIGEST, 2, pk_seed, tree_addr);
			offset--;
			heights[offset - 1]++;
		}
	}
	memcpy(output, stack, DIGEST);


}

/**
* @brief	seed를 통한 공개 키/개인 키 생성
* @brief	sk : [SK_SEED || SK_PRF || PUB_SEED || root]
* @brief	pk : [PUB_SEED || root]
* @param	pubkey		공개키 저장할 배열	
* @param    prikey		개인키 저장할 배열
* @return   실행 결과
*/
int generate_Key(OUT u8* pk, OUT u8* sk)
{
	u8 SEED[SEED_BYTE];
	u32 top_tree_addr[8] = { 0, };
	randombytes(SEED, SEED_BYTE);

	set_layer_addr(top_tree_addr, LAYER -1);
	set_type(top_tree_addr, 2);


	//생성된 SEED를 바탕으로 키를 초기화
	memcpy(sk, SEED, SEED_BYTE);
	memcpy(pk, SEED + (2 * DIGEST), DIGEST);
	
	//해시 값 초기화(추후에 사용할 값을 미리 초기화하여 중복적으로 사용)
	init_Hash_func(pk);

	for (int i = 0; i < 10; i++)
		printf("%08X ", state_seed[i]);
	printf("\n");

	generateKey_TreeHash(sk + 3 * DIGEST, sk, sk + 2 * DIGEST, 0, 0, top_tree_addr);
	memcpy(pk + DIGEST, sk + 3 * DIGEST, DIGEST);
	return SUCCESS;
}

void base_w(u32* output, u32 out_len, u8* input) {
	u32 in = 0;
	u32 out = 0;
	u32 bits = 0;
	u32 consumed = 0;
	u8 total = 0;

	for (consumed = 0; consumed < out_len; consumed++) {
		if (bits == 0) {
			total = input[in++];
			bits += 8;
		}
		bits -= WOTS_LOGW;
		output[out++] = (total >> bits) & (WOTS_W - 1);
	}
	
}

void ull_to_bytes(unsigned char* out, unsigned int outlen,
	unsigned long long in)
{
	int i;

	/* Iterate over out in decreasing order, for big-endianness. */
	for (i = outlen - 1; i >= 0; i--) {
		out[i] = in & 0xff;
		in = in >> 8;
	}
}

void wots_checksum(u32* csum_base_w, u32* msg_base_w) {
	u32 csum = 0;
	u32 i = 0;
	u8 csum_bytes[(WOTS_LEN_2 * WOTS_LOGW + 7) / 8];
	
	for (i = 0; i < WOTS_LEN_1; i++) {
		csum += WOTS_W - 1 - msg_base_w[i];
	}

	csum = csum << ((8 - ((WOTS_LEN_1 * WOTS_LOGW) % 8)) % 8);
	ull_to_bytes(csum_bytes, sizeof(csum_bytes), csum);
	base_w(csum_base_w, WOTS_LEN_2, csum_bytes);
}

static void chain_lengths(unsigned int* lengths, const unsigned char* msg)
{
	base_w(lengths, WOTS_LEN_1, msg);
	wots_checksum(lengths + WOTS_LEN_1, lengths);
}

void wots_sign(u8* sig, u8* msg, u8* sk_seed, u8* pk_seed, u32 addr[8]) {
	u32 lengths[WOTS_LEN];
	u32 i;
	chain_lengths(lengths, msg);
	for (i = 0; i < WOTS_LEN; i++) {
		set_chain_addr(addr, i);
		wots_gen_sk(sig + i * DIGEST, sk_seed, addr);
		chain(sig + i * DIGEST, sig + i * DIGEST, 0, lengths[i], pk_seed, addr);
	}

}