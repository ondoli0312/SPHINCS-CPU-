#include "type.h"

void set_type(u32 addr[8], u32 type)
{
    ((unsigned char*)addr)[9] = type;
}

void set_keypair_addr(u32 addr[8], u32 keypair)
{
#if HYPERTREE_H/LAYER > 8
    /* We have > 256 OTS at the bottom of the Merkle tree; to specify */
    /* which one, we'd need to express it in two bytes */
    ((unsigned char*)addr)[12] = keypair >> 8;
#endif
    ((unsigned char*)addr)[13] = keypair;
}

void copy_subtree_addr(u32 out[8], const u32 in[8])
{
    memcpy(out, in, 9);
}

void copy_keypair_addr(u32 out[8], const u32 in[8])
{
    memcpy(out, in, 9);
#if  HYPERTREE_H/LAYER > 8
    ((unsigned char*)out)[12] = ((unsigned char*)in)[12];
#endif
    ((unsigned char*)out)[13] = ((unsigned char*)in)[13];
}

void set_chain_addr(u32 addr[8], u32 chain)
{
    ((unsigned char*)addr)[17] = chain;
}