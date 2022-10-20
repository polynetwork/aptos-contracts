module poly::zero_copy_source {
    use std::vector;
    use poly::utils as putil;

    public fun next_bool(bs: &vector<u8>, offset: u64): (bool, u64) {
        let res = *vector::borrow<u8>(bs, offset);
        return (putil::to_bool(vector<u8>[res]), offset+1)
    }

    public fun next_byte(bs: &vector<u8>, offset: u64): (u8, u64) {
        let res = *vector::borrow<u8>(bs, offset);
        return (res, offset+1)
    }

    public fun next_u8(bs: &vector<u8>, offset: u64): (u8, u64) {
        let res = *vector::borrow<u8>(bs, offset);
        return (res, offset+1)
    }

    public fun next_u32(bs: &vector<u8>, offset: u64): (u64, u64) {
        let res = putil::slice<u8>(bs, offset, 4);
        vector::append(&mut res, vector<u8>[0, 0, 0, 0]);
        return (putil::to_u64(res), offset+4)
    }

    public fun next_u64(bs: &vector<u8>, offset: u64): (u64, u64) {
        let res = putil::slice<u8>(bs, offset, 8);
        return (putil::to_u64(res), offset+8)
    }

    // return (high128, low128, offset)
    public fun next_u256(bs: &vector<u8>, offset: u64): (u128, u128, u64) {
        let low_bcs = putil::slice<u8>(bs, offset, 16);
        let high_bcs = putil::slice<u8>(bs, offset+16, 16);
        return (putil::to_u128(high_bcs), putil::to_u128(low_bcs), offset+32)
    }

    public fun next_hash(bs: &vector<u8>, offset: u64): (vector<u8>, u64) {
        return (putil::slice<u8>(bs, offset, 32), offset+32)
    }

    public fun next_bytes20(bs: &vector<u8>, offset: u64): (vector<u8>, u64) {
        return (putil::slice<u8>(bs, offset, 20), offset+20)
    }

    public fun next_var_bytes(bs: &vector<u8>, offset: u64): (vector<u8>, u64) {
        let length: u64;
        (length, offset) = next_var_uint(bs, offset);
        return (putil::slice<u8>(bs, offset, length), offset+length)
    }

    public fun next_var_uint(bs: &vector<u8>, offset: u64): (u64, u64) {
        let prefix = *vector::borrow<u8>(bs, offset);
        if (prefix < 0xFD) {
            return ((prefix as u64), offset+1)
        } else if (prefix == 0xFD) {
            let b_0 = (*vector::borrow<u8>(bs, offset+1) as u64);
            let b_1 = (*vector::borrow<u8>(bs, offset+2) as u64);
            let res = b_0 + (b_1 << 8);
            return (res, offset+3)
        } else if (prefix == 0xFE) {
            let b_0 = (*vector::borrow<u8>(bs, offset+1) as u64);
            let b_1 = (*vector::borrow<u8>(bs, offset+2) as u64);
            let b_2 = (*vector::borrow<u8>(bs, offset+3) as u64);
            let b_3 = (*vector::borrow<u8>(bs, offset+4) as u64);
            let res = b_0 + (b_1 << 8) + (b_2 << 16) + (b_3 << 24);
            return (res, offset+5)
        } else {
            return next_u64(bs, offset+1)
        }
    }
}