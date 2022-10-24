module poly::zero_copy_sink {
    use std::vector;
    use std::bcs;

    public fun write_bool(b: bool): vector<u8> {
        return bcs::to_bytes<bool>(&b)
    }

    public fun write_u8(u: u8): vector<u8> {
        return bcs::to_bytes<u8>(&u)
    }

    public fun write_u64(u: u64): vector<u8> {
        return bcs::to_bytes<u64>(&u)
    }

    public fun write_u256(high128: u128, low128: u128): vector<u8> {
        let high_bcs = bcs::to_bytes<u128>(&high128);
        let low_bcs = bcs::to_bytes<u128>(&low128);
        vector::append<u8>(&mut low_bcs, high_bcs);
        return low_bcs
    }

    public fun write_var_bytes(bs: &vector<u8>): vector<u8> {
        let res = write_var_uint(vector::length<u8>(bs));
        vector::append(&mut res, *bs);
        return res
    }

    public fun write_var_uint(u: u64): vector<u8> {
        let u_copy = u;
        if (u_copy < 0xFD) {
            return vector<u8>[(u_copy as u8)]
        } else if (u_copy <= 0xFFFF) {
            let b_0 = (((u_copy << 56) >> 56) as u8);
            let b_1 = (((u_copy << 48) >> 56) as u8);
            return vector<u8>[0xFD, b_0, b_1]
        } else if (u_copy <= 0xFFFFFFFF) {
            let b_0 = (((u_copy << 56) >> 56) as u8);
            let b_1 = (((u_copy << 48) >> 56) as u8);
            let b_2 = (((u_copy << 40) >> 56) as u8);
            let b_3 = (((u_copy << 32) >> 56) as u8);
            return vector<u8>[0xFE, b_0, b_1, b_2, b_3]
        } else {
            let res = vector<u8>[0xFF]; 
            vector::append<u8>(&mut res, write_u64(u));
            return res
        }
    }

    #[test_only]
    use poly::zero_copy_source as source;

    #[test]
    fun sink_test() {
        let (v_bool, offset) = source::next_bool(&write_bool(true), 0);
        assert!(v_bool == true, 0);
        assert!(offset == 1, 0);
        let (v_u8, offset) = source::next_u8(&write_u8(255), 0);
        assert!(v_u8 == 255, 0);
        assert!(offset == 1, 0);
        let (v_u64, offset) = source::next_u64(&write_u64(2127648943590824778u64), 0);
        assert!(v_u64 == 2127648943590824778u64, 0);
        assert!(offset == 8, 0);
        let (v_u256_h, v_u256_l, offset) = source::next_u256(&write_u256(2127648943590824778798723478234u128, 849583948593845703094853094853u128), 0);
        assert!(v_u256_h == 2127648943590824778798723478234u128, 0);
        assert!(v_u256_l == 849583948593845703094853094853u128, 0);
        assert!(offset == 32, 0);
        
        let (v_bytes, offset) = source::next_var_bytes(&write_var_bytes(&x"32342a23b423b4d2342349c8084e09852f34"), 0);
        assert!(v_bytes == x"32342a23b423b4d2342349c8084e09852f34", 0);
        assert!(offset == 18 + 1, 0);

        (v_bytes, offset) = source::next_var_bytes(&write_var_bytes(&x"3f"), 0);
        assert!(v_bytes == x"3f", 0);
        assert!(offset == 2, 0);
    }
}