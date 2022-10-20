module poly::cross_chain_utils {
    use std::hash;
    use std::vector;
    use std::option;
    use aptos_std::secp256k1;
    use poly::utils as putil;

    const MERKLE_PROOF_NODE_LEN: u64 = 33;
    const POLYCHAIN_SIGNATURE_LEN: u64 = 65;
    const APTOS_SIGNATURE_LEN: u64 = 64;

    const EINVALID_POSITION: u64 = 1;
    const EROOT_NOT_MATCH: u64 = 2;

    struct Header has copy, drop {
        version: u64,
        chainId: u64,
        timestamp: u64,
        height: u64,
        consensusData: u64,
        prevBlockHash: vector<u8>,
        transactionsRoot: vector<u8>,
        crossStatesRoot: vector<u8>,
        blockRoot: vector<u8>,
        consensusPayload: vector<u8>,
        nextBookkeeper: vector<u8>
    }

    struct ToMerkleValue has copy, drop {
        txHash: vector<u8>,
        fromChainID: u64,
        makeTxParam: TxParam
    }

    struct TxParam has copy, drop {
        txHash: vector<u8>,
        crossChainId: vector<u8>,
        fromContract: vector<u8>,
        toChainId: u64,
        toContract: vector<u8>,
        method: vector<u8>,
        args: vector<u8>
    }

    public fun merkleProve(auditPath: &vector<u8>, root: &vector<u8>): vector<u8> {
        let offset: u64 = 0;
        let value: vector<u8>;
        (value, offset) = poly::zero_copy_source::next_var_bytes(auditPath, offset);
        let hash: vector<u8> = hashLeaf(&value);
        let size: u64 = (vector::length(auditPath) - offset) / MERKLE_PROOF_NODE_LEN;
        let nodeHash: vector<u8>;
        let index: u64 = 0;
        let pos: u8;
        while (index < size) {
            (pos, offset) = poly::zero_copy_source::next_byte(auditPath, offset);
            (nodeHash, offset) = poly::zero_copy_source::next_hash(auditPath, offset);
            hash = if (pos == 0) {
                hashChildren(&nodeHash, &hash)
            } else if (pos == 1) {
                hashChildren(&hash, &nodeHash)
            } else {
                abort EINVALID_POSITION
            };
            index = index + 1;
        };
        assert!(hash == *root, EROOT_NOT_MATCH);
        return value
    }

    fun hashLeaf(data: &vector<u8>): vector<u8> {
        let data_copy = vector<u8>[0x00];
        vector::append(&mut data_copy, *data);
        return hash::sha2_256(data_copy)
    }

    fun hashChildren(l: &vector<u8>, r: &vector<u8>): vector<u8> {
        let data = vector<u8>[0x01];
        vector::append(&mut data, *l);
        vector::append(&mut data, *r);
        return hash::sha2_256(data)
    }

    public fun verifySig(rawHeader: &vector<u8>, sigList: &vector<u8>, keepers: &vector<vector<u8>>, threshold: u64): bool  {
        let headerHash = getHeaderHash(rawHeader);
        let sigCount = vector::length<u8>(sigList)/POLYCHAIN_SIGNATURE_LEN;
        let signers = vector::empty<vector<u8>>();
        let recovery_id: u8;
        let sig: secp256k1::ECDSASignature;
        let index: u64 = 0;
        while (index < sigCount) {
            sig = secp256k1::ecdsa_signature_from_bytes(putil::slice<u8>(sigList, index*POLYCHAIN_SIGNATURE_LEN, APTOS_SIGNATURE_LEN));
            recovery_id = *vector::borrow<u8>(sigList, index*POLYCHAIN_SIGNATURE_LEN + APTOS_SIGNATURE_LEN);
            let signer_opt = secp256k1::ecdsa_recover(hash::sha2_256(headerHash), recovery_id, &sig);
            if (option::is_none(&signer_opt)) {
                return false
            };
            let the_signer = secp256k1::ecdsa_raw_public_key_to_bytes(&option::extract(&mut signer_opt));
            vector::push_back<vector<u8>>(&mut signers, the_signer);
            index = index + 1;
        };
        return containMAddresses(keepers, &signers, threshold)
    }

    fun containMAddresses(keepers: &vector<vector<u8>>, signers: &vector<vector<u8>>, threshold: u64): bool {
        let keepers_copy = *keepers;
        let cnt: u64 = 0; 
        while (!vector::is_empty<vector<u8>>(&keepers_copy)) {
            let s = vector::pop_back<vector<u8>>(&mut keepers_copy);
            if (vector::contains<vector<u8>>(signers, &s)) {
                cnt = cnt + 1;
            };
        };
        return cnt >= threshold
    }

    public fun deserializeMerkleValue(valueBs: &vector<u8>): (
        vector<u8>,
        u64,
        vector<u8>,
        vector<u8>,
        vector<u8>,
        u64,
        vector<u8>,
        vector<u8>,
        vector<u8>) 
    {
        let txHash: vector<u8>;
        let fromChainID: u64;
        let txParam_txHash: vector<u8>;
        let txParam_crossChainId: vector<u8>;
        let txParam_fromContract: vector<u8>;
        let txParam_toChainId: u64;
        let txParam_toContract: vector<u8>;
        let txParam_method: vector<u8>;
        let txParam_args: vector<u8>;
        let offset: u64 = 0;

        (txHash, offset) = poly::zero_copy_source::next_var_bytes(valueBs, offset);
        (fromChainID, offset) = poly::zero_copy_source::next_u64(valueBs, offset);

        (txParam_txHash, offset) = poly::zero_copy_source::next_var_bytes(valueBs, offset);
        (txParam_crossChainId, offset) = poly::zero_copy_source::next_var_bytes(valueBs, offset);
        (txParam_fromContract, offset) = poly::zero_copy_source::next_var_bytes(valueBs, offset);
        (txParam_toChainId, offset) = poly::zero_copy_source::next_u64(valueBs, offset);
        (txParam_toContract, offset) = poly::zero_copy_source::next_var_bytes(valueBs, offset);
        (txParam_method, offset) = poly::zero_copy_source::next_var_bytes(valueBs, offset);
        (txParam_args, _) = poly::zero_copy_source::next_var_bytes(valueBs, offset);

        return (
            txHash,
            fromChainID,
            txParam_txHash,
            txParam_crossChainId,
            txParam_fromContract,
            txParam_toChainId,
            txParam_toContract,
            txParam_method,
            txParam_args
        )
    }

    public fun deserializeHeader(headerBs : &vector<u8>): (
        u64,
        u64,
        u64,
        u64,
        u64,
        vector<u8>,
        vector<u8>,
        vector<u8>,
        vector<u8>,
        vector<u8>,
        vector<u8>)
    {
        let version: u64;
        let chainId: u64;
        let timestamp: u64;
        let height: u64;
        let consensusData: u64;
        let prevBlockHash: vector<u8>;
        let transactionsRoot: vector<u8>;
        let crossStatesRoot: vector<u8>;
        let blockRoot: vector<u8>;
        let consensusPayload: vector<u8>;
        let nextBookkeeper: vector<u8>;
        let offset: u64 = 0;

        (version, offset) = poly::zero_copy_source::next_u32(headerBs , offset);
        (chainId, offset) = poly::zero_copy_source::next_u64(headerBs , offset);
        (prevBlockHash, offset) = poly::zero_copy_source::next_hash(headerBs , offset);
        (transactionsRoot, offset) = poly::zero_copy_source::next_hash(headerBs , offset);
        (crossStatesRoot, offset) = poly::zero_copy_source::next_hash(headerBs , offset);
        (blockRoot, offset) = poly::zero_copy_source::next_hash(headerBs , offset);
        (timestamp, offset) = poly::zero_copy_source::next_u32(headerBs , offset);
        (height, offset) = poly::zero_copy_source::next_u32(headerBs , offset);
        (consensusData, offset) = poly::zero_copy_source::next_u64(headerBs , offset);
        (consensusPayload, offset) = poly::zero_copy_source::next_var_bytes(headerBs , offset);
        (nextBookkeeper, _) = poly::zero_copy_source::next_bytes20(headerBs , offset);
        
        return (
            version,
            chainId,
            timestamp,
            height,
            consensusData,
            prevBlockHash,
            transactionsRoot,
            crossStatesRoot,
            blockRoot,
            consensusPayload,
            nextBookkeeper
        )
    }

    public fun getHeaderHash(rawHeader: &vector<u8>): vector<u8> {
        return hash::sha2_256(hash::sha2_256(*rawHeader))
    }
}

/*

    struct Header {
        uint32 version;
        uint64 chainId;
        uint32 timestamp;
        uint32 height;
        uint64 consensusData;
        bytes32 prevBlockHash;
        bytes32 transactionsRoot;
        bytes32 crossStatesRoot;
        bytes32 blockRoot;
        bytes consensusPayload;
        bytes20 nextBookkeeper;
    }

    struct ToMerkleValue {
        bytes  txHash;  // cross chain txhash
        uint64 fromChainID;
        TxParam makeTxParam;
    }

    struct TxParam {
        bytes txHash; //  source chain txhash
        bytes crossChainId;
        bytes fromContract;
        uint64 toChainId;
        bytes toContract;
        bytes method;
        bytes args;
    }

*/