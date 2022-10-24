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
        let digest = hash::sha2_256(headerHash);
        while (index < sigCount) {
            sig = secp256k1::ecdsa_signature_from_bytes(putil::slice<u8>(sigList, index*POLYCHAIN_SIGNATURE_LEN, APTOS_SIGNATURE_LEN));
            recovery_id = *vector::borrow<u8>(sigList, index*POLYCHAIN_SIGNATURE_LEN + APTOS_SIGNATURE_LEN);
            let signer_opt = secp256k1::ecdsa_recover(digest, recovery_id, &sig);
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

    #[test]
    fun merkle_prove_test() {
        let merkle_value = x"205b89a0c228ef2540bf7d48a449fa11bcf555009871fd42ddaa5bc1fee65cc71c070000000000000020000000000000000000000000000000000000000000000000000000000002dfee2008867d4bcc06b0bf882fe8fda349f584bee39116ed8b2a15cf69e78147b44a9a14020c15e7d08a8ec7d35bcf3ac3ccbf0bbf2704e60600000000000000142f7ac9436ba4b548f9582af91ca1ef02cd2f1f0306756e6c6f636b4a14aee4164c1ee46ed0bbc34790f1a3d1fc8779666814d726d5d92545e840dea04a1268fddbca77398906fdd549c0cfdb42b1500f00000000000000000000000000000000000000000000";
        let audit_path = x"ef205b89a0c228ef2540bf7d48a449fa11bcf555009871fd42ddaa5bc1fee65cc71c070000000000000020000000000000000000000000000000000000000000000000000000000002dfee2008867d4bcc06b0bf882fe8fda349f584bee39116ed8b2a15cf69e78147b44a9a14020c15e7d08a8ec7d35bcf3ac3ccbf0bbf2704e60600000000000000142f7ac9436ba4b548f9582af91ca1ef02cd2f1f0306756e6c6f636b4a14aee4164c1ee46ed0bbc34790f1a3d1fc8779666814d726d5d92545e840dea04a1268fddbca77398906fdd549c0cfdb42b1500f0000000000000000000000000000000000000000000000372c064816078fe141733149e9fac0909862c84d1a0a03077f5bfc5c09ff5b13";
        let state_root = x"e573c917e6417629d19537417b2739cab162b02e8df2eba20da51a1f4f97bf12";
        let value = merkleProve(&audit_path, &state_root);
        assert!(merkle_value == value, 0);
    }

    #[test]
    fun verifySig_test() {
        let sig = x"a7c7e731c5c725d0b42c9d7f3a1750cb86681dfc7d1f775774f73984e607f4a9514c9deac23cdd76419d1e1d8a58c9316c3fc1c22809afc925b41edc70333a0b003b88138c280d96feea4cb37f81d341722fd276c2f179a464a8b3cb313a3c48590928ff3051207a5de9c4d00b42b0a52aa2aa8546acf29e71ae81da3b063b13cb00f43aa5cb2a183d3c9d3d464ef4e1ab3bce15c2663e3dee1da14a502a388f51791dd7bc54c47fa72f261fbdab62003dec1eb3336a78529f564f1a2c71006043d200";
        let header = x"000000000000000000000000287a588967978f8ff114e3cb914ccf20afecf45fce0c9dedb51cd252a4e30a26401358a308008e647eeee0ecd6119bdca0a8f8cbe904e49d02e1d1937e095c6aece1d19f467838d6f6e77a475e5c29dd6c4713602bf8568410ebf5a9931463ce140b30be8833e4665b9644ce13f50e9c79c4720497f9e5ef3fcfa53aaa565f295a4c526364fc6a01800141df9b5f387efd13017b226c6561646572223a322c227672665f76616c7565223a224243453258366773713546465677584e2f315868776e716567306a4c3149386e77466d7462735264784139586b7663672f58365671393954554a646e62334b6b6733424d46594759683844505159466f6d44523251324d3d222c227672665f70726f6f66223a226c664f3444634a426472616e55507775354649304d58657a33485875442b2f5671635355594f485561474a45614751313447617641456b504e59456e4472574a747232594e65704c51364536304349436e49536744773d3d222c226c6173745f636f6e6669675f626c6f636b5f6e756d223a32333736303030302c226e65775f636861696e5f636f6e666967223a6e756c6c7d0000000000000000000000000000000000000000";
        let keepers = vector[
            x"2bed55e8c4d9cbc50657ff5909ee51dc394a92aad911c36bace83c4d63540794bc68a65f1a54ec4f14a630043090bc29ee9cddf90f3ecb86e0973ffff3fd4899",
            x"09c6475ce07577ab72a1f96c263e5030cb53a843b00ca1238a093d9dcb183e2fec837e621b7ec6db7658c9b9808da304aed599043de1b433d490ff74f577c53d",
            x"e68a6e54bdfa0af47bd18465f4352f5151dc729c61a7399909f1cd1c6d816c0241800e782bb05f6f803b9f958930ebcee0b67d3af27845b4fbfa09e926cf17ae",
            x"29e0d1c5b2ae838930ae1ad861ddd3d0745d1c7f142492cabd02b291d2c95c1dda6633dc7be5dd4f9597f32f1e45721959d0902a8e56a58b2db79ada7c3ce932",
        ];
        assert!(verifySig(&header, &sig, &keepers, 3), 0);

        let invalid_sig = x"0508f2ab200cf3cb67cebac6fa3db7a697879cbeefcbb6fc4d6322a4941bf0a731560090c50850de069c013302eeb078746ee880d19b7562bd060c79ee135bfc005074863655161b368c3fd46f67f7badfa3dbef5536f0cb119c7254d30835a1da2fb5d7ab8a73379642b6f983fe43016dbfc3d3086f680e48fe18deef05541ea2017c58719c83f6ca0dcfe67be3920942888bdc2c6bb11efb333ea1ff7f664a5ab63750a35bff4908c481e1f5190533de77b5b222062e0b30fddf0f919174b6894a00";
        assert!(!verifySig(&header, &invalid_sig, &keepers, 3), 0);
    }

    #[test]
    fun containMAddresses_test() {
        assert!(containMAddresses(&vector[x"01", x"02"], &vector[x"01", x"02"], 2), 0);
        assert!(containMAddresses(&vector[x"01", x"02", x"03", x"04"], &vector[x"01", x"02", x"03"], 3), 0);
        assert!(!containMAddresses(&vector[x"01", x"02", x"03", x"04"], &vector[x"01", x"02", x"02"], 3), 0);
        assert!(!containMAddresses(&vector[x"01", x"02", x"03", x"04"], &vector[x"01", x"02"], 3), 0);
        assert!(!containMAddresses(&vector[x"01", x"02"], &vector[x"01", x"02", x"03"], 3), 0);
    }

    #[test]
    fun deserialize_merkleValue_test() {
        let raw = x"20f2016474450de41ec5de10698fc58f491d0d1762e1daefdcf67209130db7343b020000000000000020000000000000000000000000000000000000000000000000000000000000f9c22019c40eefcf65a7a7d3f58431d017b66c1c0ce3e128f74b51947a54d39ab6d36614f7a9fe22149ad2a077eb40a90f316a8a47525ec306000000000000001412682669700109ae1f3b326d74f2a5bdb63549e308627269646765496efdea0114e1443912860ed8baa2841cd4e6bb84337ccf6e4c14f1c21bc271fdfa48e082e1df507d450aa45bc999fc8ae07ebba9c77d450000000000000000000000000000000000000000000000fd9d010314d47a4dbf580fb2c7d745aeda3c9ed1bf9af0d5f1fd8401c6cc82940000000000000000000000000000000000000000000000000000000000000000000000000000000000000000426223eef2e4f577767533aa1854e8b980b1df5f0000000000000000000000000000000000000000000000455768799b4afd210f0000000000000000000000000000000000000000000000000000000000000100000000000000000000000000f1c21bc271fdfa48e082e1df507d450aa45bc9990000000000000000000000000000000000000000000000000000000063527412000000000000000000000000000000000000000000000045204978e8802b2bc800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003000000000000000000000000e1443912860ed8baa2841cd4e6bb84337ccf6e4c0000000000000000000000008ac76a51cc950d9822d68b83fe1ad97b32cd580d000000000000000000000000e9e7cea3dedca5984780bafc599bd69add087d56";
        let (
            txHash,
            fromChainID,
            txParam_txHash,
            txParam_crossChainId,
            txParam_fromContract,
            txParam_toChainId,
            txParam_toContract,
            txParam_method,
            txParam_args
        ) = deserializeMerkleValue(&raw);
        assert!(txHash == x"f2016474450de41ec5de10698fc58f491d0d1762e1daefdcf67209130db7343b", 0);
        assert!(fromChainID == 2, 0);
        assert!(txParam_txHash == x"000000000000000000000000000000000000000000000000000000000000f9c2", 0);
        assert!(txParam_crossChainId == x"19c40eefcf65a7a7d3f58431d017b66c1c0ce3e128f74b51947a54d39ab6d366", 0);
        assert!(txParam_fromContract == x"f7a9fe22149ad2a077eb40a90f316a8a47525ec3", 0);
        assert!(txParam_toChainId == 6, 0);
        assert!(txParam_toContract == x"12682669700109ae1f3b326d74f2a5bdb63549e3", 0);
        assert!(txParam_method == x"627269646765496e", 0);
        assert!(txParam_args == x"14e1443912860ed8baa2841cd4e6bb84337ccf6e4c14f1c21bc271fdfa48e082e1df507d450aa45bc999fc8ae07ebba9c77d450000000000000000000000000000000000000000000000fd9d010314d47a4dbf580fb2c7d745aeda3c9ed1bf9af0d5f1fd8401c6cc82940000000000000000000000000000000000000000000000000000000000000000000000000000000000000000426223eef2e4f577767533aa1854e8b980b1df5f0000000000000000000000000000000000000000000000455768799b4afd210f0000000000000000000000000000000000000000000000000000000000000100000000000000000000000000f1c21bc271fdfa48e082e1df507d450aa45bc9990000000000000000000000000000000000000000000000000000000063527412000000000000000000000000000000000000000000000045204978e8802b2bc800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003000000000000000000000000e1443912860ed8baa2841cd4e6bb84337ccf6e4c0000000000000000000000008ac76a51cc950d9822d68b83fe1ad97b32cd580d000000000000000000000000e9e7cea3dedca5984780bafc599bd69add087d56", 0);
    }

    #[test]
    fun deserialize_header_test() {
        let raw = x"0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000453c810e2d58aeb9aabc22723666785fa200c1d9fea5a5006d9e506df0911d7e00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008e305f000000001dac2b7c00000000fdb2037b226c6561646572223a343239343936373239352c227672665f76616c7565223a22484a675171706769355248566745716354626e6443456c384d516837446172364e4e646f6f79553051666f67555634764d50675851524171384d6f38373853426a2b38577262676c2b36714d7258686b667a72375751343d222c227672665f70726f6f66223a22785864422b5451454c4c6a59734965305378596474572f442f39542f746e5854624e436667354e62364650596370382f55706a524c572f536a5558643552576b75646632646f4c5267727052474b76305566385a69413d3d222c226c6173745f636f6e6669675f626c6f636b5f6e756d223a343239343936373239352c226e65775f636861696e5f636f6e666967223a7b2276657273696f6e223a312c2276696577223a312c226e223a342c2263223a312c22626c6f636b5f6d73675f64656c6179223a31303030303030303030302c22686173685f6d73675f64656c6179223a31303030303030303030302c22706565725f68616e647368616b655f74696d656f7574223a31303030303030303030302c227065657273223a5b7b22696e646578223a312c226964223a2231323035303330396336343735636530373537376162373261316639366332363365353033306362353361383433623030636131323338613039336439646362313833653266227d2c7b22696e646578223a322c226964223a2231323035303332626564353565386334643963626335303635376666353930396565353164633339346139326161643931316333366261636538336334643633353430373934227d2c7b22696e646578223a332c226964223a2231323035303265363861366535346264666130616634376264313834363566343335326635313531646337323963363161373339393930396631636431633664383136633032227d2c7b22696e646578223a342c226964223a2231323035303232396530643163356232616538333839333061653161643836316464643364303734356431633766313432343932636162643032623239316432633935633164227d5d2c22706f735f7461626c65223a5b342c312c332c312c322c322c312c342c332c312c312c332c332c312c312c342c342c312c332c312c342c322c342c322c332c342c332c342c332c332c312c322c322c332c312c342c312c312c312c322c342c332c332c322c342c322c332c312c322c342c332c322c322c332c342c322c342c322c322c345d2c226d61785f626c6f636b5f6368616e67655f76696577223a36303030307d7d40e80b1c8c5ab0510c27506970c82e462cb115140000";
        let (
            version,
            chainId,
            timestamp,
            height,
            consensusData,
            _,
            _,
            crossStatesRoot,
            _,
            _,
            nextBookkeeper
        ) = deserializeHeader(&raw);
        assert!(version == 0, 0);
        assert!(chainId == 0, 0);
        assert!(timestamp == 1597017600, 0);
        assert!(height == 0, 0);
        assert!(consensusData == 2083236893u64, 0);
        assert!(nextBookkeeper == x"40e80b1c8c5ab0510c27506970c82e462cb11514", 0);
        assert!(crossStatesRoot == x"0000000000000000000000000000000000000000000000000000000000000000", 0);
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