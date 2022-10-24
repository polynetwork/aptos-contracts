module poly::cross_chain_manager {
    use std::vector;
    use std::signer;
    use std::hash;
    use std::bcs;
    use std::acl::{ACL, Self};
    use aptos_std::table::{Table, Self};
    use aptos_std::event;
    use aptos_framework::account;

    use poly::zero_copy_sink;
    use poly::cross_chain_utils;


    // Errors
    const EINVALID_SIGNER: u64 = 1;
    const EPAUSED: u64 = 2;
    const EVERIFY_HEADER_FAILED: u64 = 3;
    const EVERIFY_HEADER_PROOF_FAILED: u64 = 4;
    const EALREADY_EXECUTED: u64 = 5;
    const ENOT_TARGET_CHAIN: u64 = 6;
    const EALREADY_HAS_ROLE: u64 = 7;
    const ENOT_HAS_ROLE: u64 = 8;
    const ENOT_ADMIN: u64 = 9;
    const ENOT_PAUSE_ROLE: u64 = 10;
    const ENOT_CA_ROLE: u64 = 11;
    const ENOT_CHANGE_KEEPER_ROLE: u64 = 12;
    const EBLACKLISTED_FROM: u64 = 13;
    const EBLACKLISTED_TO: u64 = 14;
    const EVERIFIER_NOT_RECEIVER: u64 = 15;


    // access control
    struct ACLStore has key, store {
        role_acls: Table<u64, ACL>,
        license_black_list: Table<vector<u8>, u8>
    }

    const ADMIN_ROLE: u64 = 1;
    const PAUSE_ROLE: u64 = 2;
    const CA_ROLE: u64 = 3;
    const CHANGE_KEEPER_ROLE: u64 = 4;

    public fun hasRole(role: u64, account: address): bool acquires ACLStore {
        let acl_store_ref = borrow_global<ACLStore>(@poly);
        if (table::contains(&acl_store_ref.role_acls, role)) {
            let role_acl = table::borrow(&acl_store_ref.role_acls, role);
            return acl::contains(role_acl, account)
        } else {
            return false
        }
    }

    public entry fun grantRole(admin: &signer, role: u64, account: address) acquires ACLStore {
        assert!(hasRole(ADMIN_ROLE, signer::address_of(admin)), ENOT_ADMIN);
        assert!(!hasRole(role, account), EALREADY_HAS_ROLE);
        let acl_store_ref = borrow_global_mut<ACLStore>(@poly);
        if (table::contains(&acl_store_ref.role_acls, role)) {
            let role_acl = table::borrow_mut(&mut acl_store_ref.role_acls, role);
            acl::add(role_acl, account);
        } else {
            let role_acl = acl::empty();
            acl::add(&mut role_acl, account);
            table::add(&mut acl_store_ref.role_acls, role, role_acl);
        }
    }

    public entry fun revokeRole(admin: &signer, role: u64, account: address) acquires ACLStore {
        assert!(hasRole(ADMIN_ROLE, signer::address_of(admin)), ENOT_ADMIN);
        assert!(hasRole(role, account), ENOT_HAS_ROLE);
        let acl_store_ref = borrow_global_mut<ACLStore>(@poly);
        let role_acl = table::borrow_mut(&mut acl_store_ref.role_acls, role);
        acl::remove(role_acl, account);
    }


    // cross chain license
    struct License has key, store {
        account: address,
        module_name: vector<u8>
    }

    public fun issueLicense(ca: &signer, account: address, module_name: vector<u8>): License acquires ACLStore {
        assert!(hasRole(CA_ROLE, signer::address_of(ca)), ENOT_CA_ROLE);
        License{
            account: account,
            module_name: module_name,
        }
    }

    public fun destroyLicense(license: License) {
        let License{ account: _, module_name: _ } = license;
    }

    public fun getLicenseId(license: &License): vector<u8> {
        let res = zero_copy_sink::write_var_bytes(&bcs::to_bytes(&license.account));
        vector::append(&mut res, zero_copy_sink::write_var_bytes(&license.module_name));
        return res
    }

    public fun getLicenseInfo(license: &License): (address, vector<u8>) {
        (license.account, license.module_name)
    }


    // black list
    // access level: 0b000000xy , x means blackListed as fromContract , y means blackListed as toContract
    public fun isBlackListedFrom(license_id: vector<u8>): bool acquires ACLStore {
        let acl_store_ref = borrow_global<ACLStore>(@poly);
        if (table::contains(&acl_store_ref.license_black_list, license_id)) {
            let access_level = *table::borrow(&acl_store_ref.license_black_list, license_id);
            return (access_level & 0x02) != 0
        } else {
            return false
        }
    }

    public fun isBlackListedTo(license_id: vector<u8>): bool acquires ACLStore {
        let acl_store_ref = borrow_global<ACLStore>(@poly);
        if (table::contains(&acl_store_ref.license_black_list, license_id)) {
            let access_level = *table::borrow(&acl_store_ref.license_black_list, license_id);
            return (access_level & 0x01) != 0
        } else {
            return false
        }
    }

    public entry fun setBlackList(ca: &signer, license_id: vector<u8>, access_level: u8) acquires ACLStore {
        assert!(hasRole(CA_ROLE, signer::address_of(ca)), ENOT_CA_ROLE);
        let acl_store_ref = borrow_global_mut<ACLStore>(@poly);
        let v_ref = table::borrow_mut_with_default(&mut acl_store_ref.license_black_list, license_id, access_level);
        *v_ref = access_level;
    }
 

    // event 
    struct EventStore has key, store {
        init_book_keeper_event: event::EventHandle<InitBookKeeperEvent>,
        change_book_keeper_event: event::EventHandle<ChangeBookKeeperEvent>,
        cross_chain_event: event::EventHandle<CrossChainEvent>,
        verify_header_and_execute_tx_event: event::EventHandle<VerifyHeaderAndExecuteTxEvent>,
    }

    struct InitBookKeeperEvent has store, drop {
        height: u64,
        keepers: vector<vector<u8>>
    }

    struct ChangeBookKeeperEvent has store, drop {
        height: u64,
        keepers: vector<vector<u8>>
    }

    struct CrossChainEvent has store, drop {
        sender: address,
        tx_id: vector<u8>,
        proxy_or_asset_contract: vector<u8>,
        to_chain_id: u64,
        to_contract: vector<u8>,
        raw_data: vector<u8>,
    }

    struct VerifyHeaderAndExecuteTxEvent has store, drop {
        from_chain_id: u64,
        to_contract: vector<u8>,
        cross_chain_tx_hash: vector<u8>,
        from_chain_tx_hash: vector<u8>,
    }

    
    // data store
    struct CrossChainGlobalConfig has key {
        polyId: u64,
        paused: bool,
        ethToPolyTxHashIndex: u128,
        curBookKeepers: vector<vector<u8>>,
        curEpochStartHeight: u64,
        ethToPolyTxHashMap: Table<u128, vector<u8>>,
        fromChainTxExist: Table<u64, Table<vector<u8>, bool>>,
    }

    fun putPolyId(polyId: u64) acquires CrossChainGlobalConfig {
        let config_ref = borrow_global_mut<CrossChainGlobalConfig>(@poly);
        config_ref.polyId = polyId;
    }

    public fun getPolyId(): u64 acquires CrossChainGlobalConfig {
        let config_ref = borrow_global<CrossChainGlobalConfig>(@poly);
        return config_ref.polyId
    }

    fun putCurEpochStartHeight(height: u64) acquires CrossChainGlobalConfig {
        let config_ref = borrow_global_mut<CrossChainGlobalConfig>(@poly);
        config_ref.curEpochStartHeight = height;
    }

    public fun getCurEpochStartHeight(): u64 acquires CrossChainGlobalConfig {
        let config_ref = borrow_global<CrossChainGlobalConfig>(@poly);
        return config_ref.curEpochStartHeight
    }

    fun putCurBookKeepers(keepers: &vector<vector<u8>>) acquires CrossChainGlobalConfig {
        let config_ref = borrow_global_mut<CrossChainGlobalConfig>(@poly);
        config_ref.curBookKeepers = *keepers;
    }

    public fun getCurBookKeepers(): vector<vector<u8>> acquires CrossChainGlobalConfig {
        let config_ref = borrow_global<CrossChainGlobalConfig>(@poly);
        return config_ref.curBookKeepers
    }

    fun markFromChainTxExist(fromChainId: u64, fromChainTx: &vector<u8>) acquires CrossChainGlobalConfig {
        let config_ref = borrow_global_mut<CrossChainGlobalConfig>(@poly);
        if (table::contains(&config_ref.fromChainTxExist, fromChainId)) {
            table::upsert(table::borrow_mut(&mut config_ref.fromChainTxExist, fromChainId), *fromChainTx, true);
            return
        } else {
            let subTable = table::new<vector<u8>, bool>();
            table::add(&mut subTable, *fromChainTx, true);
            table::add(&mut config_ref.fromChainTxExist, fromChainId, subTable);
            return
        }
    }

    public fun checkIfFromChainTxExist(fromChainId: u64, fromChainTx: &vector<u8>): bool acquires CrossChainGlobalConfig {
        let config_ref = borrow_global<CrossChainGlobalConfig>(@poly);
        if (table::contains(&config_ref.fromChainTxExist, fromChainId)) {
            if (table::contains(table::borrow(&config_ref.fromChainTxExist, fromChainId), *fromChainTx)) {
                return *table::borrow(table::borrow(&config_ref.fromChainTxExist, fromChainId), *fromChainTx)
            };
        };
        return false
    }

    public fun getEthTxHashIndex(): u128 acquires CrossChainGlobalConfig {
        let config_ref = borrow_global<CrossChainGlobalConfig>(@poly);
        return config_ref.ethToPolyTxHashIndex
    }

    fun putEthTxHash(hash: &vector<u8>) acquires CrossChainGlobalConfig {
        let config_ref = borrow_global_mut<CrossChainGlobalConfig>(@poly);
        let index = config_ref.ethToPolyTxHashIndex;
        table::upsert(&mut config_ref.ethToPolyTxHashMap, index, *hash);
        config_ref.ethToPolyTxHashIndex = index + 1;
    }

    public fun getEthTxHash(ethHashIndex: u128): vector<u8> acquires CrossChainGlobalConfig {
        let config_ref = borrow_global<CrossChainGlobalConfig>(@poly);
        return *table::borrow(&config_ref.ethToPolyTxHashMap, ethHashIndex)
    }


    // pause/unpause
    public fun paused(): bool acquires CrossChainGlobalConfig {
        let config_ref = borrow_global<CrossChainGlobalConfig>(@poly);
        return config_ref.paused
    }

    public fun pause(account: &signer) acquires CrossChainGlobalConfig, ACLStore {
        assert!(hasRole(PAUSE_ROLE, signer::address_of(account)), ENOT_PAUSE_ROLE);
        let config_ref = borrow_global_mut<CrossChainGlobalConfig>(@poly);
        config_ref.paused = true;
    }

    public fun unpause(account: &signer) acquires CrossChainGlobalConfig, ACLStore {
        assert!(hasRole(PAUSE_ROLE, signer::address_of(account)), ENOT_PAUSE_ROLE);
        let config_ref = borrow_global_mut<CrossChainGlobalConfig>(@poly);
        config_ref.paused = false;
    }


    // initialize
    public fun init(account: &signer, keepers: vector<vector<u8>>, startHeight: u64, polyId: u64) acquires EventStore {
        assert!(signer::address_of(account) == @poly, EINVALID_SIGNER);
        
        // init access control lists
        let acls = table::new<u64, ACL>();
        let admin_acl = acl::empty();
        let pause_acl = acl::empty();
        let ca_acl = acl::empty();
        let keeper_acl = acl::empty();
        acl::add(&mut admin_acl, @poly);
        acl::add(&mut pause_acl, @poly);
        acl::add(&mut ca_acl, @poly);
        acl::add(&mut keeper_acl, @poly);
        table::add(&mut acls, ADMIN_ROLE, admin_acl);
        table::add(&mut acls, PAUSE_ROLE, pause_acl);
        table::add(&mut acls, CA_ROLE, ca_acl);
        table::add(&mut acls, CHANGE_KEEPER_ROLE, keeper_acl);
        move_to<ACLStore>(account, ACLStore{ 
            role_acls: acls, 
            license_black_list: table::new<vector<u8>, u8>() 
        });

        // init global config
        let config = CrossChainGlobalConfig{
            polyId: polyId,
            paused: false,
            ethToPolyTxHashIndex: 0,
            curBookKeepers: keepers,
            curEpochStartHeight: startHeight,
            ethToPolyTxHashMap: table::new<u128, vector<u8>>(),
            fromChainTxExist: table::new<u64, Table<vector<u8>, bool>>()
        };
        move_to<CrossChainGlobalConfig>(account, config);

        // init event store
        move_to<EventStore>(account, EventStore{
            init_book_keeper_event: account::new_event_handle<InitBookKeeperEvent>(account),
            change_book_keeper_event: account::new_event_handle<ChangeBookKeeperEvent>(account),
            cross_chain_event: account::new_event_handle<CrossChainEvent>(account),
            verify_header_and_execute_tx_event: account::new_event_handle<VerifyHeaderAndExecuteTxEvent>(account),
        });

        let event_store = borrow_global_mut<EventStore>(@poly);
        event::emit_event(
            &mut event_store.init_book_keeper_event,
            InitBookKeeperEvent{
                height: startHeight,
                keepers: keepers,
            },
        );
    }

    
    // set poly id
    public entry fun setPolyId(account: &signer, polyId: u64) acquires CrossChainGlobalConfig, ACLStore {
        assert!(hasRole(CHANGE_KEEPER_ROLE, signer::address_of(account)), ENOT_CHANGE_KEEPER_ROLE);
        putPolyId(polyId);
    }


    // change book keeper
    public entry fun changeBookKeeper(account: &signer, keepers: vector<vector<u8>>, startHeight: u64) acquires CrossChainGlobalConfig, EventStore, ACLStore {
        assert!(hasRole(CHANGE_KEEPER_ROLE, signer::address_of(account)), ENOT_CHANGE_KEEPER_ROLE);
        putCurBookKeepers(&keepers);
        putCurEpochStartHeight(startHeight);

        let event_store = borrow_global_mut<EventStore>(@poly);
        event::emit_event(
            &mut event_store.change_book_keeper_event,
            ChangeBookKeeperEvent{
                height: startHeight,
                keepers: keepers,
            },
        );
    }

    
    // cross chain
    public fun crossChain(account: &signer, license: &License, toChainId: u64, toContract: &vector<u8>, method: &vector<u8>, txData: &vector<u8>) acquires CrossChainGlobalConfig, ACLStore, EventStore {
        assert!(!paused(), EPAUSED);

        // check license
        let msg_sender = getLicenseId(license);
        assert!(!isBlackListedFrom(msg_sender), EBLACKLISTED_FROM);

        // pack args
        let tx_hash_index = getEthTxHashIndex();
        let param_tx_hash = bcs::to_bytes(&tx_hash_index);
        vector::reverse(&mut param_tx_hash);

        let cross_chain_id = b"AptosCrossChainManager";
        vector::append(&mut cross_chain_id, copy param_tx_hash);
        cross_chain_id = hash::sha2_256(cross_chain_id);

        let raw_param = zero_copy_sink::write_var_bytes(&param_tx_hash);
        vector::append(&mut raw_param, zero_copy_sink::write_var_bytes(&cross_chain_id));
        vector::append(&mut raw_param, zero_copy_sink::write_var_bytes(&msg_sender));
        vector::append(&mut raw_param, zero_copy_sink::write_u64(toChainId));
        vector::append(&mut raw_param, zero_copy_sink::write_var_bytes(toContract));
        vector::append(&mut raw_param, zero_copy_sink::write_var_bytes(method));
        vector::append(&mut raw_param, zero_copy_sink::write_var_bytes(txData));

        // mark
        putEthTxHash(&hash::sha2_256(copy raw_param));

        // emit event
        let event_store = borrow_global_mut<EventStore>(@poly);
        event::emit_event(
            &mut event_store.cross_chain_event,
            CrossChainEvent{
                sender: signer::address_of(account),
                tx_id: param_tx_hash,
                proxy_or_asset_contract: msg_sender,
                to_chain_id: toChainId,
                to_contract: *toContract,
                raw_data: raw_param,
            },
        );
    }


    // certificate
    struct Certificate has drop {
        from_contract: vector<u8>,
        from_chain_id: u64,
        target_license_id: vector<u8>,
        method: vector<u8>,
        args: vector<u8>
    }

    public fun read_certificate(certificate: &Certificate): (
        vector<u8>,
        u64,
        vector<u8>,
        vector<u8>,
        vector<u8>) 
    {
        return (
            certificate.from_contract,
            certificate.from_chain_id,
            certificate.target_license_id,
            certificate.method,
            certificate.args
        )
    }


    // verify header and execute tx
    public fun verifyHeaderAndExecuteTx(license: &License, proof: &vector<u8>, rawHeader: &vector<u8>, headerProof: &vector<u8>, curRawHeader: &vector<u8>, headerSig: &vector<u8>): Certificate acquires CrossChainGlobalConfig, ACLStore, EventStore {
        assert!(!paused(), EPAUSED);

        let (
            _,
            _,
            _,
            height,
            _,
            _,
            _,
            cross_states_root,
            _,
            _,
            _
        ) = cross_chain_utils::deserializeHeader(rawHeader);
        let keepers = getCurBookKeepers();
        let cur_epoch_start_height = getCurEpochStartHeight();
        let n = vector::length(&keepers);
        let threshold = n - ( n - 1) / 3;

        // verify header
        if (height >= cur_epoch_start_height) {
            assert!(cross_chain_utils::verifySig(rawHeader, headerSig, &keepers, threshold), EVERIFY_HEADER_FAILED);
        } else {
            assert!(cross_chain_utils::verifySig(curRawHeader, headerSig, &keepers, threshold), EVERIFY_HEADER_FAILED);
            let (
                _,
                _,
                _,
                _,
                _,
                _,
                _,
                _,
                blockRoot,
                _,
                _
            ) = cross_chain_utils::deserializeHeader(curRawHeader);
            let prove_value = cross_chain_utils::merkleProve(headerProof, &blockRoot);
            assert!(cross_chain_utils::getHeaderHash(rawHeader) == prove_value, EVERIFY_HEADER_PROOF_FAILED);
        };

        // verify cross state proof
        let to_merkle_value_bytes = cross_chain_utils::merkleProve(proof, &cross_states_root);
        let (
            poly_tx_hash,
            from_chain_id,
            source_tx_hash,
            _,
            from_contract,
            to_chain_id,
            to_contract,
            method,
            args
        ) = cross_chain_utils::deserializeMerkleValue(&to_merkle_value_bytes);

        // double-spending check/mark
        assert!(!checkIfFromChainTxExist(from_chain_id, &poly_tx_hash), EALREADY_EXECUTED);
        markFromChainTxExist(from_chain_id, &poly_tx_hash);

        // check to chain id
        assert!(to_chain_id == getPolyId(), ENOT_TARGET_CHAIN);

        // check verifier
        let msg_sender = getLicenseId(license);
        assert!(msg_sender == to_contract, EVERIFIER_NOT_RECEIVER);

        // check black list
        assert!(!isBlackListedTo(to_contract), EBLACKLISTED_TO);

        // emit event
        let event_store = borrow_global_mut<EventStore>(@poly);
        event::emit_event(
            &mut event_store.verify_header_and_execute_tx_event,
            VerifyHeaderAndExecuteTxEvent{
                from_chain_id: from_chain_id,
                to_contract: to_contract,
                cross_chain_tx_hash: poly_tx_hash,
                from_chain_tx_hash: source_tx_hash,
            },
        );

        // return a certificate to prove the execution is certified
        return Certificate{
            from_contract: from_contract,
            from_chain_id: from_chain_id,
            target_license_id: to_contract,
            method: method,
            args: args
        }
    }


    #[test_only] 
    fun test_setup(arg: &signer) acquires EventStore {
        0x1::aptos_account::create_account(@poly);
        let keepers = vector[
            x"2bed55e8c4d9cbc50657ff5909ee51dc394a92aad911c36bace83c4d63540794bc68a65f1a54ec4f14a630043090bc29ee9cddf90f3ecb86e0973ffff3fd4899",
            x"09c6475ce07577ab72a1f96c263e5030cb53a843b00ca1238a093d9dcb183e2fec837e621b7ec6db7658c9b9808da304aed599043de1b433d490ff74f577c53d",
            x"e68a6e54bdfa0af47bd18465f4352f5151dc729c61a7399909f1cd1c6d816c0241800e782bb05f6f803b9f958930ebcee0b67d3af27845b4fbfa09e926cf17ae",
            x"29e0d1c5b2ae838930ae1ad861ddd3d0745d1c7f142492cabd02b291d2c95c1dda6633dc7be5dd4f9597f32f1e45721959d0902a8e56a58b2db79ada7c3ce932",
        ];
        init(arg, keepers, 0, 1);
    }

    #[test(arg = @poly)]
    fun pause_test(arg: signer) acquires CrossChainGlobalConfig, EventStore, ACLStore {
        test_setup(&arg);
        assert!(!paused(), 0);
        pause(&arg);
        assert!(paused(), 0);
        unpause(&arg);
        assert!(!paused(), 0);
    }

    #[test(arg = @poly, invalid_signer = @0x2), expected_failure(abort_code = 10)]
    fun pause_failure_test(arg: signer, invalid_signer: signer) acquires CrossChainGlobalConfig, EventStore, ACLStore {
        test_setup(&arg);
        let addr = signer::address_of(&invalid_signer);
        0x1::aptos_account::create_account(addr);
        assert!(!paused(), 0);
        pause(&invalid_signer);
    }

    #[test(arg = @poly)]
    fun role_test(arg: signer) acquires EventStore, ACLStore  {
        test_setup(&arg);

        let role = 9u64;
        assert!(!hasRole(role, @0x2), 0);
        grantRole(&arg, role, @0x2);
        assert!(hasRole(role, @0x2), 0);
        revokeRole(&arg, role, @0x2);
        assert!(!hasRole(role, @0x2), 0);
    }

    #[test(arg = @poly)]
    fun license_test(arg: signer) acquires EventStore, ACLStore  {
        test_setup(&arg);

        let mod = x"9923848873";
        let license = issueLicense(&arg, @0x2, mod);
        let license_id = getLicenseId(&license);
        assert!(!isBlackListedFrom(license_id), 0);
        assert!(!isBlackListedTo(license_id), 0);

        setBlackList(&arg, license_id, 1);
        assert!(!isBlackListedFrom(license_id), 0);
        assert!(isBlackListedTo(license_id), 0);

        setBlackList(&arg, license_id, 2);
        assert!(isBlackListedFrom(license_id), 0);
        assert!(!isBlackListedTo(license_id), 0);

        setBlackList(&arg, license_id, 3);
        assert!(isBlackListedFrom(license_id), 0);
        assert!(isBlackListedTo(license_id), 0);
        destroyLicense(license);
    }

    #[test(arg = @poly)]
    fun mark_tx_exist_test(arg: signer) acquires CrossChainGlobalConfig, EventStore {
        test_setup(&arg);

        let chain = 10u64;
        let tx = x"93ab9323";
        assert!(!checkIfFromChainTxExist(chain, &tx), 0);
        markFromChainTxExist(chain, &tx);
        assert!(checkIfFromChainTxExist(chain, &tx), 0);
    }
}