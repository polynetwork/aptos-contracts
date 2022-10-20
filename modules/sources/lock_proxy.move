module poly_bridge::lock_proxy {
    use std::signer;
    use std::vector;
    use std::string;
    use aptos_std::event;
    use aptos_std::table::{Table, Self};
    use aptos_std::type_info::{TypeInfo, Self};
    use aptos_framework::coin::{Coin, Self}; 
    use aptos_framework::account;

    use poly::cross_chain_manager;
    use poly::zero_copy_sink;
    use poly::zero_copy_source;
    use poly::utils;

    const EINVALID_SIGNER: u64 = 1;
    const ENOT_OWNER: u64 = 2;
    const ETREASURY_ALREADY_EXIST: u64 = 3;
    const ETREASURY_NOT_EXIST: u64 = 4;
    const ELICENSE_ALREADY_EXIST: u64 = 5;
    const ELICENSE_NOT_EXIST: u64 = 6;
    const ETARGET_PROXY_NOT_BIND: u64 = 7;
    const ETARGET_ASSET_NOT_BIND: u64 = 8;
    const EINVALID_COINTYPE: u64 = 9;
    const EINVALID_FROM_CONTRACT: u64 = 10;
    const EINVALID_TARGET_LICENSE_ID: u64 = 11;
    const EINVALID_METHOD: u64 = 12;


    struct LockProxyStore has key, store {
        proxy_map: Table<u64, vector<u8>>,
        asset_map: Table<TypeInfo, Table<u64, vector<u8>>>,
        paused: bool,
        owner: address,
        bind_proxy_event: event::EventHandle<BindProxyEvent>,
        bind_asset_event: event::EventHandle<BindAssetEvent>,
        lock_event: event::EventHandle<LockEvent>,
        unlock_event: event::EventHandle<UnlockEvent>
    }

    struct Treasury<phantom CoinType> has key, store {
        coin: Coin<CoinType>
    }

    struct LicenseStore has key, store {
        license: cross_chain_manager::License
    }


    // events
    struct BindProxyEvent has store, drop {
        to_chain_id: u64,
        target_proxy_hash: vector<u8>
    }
    struct BindAssetEvent has store, drop {
        from_asset: TypeInfo,
        to_chain_id: u64,
        to_asset_hash: vector<u8>
    }
    struct UnlockEvent has store, drop {
        to_asset: TypeInfo,
        to_address: address,
        amount: u64
    }
    struct LockEvent has store, drop {
        from_asset: TypeInfo,
        from_address: address,
        to_chain_id: u64,
        to_asset_hash: vector<u8>,
        to_address: vector<u8>,
        amount: u64
    }


    // init
    public entry fun init(admin: &signer) {
        assert!(signer::address_of(admin) == @poly_bridge, EINVALID_SIGNER);

        move_to<LockProxyStore>(admin, LockProxyStore{
            proxy_map: table::new<u64, vector<u8>>(),
            asset_map: table::new<TypeInfo, Table<u64, vector<u8>>>(),
            paused: false,
            owner: signer::address_of(admin),
            bind_proxy_event: account::new_event_handle<BindProxyEvent>(admin),
            bind_asset_event: account::new_event_handle<BindAssetEvent>(admin),
            lock_event: account::new_event_handle<LockEvent>(admin),
            unlock_event: account::new_event_handle<UnlockEvent>(admin),
        });
    }


    // getter function
    public fun getTargetProxy(to_chain_id: u64): vector<u8> acquires LockProxyStore {
        let config_ref = borrow_global<LockProxyStore>(@poly_bridge);
        if (table::contains(&config_ref.proxy_map, to_chain_id)) {
            return *table::borrow(&config_ref.proxy_map, to_chain_id)
        } else {
            abort ETARGET_PROXY_NOT_BIND
        }
    }

    public fun getToAsset<CoinType>(to_chain_id: u64): vector<u8> acquires LockProxyStore {
        let config_ref = borrow_global<LockProxyStore>(@poly_bridge);
        let from_asset = type_info::type_of<Coin<CoinType>>();
        if (table::contains(&config_ref.asset_map, from_asset)) {
            let sub_table = table::borrow(&config_ref.asset_map, from_asset);
            if (table::contains(sub_table, to_chain_id)) {
                return *table::borrow(sub_table, to_chain_id)
            } else {
                abort ETARGET_ASSET_NOT_BIND
            }
        } else {
            abort ETARGET_ASSET_NOT_BIND
        }
    }

    public fun paused(): bool acquires LockProxyStore {
        let config_ref = borrow_global<LockProxyStore>(@poly_bridge);
        return config_ref.paused
    }

    public fun owner(): address acquires LockProxyStore {
        let config_ref = borrow_global<LockProxyStore>(@poly_bridge);
        return config_ref.owner
    }

    public fun getBalance<CoinType>(): u64 acquires Treasury {
        assert!(exists<Treasury<CoinType>>(@poly_bridge), ETREASURY_NOT_EXIST);
        let treasury_ref = borrow_global<Treasury<CoinType>>(@poly_bridge);
        return coin::value(&treasury_ref.coin)
    }


    // owner function
    fun onlyOwner(owner: &signer) acquires LockProxyStore {
        let config_ref = borrow_global<LockProxyStore>(@poly_bridge);
        assert!(signer::address_of(owner) == config_ref.owner, ENOT_OWNER);
    }

    public entry fun transferOwnerShip(owner: &signer, new_owner: address) acquires LockProxyStore {
        onlyOwner(owner);
        let config_ref = borrow_global_mut<LockProxyStore>(@poly_bridge);
        *&mut config_ref.owner = new_owner;
    }

    public entry fun pause(owner: &signer) acquires LockProxyStore {
        onlyOwner(owner);
        let config_ref = borrow_global_mut<LockProxyStore>(@poly_bridge);
        *&mut config_ref.paused = true;
    }

    public entry fun unpause(owner: &signer) acquires LockProxyStore {
        onlyOwner(owner);
        let config_ref = borrow_global_mut<LockProxyStore>(@poly_bridge);
        *&mut config_ref.paused = false;
    }

    public entry fun bindProxy(owner: &signer, to_chain_id: u64, target_proxy_hash: &vector<u8>) acquires LockProxyStore {
        onlyOwner(owner);
        let config_ref = borrow_global_mut<LockProxyStore>(@poly_bridge);
        table::upsert(&mut config_ref.proxy_map, to_chain_id, *target_proxy_hash);

        event::emit_event(
            &mut config_ref.bind_proxy_event,
            BindProxyEvent{
                to_chain_id: to_chain_id,
                target_proxy_hash: *target_proxy_hash,
            },
        );
    }

    public entry fun unbindProxy(owner: &signer, to_chain_id: u64) acquires LockProxyStore {
        onlyOwner(owner);
        let config_ref = borrow_global_mut<LockProxyStore>(@poly_bridge);
        if (table::contains(&config_ref.proxy_map, to_chain_id)) {
            table::remove(&mut config_ref.proxy_map, to_chain_id);
        } else {
            abort ETARGET_PROXY_NOT_BIND
        };

        event::emit_event(
            &mut config_ref.bind_proxy_event,
            BindProxyEvent{
                to_chain_id: to_chain_id,
                target_proxy_hash: vector::empty<u8>(),
            },
        );
    }

    public entry fun bindAsset<CoinType>(owner: &signer, to_chain_id: u64, to_asset_hash: &vector<u8>) acquires LockProxyStore {
        onlyOwner(owner);
        let from_asset = type_info::type_of<Coin<CoinType>>();
        let config_ref = borrow_global_mut<LockProxyStore>(@poly_bridge);
        if (table::contains(&config_ref.asset_map, from_asset)) {
            table::upsert(table::borrow_mut(&mut config_ref.asset_map, from_asset), to_chain_id, *to_asset_hash);
        } else {
            let subTable = table::new<u64, vector<u8>>();
            table::add(&mut subTable, to_chain_id, *to_asset_hash);
            table::add(&mut config_ref.asset_map, from_asset, subTable);
        };

        event::emit_event(
            &mut config_ref.bind_asset_event,
            BindAssetEvent{
                from_asset: from_asset,
                to_chain_id: to_chain_id,
                to_asset_hash: *to_asset_hash,
            },
        );
    }

    public entry fun unbindAsset<CoinType>(owner: &signer, to_chain_id: u64) acquires LockProxyStore {
        onlyOwner(owner);
        let from_asset = type_info::type_of<Coin<CoinType>>();
        let config_ref = borrow_global_mut<LockProxyStore>(@poly_bridge);
        if (table::contains(&config_ref.asset_map, from_asset)) {
            let sub_table = table::borrow_mut(&mut config_ref.asset_map, from_asset);
            if (table::contains(sub_table, to_chain_id)) {
                table::remove(sub_table, to_chain_id);
            } else {
                abort ETARGET_ASSET_NOT_BIND
            };
        } else {
            abort ETARGET_ASSET_NOT_BIND
        };

        event::emit_event(
            &mut config_ref.bind_asset_event,
            BindAssetEvent{
                from_asset: from_asset,
                to_chain_id: to_chain_id,
                to_asset_hash: vector::empty<u8>(),
            },
        );
    }


    // treasury function
    public entry fun initTreasury<CoinType>(admin: &signer) {
        assert!(signer::address_of(admin) == @poly_bridge, EINVALID_SIGNER);
        assert!(!exists<Treasury<CoinType>>(@poly_bridge), ETREASURY_ALREADY_EXIST);
        move_to(admin, Treasury<CoinType> {
            coin: coin::zero<CoinType>()
        });
    }

    public fun is_treasury_initialzed<CoinType>(): bool {
        exists<Treasury<CoinType>>(@poly_bridge)
    }

    public fun is_admin(account: address): bool {
        account == @poly_bridge
    }

    public fun deposit<CoinType>(fund: Coin<CoinType>) acquires Treasury {
        assert!(exists<Treasury<CoinType>>(@poly_bridge), ETREASURY_NOT_EXIST);
        let treasury_ref = borrow_global_mut<Treasury<CoinType>>(@poly_bridge);
        coin::merge<CoinType>(&mut treasury_ref.coin, fund);
    }

    fun withdraw<CoinType>(amount: u64): Coin<CoinType> acquires Treasury {
        assert!(exists<Treasury<CoinType>>(@poly_bridge), ETREASURY_NOT_EXIST);
        let treasury_ref = borrow_global_mut<Treasury<CoinType>>(@poly_bridge);
        return coin::extract<CoinType>(&mut treasury_ref.coin, amount)
    }


    // license function
    public fun initLicense(admin: &signer, license: cross_chain_manager::License) {
        assert!(signer::address_of(admin) == @poly_bridge, EINVALID_SIGNER);
        assert!(!exists<LicenseStore>(@poly_bridge), ELICENSE_ALREADY_EXIST);
        move_to(admin, LicenseStore {
            license: license
        });
    }

    public fun removeLicense(admin: &signer): cross_chain_manager::License acquires LicenseStore {
        assert!(signer::address_of(admin) == @poly_bridge, EINVALID_SIGNER);
        assert!(exists<LicenseStore>(@poly_bridge), ELICENSE_NOT_EXIST);
        let LicenseStore{ license: license } = move_from<LicenseStore>(@poly_bridge);
        return license
    }

    public fun getLicenseId(): vector<u8> acquires LicenseStore {
        assert!(exists<LicenseStore>(@poly_bridge), ELICENSE_NOT_EXIST);
        let license_store_ref = borrow_global<LicenseStore>(@poly_bridge);
        return cross_chain_manager::getLicenseId(&license_store_ref.license)
    }
    

    // lock
    public fun lock<CoinType>(account: &signer, fund: Coin<CoinType>, toChainId: u64, toAddress: &vector<u8>) acquires Treasury, LicenseStore, LockProxyStore {
        // lock fund
        let amount = coin::value(&fund);
        deposit(fund);
        
        // borrow license
        assert!(exists<LicenseStore>(@poly_bridge), ELICENSE_NOT_EXIST);
        let license_store_ref = borrow_global<LicenseStore>(@poly_bridge);
        let license_ref = &license_store_ref.license;

        // get target proxy/asset
        let to_proxy = getTargetProxy(toChainId);
        let to_asset = getToAsset<CoinType>(toChainId);

        // pack args
        let tx_data = serializeTxArgs(&to_asset, toAddress, amount);

        // cross chain
        cross_chain_manager::crossChain(account, license_ref, toChainId, &to_proxy, &b"unlock", &tx_data);

        // emit event 
        let config_ref = borrow_global_mut<LockProxyStore>(@poly_bridge);
        event::emit_event(
            &mut config_ref.lock_event,
            LockEvent{
                from_asset: type_info::type_of<Coin<CoinType>>(),
                from_address: signer::address_of(account),
                to_chain_id: toChainId,
                to_asset_hash: to_asset,
                to_address: *toAddress,
                amount: amount,
            },
        );
    }


    // unlock
    public fun unlock<CoinType>(certificate: cross_chain_manager::Certificate) acquires Treasury, LicenseStore, LockProxyStore {
        // read certificate
        let (
            from_contract,
            from_chain_id,
            target_license_id,
            method,
            args
        ) = cross_chain_manager::read_certificate(&certificate);

        // unpac args
        let (
            to_asset,
            to_address,
            amount
        ) = deserializeTxArgs(&args);

        // check
        assert!(*string::bytes(&type_info::type_name<Coin<CoinType>>()) == to_asset, EINVALID_COINTYPE);
        assert!(getTargetProxy(from_chain_id) == from_contract, EINVALID_FROM_CONTRACT);
        assert!(getLicenseId() == target_license_id, EINVALID_TARGET_LICENSE_ID);
        assert!(method == b"unlock", EINVALID_METHOD);

        // unlock fund
        let fund = withdraw<CoinType>(amount);
        coin::deposit(utils::to_address(to_address), fund);

        // emit event
        let config_ref = borrow_global_mut<LockProxyStore>(@poly_bridge);
        event::emit_event(
            &mut config_ref.unlock_event,
            UnlockEvent{
                to_asset: type_info::type_of<Coin<CoinType>>(),
                to_address: utils::to_address(to_address),
                amount: amount,
            },
        );
    }


    // codecs
    public fun serializeTxArgs(to_asset: &vector<u8>, to_address: &vector<u8>, amount: u64): vector<u8> {
        let buf = zero_copy_sink::write_var_bytes(to_asset);
        vector::append(&mut buf, zero_copy_sink::write_var_bytes(to_address));
        vector::append(&mut buf, zero_copy_sink::write_u256((0 as u128), (amount as u128)));
        return buf
    }

    public fun deserializeTxArgs(raw_data: &vector<u8>): (vector<u8>, vector<u8>, u64) {
        let offset = (0 as u64);
        let to_asset: vector<u8>;
        let to_address: vector<u8>;
        let amount: u128;
        (to_asset, offset) = zero_copy_source::next_var_bytes(raw_data, offset);
        (to_address, offset) = zero_copy_source::next_var_bytes(raw_data, offset);
        (_, amount, _) = zero_copy_source::next_u256(raw_data, offset);
        return (to_asset, to_address, (amount as u64))
    }
}