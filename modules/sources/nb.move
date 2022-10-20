module poly::nb {
    use std::string;
    use std::error;
    use std::signer;

    use aptos_framework::coin::{Self, BurnCapability, FreezeCapability, MintCapability};

    const ENOT_ADMIN: u64 = 1;

    struct NBCoin has key {}

    struct NBCapStore has key {
        burn_cap: BurnCapability<NBCoin>,
        freeze_cap: FreezeCapability<NBCoin>,
        mint_cap: MintCapability<NBCoin>,
    }

    public entry fun initialize(admin: &signer) {
        only_admin(admin);

        let (burn_cap, freeze_cap, mint_cap) = coin::initialize<NBCoin>(
            admin,
            string::utf8(b"NobelBoss Coin"),
            string::utf8(b"NB"),
            6, /* decimals */
            true, /* monitor_supply */
        );

        move_to(admin, NBCapStore { burn_cap, freeze_cap, mint_cap });

        coin::destroy_burn_cap(burn_cap);
        coin::destroy_freeze_cap(freeze_cap);
        coin::destroy_mint_cap(mint_cap);
    }

    public entry fun register(account: &signer) {
        coin::register<NBCoin>(account);
    }

    public entry fun mint(
        admin: &signer,
        dst_addr: address,
        amount: u64,
    ) acquires NBCapStore {
        only_admin(admin);

        let mint_cap = &borrow_global<NBCapStore>(signer::address_of(admin)).mint_cap;
        let coins_minted = coin::mint<NBCoin>(amount, mint_cap);
        coin::deposit<NBCoin>(dst_addr, coins_minted);
    }

    public entry fun burn(
        admin: &signer,
        amount: u64,
    ) acquires NBCapStore {
        only_admin(admin);

        let admin_addr = signer::address_of(admin);
        let burn_cap = &borrow_global<NBCapStore>(admin_addr).burn_cap;
        coin::burn_from<NBCoin>(admin_addr, amount, burn_cap);
    }

    public entry fun freeze_coin_store(
        admin: &signer,
        freeze_addr: address,
    ) acquires NBCapStore {
        only_admin(admin);

        let freeze_cap = &borrow_global<NBCapStore>(signer::address_of(admin)).freeze_cap;
        coin::freeze_coin_store<NBCoin>(freeze_addr, freeze_cap);
    }

    public entry fun unfreeze_coin_store(
        admin: &signer,
        unfreeze_addr: address,
    ) acquires NBCapStore {
        only_admin(admin);

        let freeze_cap = &borrow_global<NBCapStore>(signer::address_of(admin)).freeze_cap;
        coin::unfreeze_coin_store<NBCoin>(unfreeze_addr, freeze_cap);
    }

    fun only_admin(account: &signer) {
        assert!(signer::address_of(account) == @poly, error::permission_denied(ENOT_ADMIN));
    }
}