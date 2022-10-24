module poly::tools {
    use poly::cross_chain_manager;
    use poly_bridge::lock_proxy;
    use poly_bridge::wrapper_v1;

    use std::vector;
    use std::signer;

    // mainnet
    public entry fun init_as_mainnet(account: &signer) {
        init_mainnet_ccm(account);
        wrapper_v1::init(account);
        lock_proxy::init(account);
        issue_license_to_lock_proxy(account, signer::address_of(account));
    }

    public entry fun init_mainnet_ccm(account: &signer) {
        let polyId: u64 = 41;
        let startHeight: u64 = 0;
        let keepers: vector<vector<u8>> = vector::empty<vector<u8>>();
        vector::push_back(&mut keepers, x"2bed55e8c4d9cbc50657ff5909ee51dc394a92aad911c36bace83c4d63540794bc68a65f1a54ec4f14a630043090bc29ee9cddf90f3ecb86e0973ffff3fd4899");
        vector::push_back(&mut keepers, x"09c6475ce07577ab72a1f96c263e5030cb53a843b00ca1238a093d9dcb183e2fec837e621b7ec6db7658c9b9808da304aed599043de1b433d490ff74f577c53d");
        vector::push_back(&mut keepers, x"e68a6e54bdfa0af47bd18465f4352f5151dc729c61a7399909f1cd1c6d816c0241800e782bb05f6f803b9f958930ebcee0b67d3af27845b4fbfa09e926cf17ae");
        vector::push_back(&mut keepers, x"29e0d1c5b2ae838930ae1ad861ddd3d0745d1c7f142492cabd02b291d2c95c1dda6633dc7be5dd4f9597f32f1e45721959d0902a8e56a58b2db79ada7c3ce932");
        cross_chain_manager::init(account, keepers, startHeight, polyId);
    }

    public entry fun issue_license_to_lock_proxy(account: &signer, bridge_addr: address) {
        let license = cross_chain_manager::issueLicense(account, bridge_addr, b"lock_proxy");
        lock_proxy::receiveLicense(license);
    }

    // testnet
    public entry fun init_as_testnet(account: &signer) {
        init_testnet_ccm(account);
        wrapper_v1::init(account);
        lock_proxy::init(account);
        issue_license_to_lock_proxy(account, signer::address_of(account));
    }

    public entry fun init_testnet_ccm(account: &signer) {
        let polyId: u64 = 998;
        let startHeight: u64 = 0;
        let keepers: vector<vector<u8>> = vector::empty<vector<u8>>();
        vector::push_back(&mut keepers, x"2092e34e0176dccf8abb496b833d591d25533469b3caf0e279b9742955dd8fc3899a042cd338e82698b5284720f85b309f2b711c05cb37836488371741168da6");
        vector::push_back(&mut keepers, x"696c0cbe74f01ee85e3c0ebe4ebdc5bea404f199d0262f1941fd39ff0d100257a2f2a11aaf2f0baccf6c9e30aa3b204bd4b935f3c1bb5b20349c7afd35565f2e");
        vector::push_back(&mut keepers, x"7bd771e68adb88398282e21a8b03c12f64c2351ea49a2ba06a0327c83b239ca9420cf3852f7991d2a53afd008d1f6c356294b83aeeb4aad769f8c95ffeb4d5ac");
        vector::push_back(&mut keepers, x"8247efcfeae0fdf760685d1ac1c083be3ff5e9a4a548bc3a2e98f0434f092483760cb1d3138a9beadf9f784d60604f37f1a51464ba228ec44f89879df1c10e07");
        vector::push_back(&mut keepers, x"a4f44dd65cbcc52b1d1ac51747378a7f84753b5f7bf2760ca21390ced6b172bbf4d03e2cf4e0e79e46f7a757058d240e542853341e88feb1610ff03ba785cfc1");
        vector::push_back(&mut keepers, x"d0d0e883c73d8256cf4314822ddd973c0179b73d8ed3df85aad38d36a8b2b0c7696f0c66330d243b1bc7bc8d05e694b4d642ac68f741d2b7f6ea4037ef46b992");
        vector::push_back(&mut keepers, x"ef44beba84422bd76a599531c9fe50969a929a0fee35df66690f370ce19fa8c00ed4b649691d116b7deeb79b714156d18981916e58ae40c0ebacbf3bd0b87877");
        cross_chain_manager::init(account, keepers, startHeight, polyId);
    }
}