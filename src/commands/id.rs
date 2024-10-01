use crate::app::config::Config;
use crate::helper::encoding::from_base64;

use libp2p::identity::Keypair;

pub fn execute(home: &str) {
    let conf = Config::from_file(home).unwrap();

    if conf.p2p_keypair.is_empty() {
        println!("no key pair set in the config file");
        return;
    }

    let key_pair =
        Keypair::from_protobuf_encoding(from_base64(&conf.p2p_keypair).unwrap().as_slice())
            .unwrap();
    println!("local peer id: {}", key_pair.public().to_peer_id())
}
