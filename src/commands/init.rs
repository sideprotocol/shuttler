use crate::config;

use bitcoin::Network;

pub fn execute(home: &str, port : u32, network: Network) {
    println!("Initialize Shuttler Home: {}", home);
    // config::update_app_home(&cli.home);
    config::Config::default(home, port, network).save().unwrap();
}