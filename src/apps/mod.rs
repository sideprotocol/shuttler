use libp2p::Swarm;
use tokio::time::Interval;

use crate::shuttler::ShuttlerBehaviour;

pub mod signer;
pub mod relayer;
pub mod oracle;

pub type SubscribeMessage = libp2p::gossipsub::Message;

pub trait App {
    fn on_message(&self, ctx: &mut Context, message: &SubscribeMessage);
    fn ticker(&self) -> impl std::future::Future<Output = Interval> + Send;
    fn on_tick(&self, ctx: &mut Context) -> impl std::future::Future<Output = ()> + Send;
}

pub struct Context {
    pub swarm: Swarm<ShuttlerBehaviour>
}