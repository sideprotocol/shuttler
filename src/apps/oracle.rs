use tokio::time::Instant;

use crate::config::Config;

use super::{App, Context, SubscribeMessage};


#[derive(Debug)]
pub struct Oracle {
    config: Config,
}

impl Oracle {
    pub fn new(conf: Config, enabled: bool) -> Self {
        Self {
            config: conf,
        }
    }
    pub fn config(&self) -> &Config {
        &self.config
    }
}

impl App for Oracle {
    fn on_message(&self, _ctx: &mut Context, _message: &SubscribeMessage) {
        todo!()
    }

    fn enabled(&self) -> bool {
        false
    }

    async fn tick(&mut self) -> Instant {
        todo!()
    }

    async fn on_tick(&self, _ctx: &mut Context) {
        todo!()
    }
}
