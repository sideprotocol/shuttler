
pub mod tss_tasks;
pub mod relayer_tasks;

// pub async fn run_tick_tests() {
//     // this is to ensure that each node fetches tasks at the same time    
//     let d = 6 as u64;
//     let start = Instant::now() + (Duration::from_secs(d) - Duration::from_secs(now() % d));
//     let mut interval_relayer = tokio::time::interval_at(start, Duration::from_secs(d));
//     let mut interval_signer = tokio::time::interval_at(start, Duration::from_secs(d));


//     let seed = Utc::now().minute() as u64;
//     let mut rng = ChaCha8Rng::seed_from_u64(seed );
//     // test::run_tick_tests();
//     // cosmrs::run_tick_tests();
//     loop {
//         select!{
//             _ = interval_relayer.tick() => {
//                 relayer_tasks::start_relayer_tasks(&shuttler, &mut rng).await;
//             },
//             _ = interval_signer.tick() => {
//                 tss_tasks::tss_tasks_fetcher(&mut swarm, &shuttler).await;
//             }
//         }
//     }
// }