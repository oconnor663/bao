extern crate bao;
extern crate rand;

use rand::Rng;
use std::collections::HashMap;
use std::io::prelude::*;
use std::time::{Duration, Instant};

const INPUT_SIZE: usize = 100_000_000;
const RUNS: usize = 10;
const SLEEP_MS: u64 = 0;

const JOB_SIZES: &[usize] = &[
    1 << 12,
    1 << 13,
    1 << 14,
    1 << 15,
    1 << 16,
    1 << 17,
    1 << 18,
];

const JOBS_MAXES: &[usize] = &[12, 16, 32, 64, 128];

fn secs_float(time: Duration) -> f64 {
    time.as_secs() as f64 + time.subsec_nanos() as f64 / 1_000_000_000f64
}

fn print_run(run: Run, time: f64, msg: &str) {
    let gigs_rate: f64 = INPUT_SIZE as f64 / 1_000_000_000f64 / time;
    println!(
        "time {:.6}s rate {:.6} GB/s job_size {} max_jobs {} {}",
        time, gigs_rate, run.job_size, run.max_jobs, msg
    );
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct Run {
    job_size: usize,
    max_jobs: usize,
}

fn shuffled_runs() -> Vec<Run> {
    let mut ret = Vec::new();
    for &job_size in JOB_SIZES {
        for &max_jobs in JOBS_MAXES {
            for _ in 0..RUNS {
                ret.push(Run { job_size, max_jobs });
            }
        }
    }
    rand::thread_rng().shuffle(&mut ret);
    ret
}

fn main() {
    let input = vec![0; INPUT_SIZE];
    // Spin things up with one hash run.
    bao::hash::hash(&input);

    let mut run_times = HashMap::<Run, Vec<f64>>::new();
    for run in shuffled_runs() {
        let start = Instant::now();
        let mut writer = bao::hash::Writer::new_benchmarking(run.job_size, run.max_jobs);
        writer.write_all(&input).unwrap();
        writer.finish();
        let time = secs_float(Instant::now() - start);
        print_run(run, time, "");
        run_times.entry(run).or_insert(Vec::new()).push(time);
        std::thread::sleep(std::time::Duration::from_millis(SLEEP_MS));
    }

    let mut averages = Vec::new();
    for (run, times) in run_times {
        let average = times.iter().sum::<f64>() / times.len() as f64;
        averages.push((run, average));
    }
    averages.sort_by(|a, b| (-a.1).partial_cmp(&(-b.1)).unwrap());

    println!("=== averages ===");
    for (run, time) in averages {
        print_run(run, time, "");
    }
}
