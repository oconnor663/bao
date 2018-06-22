extern crate rayon;

use std::collections::VecDeque;
use std::mem;
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::sync::Arc;

pub(crate) trait Runner {
    type Job;

    fn current(&mut self) -> &mut Self::Job;
    fn launch(&mut self) -> Option<&mut Self::Job>;
    fn finish(&mut self) -> Option<&mut Self::Job>;
}

pub(crate) trait Job: Send {
    fn new() -> Self;
    fn clear(&mut self);
    fn do_work(&mut self);
}

pub(crate) struct MultiThreadedRunner<T: 'static + Job> {
    current: JobWrapper<T>,
    should_clear: bool,
    receivers: VecDeque<Receiver<JobWrapper<T>>>,
    capacity: usize,
}

impl<T: Job> MultiThreadedRunner<T> {
    fn new() -> Self {
        Self {
            current: JobWrapper::new(),
            should_clear: false,
            receivers: VecDeque::new(),
            // TODO: tune this number
            capacity: 2 * rayon::current_num_threads(),
        }
    }
}

impl<T: Job> Runner for MultiThreadedRunner<T> {
    type Job = T;

    fn current(&mut self) -> &mut T {
        if self.should_clear {
            self.current.job.clear();
            self.should_clear = false;
        }
        &mut self.current.job
    }

    fn launch(&mut self) -> Option<&mut T> {
        let mut current;
        let finished;
        if self.receivers.len() < self.capacity {
            current = mem::replace(&mut self.current, JobWrapper::new());
            finished = None;
        } else {
            let receiver = self.receivers.pop_front().unwrap();
            let mut received = receiver.recv().unwrap();
            received.receiver = Some(receiver);
            current = mem::replace(&mut self.current, received);
            finished = Some(&mut *self.current.job);
            self.should_clear = true;
        }

        self.receivers.push_back(current.receiver.take().unwrap());
        rayon::spawn(move || {
            current.job.do_work();
            let sender = current.sender.clone();
            sender.send(current).unwrap();
        });

        finished
    }

    fn finish(&mut self) -> Option<&mut T> {
        self.receivers.pop_front().map(move |r| {
            self.current = r.recv().unwrap();
            &mut *self.current.job
        })
    }
}

struct JobWrapper<T: Job> {
    job: Box<T>,
    sender: Arc<SyncSender<JobWrapper<T>>>,
    receiver: Option<Receiver<JobWrapper<T>>>,
}

impl<T: Job> JobWrapper<T> {
    fn new() -> Self {
        let (sender, receiver) = mpsc::sync_channel(1);
        Self {
            job: Box::new(T::new()),
            sender: Arc::new(sender),
            receiver: Some(receiver),
        }
    }
}

pub(crate) struct SingleThreadedRunner<T: 'static + Job> {
    job: T,
    should_clear: bool,
}

impl<T: Job> SingleThreadedRunner<T> {
    fn new() -> Self {
        Self {
            job: T::new(),
            should_clear: false,
        }
    }
}

impl<T: Job> Runner for SingleThreadedRunner<T> {
    type Job = T;

    fn current(&mut self) -> &mut T {
        if self.should_clear {
            self.job.clear();
            self.should_clear = false;
        }
        &mut self.job
    }

    fn launch(&mut self) -> Option<&mut T> {
        self.job.do_work();
        self.should_clear = true;
        Some(&mut self.job)
    }

    fn finish(&mut self) -> Option<&mut T> {
        None
    }
}

#[cfg(test)]
mod test {
    use super::*;

    struct DoublerJob {
        x: i32,
    }

    impl Job for DoublerJob {
        fn new() -> Self {
            Self { x: 0 }
        }

        fn clear(&mut self) {}

        fn do_work(&mut self) {
            self.x *= 2;
        }
    }

    #[test]
    fn test_multi_runner() {
        let mut runner: MultiThreadedRunner<DoublerJob> = MultiThreadedRunner::new();
        let mut total = 0;
        for x in 1..=100 {
            runner.current().x = x;
            if let Some(finished) = runner.launch() {
                total += finished.x;
            }
        }
        while let Some(finished) = runner.finish() {
            total += finished.x;
        }
        assert_eq!(10100, total);
    }

    #[test]
    fn test_single_runner() {
        let mut runner: SingleThreadedRunner<DoublerJob> = SingleThreadedRunner::new();
        let mut total = 0;
        for x in 1..=100 {
            runner.current().x = x;
            if let Some(finished) = runner.launch() {
                total += finished.x;
            }
        }
        while let Some(finished) = runner.finish() {
            total += finished.x;
        }
        assert_eq!(10100, total);
    }
}
