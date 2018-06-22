extern crate rayon;

use std::collections::VecDeque;
use std::mem;
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::sync::Arc;

pub(crate) trait Runner {
    type Job;

    fn current(&mut self) -> &mut Self::Job;
    fn finished(&mut self) -> Option<&mut Self::Job>;

    fn launch(&mut self) -> Option<&mut Self::Job>;
    fn wait(&mut self) -> Option<&mut Self::Job>;
}

pub(crate) trait Job: Send {
    fn new() -> Self;
    fn clear(&mut self);
    fn do_work(&mut self);
}

pub(crate) struct MultiThreadedRunner<T: 'static + Job> {
    current_or_finished: JobWrapper<T>,
    current_is_finished: bool,
    receivers: VecDeque<Receiver<JobWrapper<T>>>,
    capacity: usize,
}

impl<T: Job> MultiThreadedRunner<T> {
    fn new() -> Self {
        Self {
            current_or_finished: JobWrapper::new(),
            current_is_finished: false,
            receivers: VecDeque::new(),
            // TODO: tune this number
            capacity: 2 * rayon::current_num_threads(),
        }
    }
}

impl<T: Job> Runner for MultiThreadedRunner<T> {
    type Job = T;

    fn current(&mut self) -> &mut T {
        if self.current_is_finished {
            self.current_or_finished.job.clear();
            self.current_is_finished = false;
        }
        &mut self.current_or_finished.job
    }

    fn finished(&mut self) -> Option<&mut T> {
        if self.current_is_finished {
            Some(&mut *self.current_or_finished.job)
        } else {
            None
        }
    }

    fn launch(&mut self) -> Option<&mut T> {
        assert!(
            !self.current_is_finished,
            "trying to launch without using current()"
        );
        let mut current;
        if self.receivers.len() < self.capacity {
            current = mem::replace(&mut self.current_or_finished, JobWrapper::new());
        } else {
            let receiver = self.receivers.pop_front().unwrap();
            let mut received = receiver.recv().unwrap();
            received.receiver = Some(receiver);
            current = mem::replace(&mut self.current_or_finished, received);
            self.current_is_finished = true;
        }

        self.receivers.push_back(current.receiver.take().unwrap());
        rayon::spawn(move || {
            current.job.do_work();
            let sender = current.sender.clone();
            sender.send(current).unwrap();
        });

        self.finished()
    }

    fn wait(&mut self) -> Option<&mut T> {
        self.receivers.pop_front().map(move |r| {
            self.current_or_finished = r.recv().unwrap();
            self.current_is_finished = true;
            &mut *self.current_or_finished.job
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
    job_is_finished: bool,
}

impl<T: Job> SingleThreadedRunner<T> {
    fn new() -> Self {
        Self {
            job: T::new(),
            job_is_finished: false,
        }
    }
}

impl<T: Job> Runner for SingleThreadedRunner<T> {
    type Job = T;

    fn current(&mut self) -> &mut T {
        if self.job_is_finished {
            self.job.clear();
            self.job_is_finished = false;
        }
        &mut self.job
    }

    fn finished(&mut self) -> Option<&mut T> {
        if self.job_is_finished {
            Some(&mut self.job)
        } else {
            None
        }
    }

    fn launch(&mut self) -> Option<&mut T> {
        self.job.do_work();
        self.job_is_finished = true;
        self.finished()
    }

    fn wait(&mut self) -> Option<&mut T> {
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

        fn clear(&mut self) {
            self.x = 0;
        }

        fn do_work(&mut self) {
            self.x *= 2;
        }
    }

    fn test_runner<T>(mut runner: T)
    where
        T: Runner<Job = DoublerJob>,
    {
        let mut total = 0;
        for x in 1..=100 {
            runner.current().x = x;
            assert!(runner.finished().is_none());
            if let Some(finished) = runner.launch() {
                total += finished.x;
            }
        }
        while let Some(finished) = runner.wait() {
            total += finished.x;
        }
        assert!(runner.finished().is_some());
        assert_eq!(10100, total);
    }

    #[test]
    fn test_multi_runner() {
        test_runner(MultiThreadedRunner::new());
    }

    #[test]
    fn test_single_runner() {
        test_runner(SingleThreadedRunner::new());
    }
}
