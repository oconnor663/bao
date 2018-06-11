use rayon;
use std::cmp;
use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::mpsc;

use hash::{self, Finalization::{NotRoot, Root}, Hash, CHUNK_SIZE};

trait Chunker {
    /// Returns the number of input bytes consumed. If there is internal buffer
    /// space available, `job_callback` won't be called. If not, `feed` will
    /// wait on an existing job to free up its buffer space, and yield the
    /// result via `job_callback`.
    ///
    /// This function will never yield the final chunk; callers can rely on
    /// `finish` always yielding at least one more chunk. In particular,
    /// callers can roll up subtrees based on finished chunks, without worrying
    /// about whether the current topmost node might be the root.
    fn feed<F>(&mut self, input: &[u8], job_callback: F) -> usize
    where
        F: FnOnce(&[u8], &Hash);

    /// Runs the `job_callback` on exactly one finished job. If it was the
    /// final job, the boolean argument will be true. At that point, it's safe
    /// to reuse this chunker as though it's newly allocated.
    fn finish<F>(&mut self, job_callback: F)
    where
        F: FnOnce(&[u8], &Hash, bool);
}

// A reusable buffer for sending bytes to a worker thread to be hashed.
struct Job {
    bytes: Vec<u8>,
    hash: Hash,
    sender: Arc<mpsc::SyncSender<Job>>,
    receiver: Option<mpsc::Receiver<Job>>,
}

impl Job {
    fn new() -> Self {
        let (sender, receiver) = mpsc::sync_channel(1);
        Self {
            bytes: Vec::new(),
            hash: Hash::default(),
            sender: Arc::new(sender),
            receiver: Some(receiver),
        }
    }

    // Worker threads call this method.
    fn run(mut self) {
        self.hash = hash::hash_recurse(&self.bytes, NotRoot);
        let sender = self.sender.clone();
        sender.send(self).unwrap();
    }
}

// A collection of Job buffers waiting to be filled, and receiver handles for
// jobs in flight.
pub struct ParallelChunker {
    free_jobs: VecDeque<Job>,
    receivers: VecDeque<mpsc::Receiver<Job>>,
    first_job: bool,
}

impl ParallelChunker {
    const MAX_JOBS: usize = 8;
    const JOB_SIZE: usize = 8 * CHUNK_SIZE; // must be a power of 2

    pub fn new() -> Self {
        Self {
            free_jobs: VecDeque::new(),
            receivers: VecDeque::new(),
            first_job: true,
        }
    }

    fn start_job(&mut self) {
        let mut job = self.free_jobs.pop_front().unwrap();
        self.receivers.push_back(job.receiver.take().unwrap());
        rayon::spawn(|| job.run());
    }
}

impl Chunker for ParallelChunker {
    fn feed<F>(&mut self, input: &[u8], job_callback: F) -> usize
    where
        F: FnOnce(&[u8], &Hash),
    {
        // Don't do any work if there's no input. Otherwise we could
        // prematurely send the first block and wind up with the wrong
        // finalization. Also, callers rely on us
        if input.is_empty() {
            return 0;
        }

        // If the next job is ready to go, send it.
        if self.free_jobs.front().unwrap().bytes.len() == CHUNK_SIZE {
            self.start_job();
            self.first_job = false;
        }

        // If there aren't any jobs left in the queue, create one or wait on one.
        if self.free_jobs.is_empty() {
            if self.receivers.len() < Self::MAX_JOBS {
                self.free_jobs.push_back(Job::new());
            } else {
                let receiver = self.receivers.pop_front().unwrap();
                let mut job = receiver.recv().unwrap();
                // Give the caller the resuts of the finished job.
                job_callback(&job.bytes, &job.hash);
                // Clean it up and put it back in the queue for reuse.
                job.receiver = Some(receiver);
                job.bytes.clear();
                self.free_jobs.push_back(job);
            }
        }

        // Put as many bytes as we can into the next job.
        let want = Self::JOB_SIZE - self.free_jobs.front().unwrap().bytes.len();
        let take = cmp::min(want, input.len());
        self.free_jobs
            .front_mut()
            .unwrap()
            .bytes
            .extend_from_slice(&input[..take]);
        take
    }

    fn finish<F>(&mut self, job_callback: F)
    where
        F: FnOnce(&[u8], &Hash, bool),
    {
        // If we never submitted any jobs, just hash whatever bytes we have and
        // yield that one result. Note that this might be an empty chunk.
        if self.first_job {
            let job = self.free_jobs.front_mut().unwrap();
            let hash = hash::hash_recurse(&job.bytes, Root(job.bytes.len() as u64));
            job_callback(&job.bytes, &hash, true);
            job.bytes.clear();
            return;
        }

        // Otherwise, queue up the final job, if we haven't already.
        if !self.free_jobs.front().unwrap().bytes.is_empty() {
            self.start_job();
        }

        // Finally, yield jobs until there aren't any left. At that point,
        // prepare ourselves for reuse by resetting the first_job flag.
        let receiver = self.receivers.pop_front().unwrap();
        let mut job = receiver.recv().unwrap();
        job_callback(&job.bytes, &job.hash, self.receivers.is_empty());
        job.receiver = Some(receiver);
        job.bytes.clear();
        self.free_jobs.push_back(job);
        if self.receivers.is_empty() {
            self.first_job = true;
        }
    }
}

#[cfg(test)]
mod test {
    fn collect<T: Chunker>(chunker: &mut T, mut input: &[u8]) -> Vec<(Vec<u8>, Hash)> {
        unimplemented!()
    }
}
