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

pub struct NoStdChunker {
    chunk_buf: [u8; CHUNK_SIZE],
    chunk_len: usize,
    first_chunk: bool,
}

impl NoStdChunker {
    pub fn new() -> Self {
        Self {
            chunk_buf: [0; CHUNK_SIZE],
            chunk_len: 0,
            first_chunk: true,
        }
    }

    fn chunk(&self) -> &[u8] {
        &self.chunk_buf[..self.chunk_len]
    }
}

impl Chunker for NoStdChunker {
    fn feed<F>(&mut self, input: &[u8], job_callback: F) -> usize
    where
        F: FnOnce(&[u8], &Hash),
    {
        if input.is_empty() {
            return 0;
        }

        if self.chunk_len == CHUNK_SIZE {
            job_callback(self.chunk(), &hash::hash_chunk(self.chunk(), NotRoot));
            self.chunk_len = 0;
            self.first_chunk = false;
        }

        let want = CHUNK_SIZE - self.chunk_len;
        let take = cmp::min(want, input.len());
        self.chunk_buf[self.chunk_len..][..take].copy_from_slice(&input[..take]);
        self.chunk_len += take;
        take
    }

    fn finish<F>(&mut self, job_callback: F)
    where
        F: FnOnce(&[u8], &Hash, bool),
    {
        let finalization = if self.first_chunk {
            Root(self.chunk().len() as u64)
        } else {
            NotRoot
        };
        job_callback(
            self.chunk(),
            &hash::hash_chunk(self.chunk(), finalization),
            true,
        );
        self.chunk_len = 0;
        self.first_chunk = true;
    }
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

    pub fn new() -> Self {
        let mut free_jobs = VecDeque::new();
        free_jobs.push_back(Job::new());
        Self {
            free_jobs,
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
        // TODO: More than one chunk per job.
        let want = CHUNK_SIZE - self.free_jobs.front().unwrap().bytes.len();
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
    use super::*;

    // Put a 1 at the end to test resetting the first chunk flag.
    const CASES: &[usize] = &[0, 1, 10, 100, 1_000, 10_000, 100_000, 1];

    fn drive<T: Chunker>(chunker: &mut T, mut input: &[u8]) -> Vec<(Vec<u8>, Hash)> {
        let mut output = Vec::new();
        while !input.is_empty() {
            let used = chunker.feed(input, |bytes, hash| {
                output.push((bytes.to_vec(), *hash));
            });
            input = &input[used..];
        }
        loop {
            let mut last_job = false;
            chunker.finish(|bytes, hash, last| {
                output.push((bytes.to_vec(), *hash));
                last_job = last;
            });
            if last_job {
                break;
            }
        }
        output
    }

    fn expected_chunks(input: &[u8]) -> Vec<(Vec<u8>, Hash)> {
        if input.len() <= CHUNK_SIZE {
            vec![
                (
                    input.to_vec(),
                    hash::hash_chunk(input, Root(input.len() as u64)),
                ),
            ]
        } else {
            input
                .chunks(CHUNK_SIZE)
                .map(|chunk| (chunk.to_vec(), hash::hash_chunk(chunk, NotRoot)))
                .collect()
        }
    }

    #[test]
    fn test_parallel_chunker() {
        for &case in CASES.iter() {
            println!("case {}", case);
            let input = vec![0; case];
            let expected = expected_chunks(&input);
            let mut chunker = ParallelChunker::new();
            let found = drive(&mut chunker, &input);
            assert_eq!(expected, found);
        }
    }

    #[test]
    fn test_parallel_chunker_with_reuse() {
        let mut chunker = ParallelChunker::new();
        for &case in CASES.iter() {
            println!("case {}", case);
            let input = vec![0; case];
            let expected = expected_chunks(&input);
            let found = drive(&mut chunker, &input);
            assert_eq!(expected, found);
        }
    }

    #[test]
    fn test_nostd_chunker() {
        for &case in CASES.iter() {
            println!("case {}", case);
            let input = vec![0; case];
            let expected = expected_chunks(&input);
            let mut chunker = NoStdChunker::new();
            let found = drive(&mut chunker, &input);
            assert_eq!(expected, found);
        }
    }

    #[test]
    fn test_nostd_chunker_with_reuse() {
        let mut chunker = NoStdChunker::new();
        for &case in CASES.iter() {
            println!("case {}", case);
            let input = vec![0; case];
            let expected = expected_chunks(&input);
            let found = drive(&mut chunker, &input);
            assert_eq!(expected, found);
        }
    }
}
