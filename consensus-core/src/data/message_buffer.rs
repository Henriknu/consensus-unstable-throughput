use std::collections::{HashMap, VecDeque};

pub struct MessageBuffer<T> {
    pub epochs: HashMap<usize, VecDeque<T>>,
}

impl<T> MessageBuffer<T> {
    pub fn new() -> Self {
        Self {
            epochs: Default::default(),
        }
    }

    pub fn contains_epoch(&self, epoch: usize) -> bool {
        self.epochs.contains_key(&epoch)
    }

    pub fn put(&mut self, epoch: usize, message: T) {
        self.epochs.entry(epoch).or_default().push_back(message);
    }
}
