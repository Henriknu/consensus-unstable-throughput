use std::collections::{HashMap, VecDeque};

#[derive(Debug, Clone, Default)]
pub struct MessageBuffer<T: Default> {
    pub epochs: HashMap<usize, VecDeque<T>>,
}

impl<T: Default> MessageBuffer<T> {
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

    pub fn clear(&mut self, epoch: usize) {
        self.epochs.remove(&epoch);
    }
}
