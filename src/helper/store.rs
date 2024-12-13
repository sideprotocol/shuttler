use std::{marker::PhantomData, path::Path};

use serde::{Deserialize, Serialize};
use sled::Db;

pub trait Store<K, V> where K: AsRef<[u8]>, V: Serialize + for<'a> Deserialize<'a> {
    fn save(&self, key: &K, value: &V) -> bool;
    fn list(&self) -> Vec<V>;
    fn remove(&self, key: &K) -> bool;
    fn get(&self, key: &K) -> Option<V>;
    fn exists(&self, key: &K) -> bool;
}

pub fn new_store<K, V>(path: String) -> impl Store<K, V> where K: AsRef<[u8]>, V: Serialize + for<'a> Deserialize<'a>  {
    SledStore::<K, V>::new(path)
}

pub type DefaultStore<K, V> = SledStore<K, V>;

pub struct Value<T>(T);

pub struct SledStore<K, V> where K: AsRef<[u8]>, V: Serialize + for<'a> Deserialize<'a> {
    inner: Db,
    _pdk: PhantomData<K>,
    _pdv: PhantomData<V>
}

impl<K, V> SledStore<K, V> where K: AsRef<[u8]>, V: Serialize + for<'a> Deserialize<'a> {
    pub fn new(path: String) -> Self {
        let inner = sled::open(path).unwrap();
        Self {
            inner,
            _pdk: PhantomData,
            _pdv: PhantomData,
        }
    }
}

impl<K, V> Store<K, V> for SledStore<K, V> where K: AsRef<[u8]>, V: Serialize + for<'a> Deserialize<'a> {
    fn save(&self, key: &K, value: &V) -> bool {
        let value = serde_json::to_vec(value).unwrap();
        self.inner
            .insert(key, value)
            .is_ok()
    }

    fn list(&self) -> Vec<V> {
        self.inner
        .iter()
        .map(|r| {
            let (_k, v) = r.unwrap();
            serde_json::from_slice(&v).unwrap()
        })
        .collect()
    }

    fn remove(&self, key: &K) -> bool {
        self.inner.remove(key).is_ok()
    }

    fn get(&self, key: &K) -> Option<V> {
        match self.inner.get(key) {
            Ok(Some(v)) => Some(serde_json::from_slice(&v).unwrap()),
            _ => None,
        }
    }

    fn exists(&self, key: &K) -> bool {
        self.inner.contains_key(key).unwrap_or(false)
    }
}

