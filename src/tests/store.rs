use tempfile::TempDir;

use crate::helper::store::{DefaultStore, Store};

#[test]
fn test_store() {

    let testdir = TempDir::new().expect("Unable to create test directory!");
    let mut store: DefaultStore<String, String> = DefaultStore::new(testdir.path().join("test.db"));
    // let store2 = store.clone();
    store.save(&"key".to_string(), &"value".to_string());
}