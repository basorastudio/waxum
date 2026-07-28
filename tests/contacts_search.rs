//! Regression test for contacts search LIKE-escaping (security hardening
//! pass): a search query containing literal `%`/`_` must not act as a SQL
//! wildcard, and normal substring search must keep matching. Also guards
//! against the MySQL-vs-SQLite `ESCAPE` clause dialect trap directly (see
//! `db::messages::like_query`'s doc comment) by exercising the actual SQL
//! text against a real SQLite connection rather than just checking it
//! compiles.

use tempfile::TempDir;

use waxum::db::contacts::{ContactStore, ContactUpsert};
use waxum::db::schema;
use waxum::db::session::{DbPool, SessionManager};
use waxum::db::sqlite_raw;

/// Fresh SQLite DB in its own temp dir, with a `s1` session row seeded so
/// contact inserts satisfy the `contacts.session_id` foreign key.
async fn setup() -> (TempDir, DbPool) {
    let tmp = TempDir::new().expect("tempdir");
    let db_path = tmp.path().join("waxum.db");
    let sqlite = sqlite_raw::open(db_path.to_str().unwrap()).expect("open sqlite");
    let pool = DbPool::SQLite(sqlite);
    schema::init_schema(&pool).await.expect("init schema");

    let manager = SessionManager::new(pool.clone());
    manager
        .create_session("s1", None, tmp.path().to_str().unwrap())
        .await
        .expect("seed session");

    (tmp, pool)
}

/// The query contains `%`, which -- unescaped -- would match any character
/// sequence between "100" and "Fresh", matching both contacts below.
/// Escaped, it must match only the one whose name literally contains "100%".
#[tokio::test]
async fn literal_percent_in_query_is_not_a_wildcard() {
    let (_tmp, pool) = setup().await;
    let store = ContactStore::new(&pool);

    store
        .upsert(&ContactUpsert {
            session_id: "s1",
            jid: "111@s.whatsapp.net",
            phone: Some("111"),
            full_name: Some("100% Fresh Produce"),
            source: "manual",
            ..Default::default()
        })
        .await
        .expect("upsert 1");
    store
        .upsert(&ContactUpsert {
            session_id: "s1",
            jid: "222@s.whatsapp.net",
            phone: Some("222"),
            full_name: Some("100 Percent Fresh"),
            source: "manual",
            ..Default::default()
        })
        .await
        .expect("upsert 2");

    let results = store
        .list("s1", Some("100% Fresh"), 20, 0)
        .await
        .expect("search");
    assert_eq!(
        results.len(),
        1,
        "escaped '%' must match literally, not as a wildcard: {results:?}"
    );
    assert_eq!(results[0].jid, "111@s.whatsapp.net");
}

#[tokio::test]
async fn ordinary_substring_search_still_matches() {
    let (_tmp, pool) = setup().await;
    let store = ContactStore::new(&pool);

    store
        .upsert(&ContactUpsert {
            session_id: "s1",
            jid: "333@s.whatsapp.net",
            phone: Some("333"),
            full_name: Some("Budi Santoso"),
            source: "manual",
            ..Default::default()
        })
        .await
        .expect("upsert");

    let results = store
        .list("s1", Some("Santoso"), 20, 0)
        .await
        .expect("search");
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].jid, "333@s.whatsapp.net");

    let no_match = store
        .list("s1", Some("nonexistent"), 20, 0)
        .await
        .expect("search");
    assert!(no_match.is_empty());
}
