//! `moli-os backup <dir>` and `moli-os restore <dir>`: the house's persistent
//! configuration and history, in one folder (inventory: docs/components/exploitation.md).
//!
//! - SQLite databases are copied with `VACUUM INTO`: a consistent snapshot,
//!   safe while Moli runs (WAL), compact, a standalone file.
//! - Small files are copied as they are (`secrets.enc` stays encrypted: the
//!   master key lives in a secrets manager, never in a backup).
//! - The house plan's images (`plan/`) go along with `plan.json`.
//! - `manifest.json` says when, which version, and each file's size.
//!
//! Restoring is for a stopped Moli and never overwrites without `--force`.
//! Every file is checked against the manifest before anything is written:
//! a damaged backup restores nothing rather than half of the house.

use std::path::Path;

use anyhow::{Context as _, bail};

/// SQLite databases: copied through SQLite itself.
const DATABASES: [&str; 2] = ["history.db", "energy.db"];
/// Persistent files; missing ones are skipped. Keep the documented inventory in sync.
const FILES: [&str; 18] = [
    "moli.toml",
    "settings.json",
    "people.json",
    "assistant.json",
    "plan.json",
    "phones.json",
    "secrets.enc",
    "labels.toml",
    "home.json",
    "tuya.json",
    "automations.json",
    "automation-runs.jsonl",
    "journal.jsonl",
    "journal.jsonl.1",
    "state.json",
    "trusted-profiles.toml",
    "perf.jsonl",
    "bench.json",
];

pub fn backup(data_dir: &Path, dir: &Path) -> anyhow::Result<()> {
    if dir.exists() && std::fs::read_dir(dir)?.next().is_some() {
        bail!(
            "{} is not empty: a backup goes into a new folder",
            dir.display()
        );
    }
    std::fs::create_dir_all(dir).with_context(|| format!("cannot create {}", dir.display()))?;
    let mut files = serde_json::Map::new();
    for name in DATABASES {
        let source = data_dir.join(name);
        if !source.exists() {
            continue;
        }
        let target = dir.join(name);
        let db = rusqlite::Connection::open_with_flags(
            &source,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .with_context(|| format!("cannot open {name}"))?;
        db.execute("VACUUM INTO ?1", [target.to_string_lossy().as_ref()])
            .with_context(|| format!("cannot snapshot {name}"))?;
        files.insert(name.into(), std::fs::metadata(&target)?.len().into());
    }
    for name in FILES {
        let source = data_dir.join(name);
        if !source.exists() {
            continue;
        }
        let bytes = std::fs::copy(&source, dir.join(name))
            .with_context(|| format!("cannot copy {name}"))?;
        files.insert(name.into(), bytes.into());
    }
    if let Ok(entries) = std::fs::read_dir(data_dir.join("plan")) {
        std::fs::create_dir_all(dir.join("plan"))?;
        for entry in entries.filter_map(Result::ok) {
            let Some(name) = entry
                .file_name()
                .to_str()
                .filter(|n| moli_api::plan_image_name_ok(n))
                .map(str::to_owned)
            else {
                continue;
            };
            let bytes = std::fs::copy(entry.path(), dir.join("plan").join(&name))
                .with_context(|| format!("cannot copy plan/{name}"))?;
            files.insert(format!("plan/{name}"), bytes.into());
        }
    }
    let manifest = serde_json::json!({
        "moli_os": env!("CARGO_PKG_VERSION"),
        "taken_ms": moli_core::now_ms(),
        "files": files,
    });
    std::fs::write(
        dir.join("manifest.json"),
        serde_json::to_string_pretty(&manifest)? + "\n",
    )?;
    println!(
        "backup: {} files in {} (secrets stay encrypted; the master key is not in it)",
        files.len(),
        dir.display()
    );
    Ok(())
}

pub fn restore(data_dir: &Path, dir: &Path, force: bool) -> anyhow::Result<()> {
    let manifest: serde_json::Value = serde_json::from_slice(
        &std::fs::read(dir.join("manifest.json"))
            .with_context(|| format!("{} has no manifest.json: not a backup", dir.display()))?,
    )?;
    let listed = manifest["files"]
        .as_object()
        .context("manifest without files")?;
    let names: Vec<String> = listed.keys().cloned().collect();
    // Only names this program writes: a manifest never chooses a path.
    if let Some(odd) = names.iter().find(|n| !known_name(n)) {
        bail!("unexpected file in the manifest: {odd:?}");
    }
    // The whole backup is checked before the first byte is written.
    for name in &names {
        let expected = listed[name.as_str()].as_u64();
        let found = std::fs::metadata(dir.join(name)).map(|m| m.len()).ok();
        if expected.is_none() || found != expected {
            bail!(
                "{name}: {} bytes in the backup, {} in its manifest: damaged backup, nothing restored",
                found.map_or_else(|| "no".to_owned(), |n| n.to_string()),
                expected.map_or_else(|| "?".to_owned(), |n| n.to_string()),
            );
        }
    }
    let existing: Vec<&String> = names.iter().filter(|n| data_dir.join(n).exists()).collect();
    if !existing.is_empty() && !force {
        bail!(
            "{} already holds {} of these files: stop moli-os, then restore with --force",
            data_dir.display(),
            existing.len()
        );
    }
    std::fs::create_dir_all(data_dir)?;
    if names.iter().any(|n| n.starts_with("plan/")) {
        std::fs::create_dir_all(data_dir.join("plan"))?;
    }
    for name in &names {
        let target = data_dir.join(name);
        // A database restored next to a stale WAL would replay it.
        if DATABASES.contains(&name.as_str()) {
            for suffix in ["-wal", "-shm"] {
                let _ = std::fs::remove_file(data_dir.join(format!("{name}{suffix}")));
            }
        }
        std::fs::copy(dir.join(name), &target).with_context(|| format!("cannot restore {name}"))?;
    }
    println!(
        "restored {} files into {} (taken {} ms since the epoch)",
        names.len(),
        data_dir.display(),
        manifest["taken_ms"]
    );
    Ok(())
}

fn known_name(name: &str) -> bool {
    DATABASES.contains(&name)
        || FILES.contains(&name)
        || name
            .strip_prefix("plan/")
            .is_some_and(moli_api::plan_image_name_ok)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn household_files() -> [(&'static str, serde_json::Value); 3] {
        use serde_json::json;

        [
            (
                "people.json",
                json!({
                    "people": [
                        {"id": "owner", "name": "Owner", "role": "owner",
                         "emails": ["user@example.com"]},
                        {"id": "guest", "name": "Guest", "role": "guest",
                         "rooms": ["Salon"], "expires": 4_102_444_800_000_u64}
                    ],
                    "zones": [{"id": "maison", "name": "Maison", "latitude": 0.0,
                               "longitude": 0.0, "radius": 100.0}],
                    "invites": [{"code_hmac": "00".repeat(32), "person": "guest",
                                 "expires": 4_102_444_800_000_u64}]
                }),
            ),
            ("settings.json", json!({"language": "en"})),
            (
                "assistant.json",
                json!({"voice": "nova", "style": "doux", "pace": "rapide"}),
            ),
        ]
    }

    #[tokio::test]
    async fn a_backup_preserves_people_and_preferences() {
        let base = std::env::temp_dir().join(format!("moli-backup-people-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let (data, saved, fresh) = (base.join("data"), base.join("saved"), base.join("fresh"));
        std::fs::create_dir_all(&data).unwrap();
        for (name, value) in household_files() {
            std::fs::write(data.join(name), serde_json::to_vec(&value).unwrap()).unwrap();
        }
        // This marker is deliberately not a key: no key generation or real secrets here.
        std::fs::write(data.join("master.key"), b"excluded marker").unwrap();

        backup(&data, &saved).unwrap();
        let manifest: serde_json::Value =
            serde_json::from_slice(&std::fs::read(saved.join("manifest.json")).unwrap()).unwrap();
        for (name, _) in household_files() {
            assert_eq!(
                manifest["files"][name].as_u64(),
                Some(std::fs::metadata(data.join(name)).unwrap().len()),
                "{name} must be included in the manifest"
            );
        }
        assert!(manifest["files"].get("master.key").is_none());
        assert!(!saved.join("master.key").exists());

        restore(&fresh, &saved, false).unwrap();
        for (name, _) in household_files() {
            assert_eq!(
                std::fs::read(fresh.join(name)).unwrap(),
                std::fs::read(data.join(name)).unwrap(),
                "{name} must survive a restore unchanged"
            );
            let occupied = base.join(format!("occupied-{name}"));
            std::fs::create_dir_all(&occupied).unwrap();
            std::fs::write(occupied.join(name), b"existing settings").unwrap();
            assert!(restore(&occupied, &saved, false).is_err());
            assert_eq!(std::fs::read_dir(&occupied).unwrap().count(), 1);
            assert_eq!(
                std::fs::read(occupied.join(name)).unwrap(),
                b"existing settings"
            );
            restore(&occupied, &saved, true).unwrap();
            assert_eq!(
                std::fs::read(occupied.join(name)).unwrap(),
                std::fs::read(data.join(name)).unwrap()
            );
        }
        assert!(!fresh.join("master.key").exists());
        assert_eq!(
            std::fs::read(data.join("master.key")).unwrap(),
            b"excluded marker"
        );
        assert_reloaded_household(&fresh).await;
        std::fs::remove_dir_all(base).unwrap();
    }

    /// Open the restored files through the same readers as startup, without any drivers.
    async fn assert_reloaded_household(data: &Path) {
        use moli_runtime::{Hub, HubOptions};
        use tokio_util::sync::CancellationToken;

        assert_eq!(moli_api::settings::language(data).as_deref(), Some("en"));
        let hub = Hub::new(HubOptions::default()).unwrap();
        let assistant = moli_assistant::Assistant::new(
            hub.clone(),
            None,
            None,
            None,
            moli_assistant::Config::default(),
        )
        .unwrap();
        assistant.load_voice_prefs(data.join("assistant.json"));
        let settings = assistant.settings();
        for key in ["voice", "style", "pace"] {
            assert_eq!(settings[key], household_files()[2].1[key]);
        }

        let options = moli_api::Options {
            household: Some(moli_api::Household::open(&hub, Some(data), &[])),
            ..Default::default()
        };
        let app = moli_api::router(hub, CancellationToken::new(), &options)
            .into_make_service_with_connect_info::<std::net::SocketAddr>();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let request = moli_net::empty(
            http::Request::get("/api/people").header(http::header::HOST, addr.to_string()),
        )
        .unwrap();
        let (status, body) = moli_net::plain("127.0.0.1", addr.port(), request)
            .await
            .unwrap();
        server.abort();
        assert_eq!(status, http::StatusCode::OK);
        let loaded: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let expected = &household_files()[0].1;
        assert_eq!(loaded["people"].as_array().unwrap().len(), 2);
        for (i, person) in expected["people"].as_array().unwrap().iter().enumerate() {
            for key in ["id", "name", "role"] {
                assert_eq!(loaded["people"][i][key], person[key]);
            }
        }
        assert_eq!(loaded["zones"], expected["zones"]);
    }

    #[test]
    fn an_older_backup_without_household_files_still_restores() {
        let base = std::env::temp_dir().join(format!("moli-backup-legacy-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let (saved, fresh) = (base.join("saved"), base.join("fresh"));
        std::fs::create_dir_all(&saved).unwrap();
        std::fs::write(saved.join("labels.toml"), b"x = 1\n").unwrap();
        std::fs::write(
            saved.join("manifest.json"),
            br#"{"moli_os":"0.1.0","taken_ms":0,"files":{"labels.toml":6}}"#,
        )
        .unwrap();
        restore(&fresh, &saved, false).unwrap();
        assert_eq!(
            std::fs::read(fresh.join("labels.toml")).unwrap(),
            b"x = 1\n"
        );
        for (name, _) in household_files() {
            assert!(
                !fresh.join(name).exists(),
                "old backups cannot recreate {name}"
            );
        }
        assert!(!fresh.join("master.key").exists());
        std::fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn a_backup_restores_into_an_empty_home() {
        let base = std::env::temp_dir().join(format!("moli-backup-{}", std::process::id()));
        let (data, saved, fresh) = (base.join("data"), base.join("saved"), base.join("fresh"));
        std::fs::create_dir_all(&data).unwrap();
        let db = rusqlite::Connection::open(data.join("history.db")).unwrap();
        db.execute_batch(
            "PRAGMA journal_mode = WAL; CREATE TABLE t (v INTEGER); INSERT INTO t VALUES (42);",
        )
        .unwrap();
        std::fs::write(data.join("labels.toml"), "x = 1\n").unwrap();
        std::fs::create_dir_all(data.join("plan")).unwrap();
        std::fs::write(data.join("plan").join("0123456789abcdef.png"), b"png").unwrap();
        std::fs::write(data.join("plan").join("notes.txt"), b"not a plan").unwrap();

        backup(&data, &saved).unwrap();
        assert!(
            backup(&data, &saved).is_err(),
            "never into a non-empty folder"
        );
        restore(&fresh, &saved, false).unwrap();
        let back = rusqlite::Connection::open(fresh.join("history.db")).unwrap();
        let v: i64 = back.query_row("SELECT v FROM t", [], |r| r.get(0)).unwrap();
        assert_eq!(v, 42);
        assert_eq!(
            std::fs::read_to_string(fresh.join("labels.toml")).unwrap(),
            "x = 1\n"
        );
        assert_eq!(
            std::fs::read(fresh.join("plan").join("0123456789abcdef.png")).unwrap(),
            b"png",
            "the plan's images come back"
        );
        assert!(!fresh.join("plan").join("notes.txt").exists());
        assert!(
            restore(&fresh, &saved, false).is_err(),
            "no overwrite without --force"
        );
        restore(&fresh, &saved, true).unwrap();
        // A damaged backup restores nothing.
        std::fs::write(saved.join("labels.toml"), "x = 12345\n").unwrap();
        let other = base.join("other");
        assert!(restore(&other, &saved, false).is_err());
        assert!(!other.join("history.db").exists(), "nothing half-restored");
        drop((db, back));
        let _ = std::fs::remove_dir_all(base);
    }
}
