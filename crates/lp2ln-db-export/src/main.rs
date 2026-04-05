use std::env;
use std::fs::File;
use std::io::{stdout, BufWriter, Write};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use lp2ln_core_v2::db::tables::{
    PEER_DESCRIPTOR_TABLE, PEER_INFO_TABLE, PEER_SCORE_SNAPSHOT_KEY, PEER_SCORE_TABLE,
    STORAGE_TABLE,
};
use lp2ln_core_v2::db::Storage;
use lp2ln_core_v2::topology::NodeDescriptor;
use redb::ReadableTable;
use serde::Serialize;
use serde_json::{json, Value};

struct Args {
    path: Option<PathBuf>,
    output: Option<PathBuf>,
    pretty: bool,
    include_secrets: bool,
    pick: bool,
    help: bool,
}

fn print_help(bin: &str) {
    eprintln!(
        "Использование: {bin} [OPTIONS] [PATH]\n\
\n\
PATH — файл redb (`db`) или каталог данных узла (содержит `db`).\n\
\n\
Опции:\n\
  -o, --output FILE   записать JSON в файл вместо stdout\n\
  -p, --pretty        форматировать JSON с отступами\n\
      --include-secrets  не скрывать private_key в peer_info\n\
      --pick            диалог выбора файла (по умолчанию включён в сборке)\n\
  -h, --help          эта справка\n"
    );
}

fn parse_args() -> Result<Args> {
    let mut args = Args {
        path: None,
        output: None,
        pretty: false,
        include_secrets: false,
        pick: false,
        help: false,
    };

    let mut argv = env::args().skip(1).peekable();
    while let Some(a) = argv.next() {
        match a.as_str() {
            "-h" | "--help" => args.help = true,
            "-p" | "--pretty" => args.pretty = true,
            "--include-secrets" => args.include_secrets = true,
            "--pick" => args.pick = true,
            "-o" | "--output" => {
                let p = argv.next().context("ожидается путь после -o/--output")?;
                args.output = Some(PathBuf::from(p));
            }
            s if s.starts_with('-') => bail!("неизвестный флаг: {s}"),
            s => {
                if args.path.is_some() {
                    bail!("лишний аргумент: {s}");
                }
                args.path = Some(PathBuf::from(s));
            }
        }
    }
    Ok(args)
}

#[derive(Serialize)]
struct Meta {
    db_path: String,
    format: &'static str,
}

#[derive(Serialize)]
struct Dump {
    meta: Meta,
    storage: Vec<StorageRow>,
    peer_info: Vec<PeerInfoRow>,
    peer_descriptors: Vec<DescriptorRow>,
    peer_scores: Option<Value>,
}

#[derive(Serialize)]
struct StorageRow {
    key: String,
    value: Value,
}

#[derive(Serialize)]
struct PeerInfoRow {
    key: String,
    value: Value,
}

#[derive(Serialize)]
struct DescriptorRow {
    key: String,
    value: Value,
}

fn resolve_db_path(p: &Path) -> Result<PathBuf> {
    if p.is_dir() {
        let db = p.join("db");
        if db.is_file() {
            Ok(db)
        } else {
            bail!("в каталоге нет файла db: {}", p.display());
        }
    } else if p.is_file() {
        Ok(p.to_path_buf())
    } else {
        bail!("путь не найден: {}", p.display());
    }
}

fn parse_storage_value(bytes: &[u8]) -> Value {
    let Ok(s) = std::str::from_utf8(bytes) else {
        return json!({ "error": "invalid_utf8", "hex": hex::encode(bytes) });
    };
    serde_json::from_str::<Storage>(s)
        .map(|v| serde_json::to_value(v).unwrap_or_else(|_| json!(s)))
        .unwrap_or_else(|_| {
            serde_json::from_str::<Value>(s).unwrap_or_else(|_| Value::String(s.to_string()))
        })
}

fn parse_descriptor_value(bytes: &[u8]) -> Value {
    serde_json::from_slice::<NodeDescriptor>(bytes)
        .map(|d| serde_json::to_value(d).unwrap_or_else(|_| json!("<serialize error>")))
        .unwrap_or_else(|_| {
            serde_json::from_slice::<Value>(bytes).unwrap_or_else(|_| {
                json!({
                    "parse_error": true,
                    "hex": hex::encode(bytes),
                })
            })
        })
}

fn dump_db(db_path: &Path, include_secrets: bool) -> Result<Dump> {
    let db = redb::Database::open(db_path).with_context(|| format!("open {}", db_path.display()))?;
    let read = db
        .begin_read()
        .with_context(|| format!("read txn {}", db_path.display()))?;

    let mut storage = Vec::new();
    if let Ok(table) = read.open_table(STORAGE_TABLE) {
        for item in table.iter()? {
            let (k, v) = item?;
            storage.push(StorageRow {
                key: k.value().to_string(),
                value: parse_storage_value(v.value()),
            });
        }
    }

    let mut peer_info = Vec::new();
    if let Ok(table) = read.open_table(PEER_INFO_TABLE) {
        for item in table.iter()? {
            let (k, v) = item?;
            let key = k.value().to_string();
            let value = if key == "private_key" && !include_secrets {
                json!("***REDACTED***")
            } else if let Ok(s) = std::str::from_utf8(v.value()) {
                Value::String(s.to_string())
            } else {
                json!({ "hex": hex::encode(v.value()) })
            };
            peer_info.push(PeerInfoRow { key, value });
        }
    }

    let mut peer_descriptors = Vec::new();
    if let Ok(table) = read.open_table(PEER_DESCRIPTOR_TABLE) {
        for item in table.iter()? {
            let (k, v) = item?;
            peer_descriptors.push(DescriptorRow {
                key: k.value().to_string(),
                value: parse_descriptor_value(v.value()),
            });
        }
    }

    let peer_scores = if let Ok(table) = read.open_table(PEER_SCORE_TABLE) {
        table
            .get(PEER_SCORE_SNAPSHOT_KEY)?
            .map(|raw| {
                serde_json::from_slice::<Value>(raw.value()).unwrap_or_else(|_| {
                    json!({ "raw_hex": hex::encode(raw.value()) })
                })
            })
    } else {
        None
    };

    Ok(Dump {
        meta: Meta {
            db_path: db_path.display().to_string(),
            format: "lp2ln-redb-export-v1",
        },
        storage,
        peer_info,
        peer_descriptors,
        peer_scores,
    })
}

fn main() -> Result<()> {
    let bin = env::args()
        .next()
        .unwrap_or_else(|| "lp2ln-db-export".to_string());
    let args = parse_args()?;

    if args.help {
        print_help(&bin);
        return Ok(());
    }

    let path = if args.pick {
        #[cfg(feature = "pick")]
        {
            let mut dlg = rfd::FileDialog::new().set_title("Файл redb (db) или каталог узла");
            if let Ok(cwd) = env::current_dir() {
                dlg = dlg.set_directory(cwd);
            }
            dlg.pick_file().context("файл не выбран")?
        }
        #[cfg(not(feature = "pick"))]
        {
            bail!(
                "--pick: пересоберите с feature pick (по умолчанию он включён; если отключали — cargo build -p lp2ln-db-export)"
            );
        }
    } else {
        args.path.with_context(|| {
            format!("укажите PATH к файлу db или каталогу данных ({bin} --help)")
        })?
    };

    let db_path = resolve_db_path(&path)?;
    let dump = dump_db(&db_path, args.include_secrets)?;

    let out: Value = serde_json::to_value(&dump)?;
    let serialized = if args.pretty {
        serde_json::to_string_pretty(&out)?
    } else {
        serde_json::to_string(&out)?
    };

    if let Some(out_path) = args.output {
        let mut w = BufWriter::new(File::create(&out_path)?);
        w.write_all(serialized.as_bytes())?;
        w.flush()?;
    } else {
        let mut w = BufWriter::new(stdout().lock());
        w.write_all(serialized.as_bytes())?;
        w.write_all(b"\n")?;
        w.flush()?;
    }

    Ok(())
}
