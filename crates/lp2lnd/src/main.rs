use core::fmt;
use lp2ln_core_v2::logger::info;
use lp2ln_core_v2::logger::LoggerOptions;
use lp2ln_core_v2::node::{NodeBuilder, NodeOptions};
use lp2ln_core_v2::transport::{tcp::TcpTransport, udp::UdpTransport};
use std::env;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::task;

struct Args {
    options_path: String,
}

impl Default for Args {
    fn default() -> Self {
        Self {
            options_path: String::new(),
        }
    }
}

impl fmt::Display for Args {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        return write!(f, "options_path = {}", self.options_path);
    }
}

fn parse_args() -> Args {
    let args: Vec<String> = env::args().collect();
    let mut result = Args::default();
    for (i, item) in args.iter().enumerate() {
        if i == 0 {
            continue;
        }
        let prev_arg = &args[i - 1];
        if prev_arg.starts_with("-") && prev_arg[1..] == *"o" && !item.starts_with("-") {
            result.options_path = item.clone();
        }
    }
    return result;
}

fn developer_options() -> NodeOptions {
    NodeOptions::empty()
        .with_listen("udp", "0.0.0.0:8080".parse().unwrap())
        .with_listen("tcp", "0.0.0.0:8080".parse().unwrap())
        .with_default_nodes(vec![])
        .allow_unsigned_packets(true)
        .keypair_generate()
        .with_logger_options(LoggerOptions {
            log_dir: Some(PathBuf::from("./logs")),
            file_enabled: true,
            show_debug: true,
            show_info: true,
            show_warning: true,
            show_error: true,
        })
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    lp2ln_core_v2::info!("[Main] Starting LP2LN-Demon");
    console_subscriber::init();
    lp2ln_core_v2::info!("[Main] console_subscriber inited");

    let args = parse_args();

    lp2ln_core_v2::info!("[Main] Loaded args: {}", args);
    let options: NodeOptions;

    if args.options_path.is_empty() {
        options = developer_options();
    } else {
        options = match NodeOptions::from_file(args.options_path.clone()) {
            Ok(opts) => opts,
            Err(err) => {
                lp2ln_core_v2::error!("[Main] Error of reading config: {}", err);
                NodeOptions::new()
            }
        };
    }

    if !args.options_path.is_empty() {
        options.save(args.options_path.clone()).unwrap();
    }

    let builder = NodeBuilder::new()
        .add_transport(Arc::new(TcpTransport::new()))
        .add_transport(Arc::new(UdpTransport::new()));
    let mut node = builder.build(options)?;
    node.start().await?;

    info("[Main] Node started");

    task::spawn(async {
        info("Main sosat hui!");
    });

    tokio::signal::ctrl_c().await?;
    node.stop().await?;
    lp2ln_core_v2::info!("[Main] LP2LN-Demon stopped");
    Ok(())
}
