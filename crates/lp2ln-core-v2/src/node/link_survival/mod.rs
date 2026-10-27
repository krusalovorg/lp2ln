//! Link survival: keeps a node reachable when the network in between filters,
//! throttles or silently drops some protocols.
//!
//! * [`PathScoreboard`] learns which (transport, endpoint) paths work here.
//! * [`race_verified_dial`] dials ranked paths in parallel and only accepts one
//!   whose node actually answered.
//! * [`run_link_watchdog`] closes links that went silent and penalises their
//!   path, so the next redial goes another way.

mod racer;
mod scoreboard;
mod watchdog;

pub use racer::{RaceCandidate, RaceConfig, RaceWinner, race_verified_dial};
pub use scoreboard::{PathFailure, PathReport, PathScoreboard};
pub use watchdog::{
    LinkSnapshot, LinkVerdict, WatchdogConfig, assess as assess_link, run_link_watchdog,
};
