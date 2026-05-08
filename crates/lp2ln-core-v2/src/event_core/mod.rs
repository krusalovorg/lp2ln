pub mod bus;
pub mod commands;
pub mod events;
pub mod lifecycle;

pub mod prelude {
    pub use super::bus::{
        CommandContext, CoreBus, CoreCommandHandler, CoreEventHandler, EventContext, HandlerId,
        HandlerRegistration,
    };
    pub use super::commands::{
        ConsensusCommand, CoreCommand, CoreCommandKind, DhtCommand, LifecycleAction,
        LifecycleCommand, RelayCommand, RoutingCommand, TransportCommand, WasmExtensionCommand,
    };
    pub use super::events::{
        ConsensusEvent, CoreEvent, CoreEventKind, DhtEvent, LifecycleEvent, PacketClass,
        PacketEvent, PeerEvent, RelayEvent, RoutingEvent, ServiceDescriptor, ServiceKind,
        ServiceStatus, SessionEvent, TransportCapability, TransportEvent, TransportProtocol,
        TransportReadiness, WasmExtensionEvent,
    };
    pub use super::lifecycle::{ManagedService, ServiceContext, ServiceReadiness};
}
