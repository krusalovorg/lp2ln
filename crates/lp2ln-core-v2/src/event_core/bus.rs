use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock, Weak};

use anyhow::Result;
use async_trait::async_trait;
use tokio::sync::broadcast;

use super::commands::{CoreCommand, CoreCommandKind};
use super::events::{CoreEvent, CoreEventKind};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct HandlerId(u64);

impl HandlerId {
    pub fn get(self) -> u64 {
        self.0
    }
}

#[async_trait]
pub trait CoreEventHandler: Send + Sync {
    async fn handle_event(&self, event: CoreEvent, ctx: EventContext) -> Result<()>;
}

#[async_trait]
pub trait CoreCommandHandler: Send + Sync {
    async fn handle_command(&self, command: CoreCommand, ctx: CommandContext) -> Result<()>;
}

#[derive(Clone)]
pub struct EventContext {
    pub bus: CoreBus,
    pub handler_id: HandlerId,
}

impl EventContext {
    pub async fn emit(&self, event: CoreEvent) -> Result<usize> {
        self.bus.emit(event).await
    }
}

#[derive(Clone)]
pub struct CommandContext {
    pub bus: CoreBus,
    pub handler_id: HandlerId,
}

impl CommandContext {
    pub async fn emit(&self, event: CoreEvent) -> Result<usize> {
        self.bus.emit(event).await
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CoreBusStats {
    pub emitted_events: u64,
    pub broadcast_observer_deliveries: u64,
    pub broadcast_no_receivers: u64,
    pub event_handler_deliveries: u64,
    pub event_handler_errors: u64,
    pub dispatched_commands: u64,
    pub command_handler_deliveries: u64,
    pub command_handler_errors: u64,
    pub missing_command_handlers: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum RegistrationKind {
    Event(CoreEventKind),
    Command(CoreCommandKind),
}

#[derive(Clone)]
pub struct HandlerRegistration {
    id: HandlerId,
    kind: RegistrationKind,
    inner: Weak<CoreBusInner>,
}

impl HandlerRegistration {
    pub fn id(&self) -> HandlerId {
        self.id
    }

    pub fn unregister(&self) -> bool {
        let Some(inner) = self.inner.upgrade() else {
            return false;
        };
        match self.kind.clone() {
            RegistrationKind::Event(kind) => inner.unregister_event(kind, self.id),
            RegistrationKind::Command(kind) => inner.unregister_command(kind, self.id),
        }
    }
}

#[derive(Clone)]
pub struct CoreBus {
    inner: Arc<CoreBusInner>,
}

impl Default for CoreBus {
    fn default() -> Self {
        Self::new(4096)
    }
}

impl CoreBus {
    pub fn new(event_broadcast_capacity: usize) -> Self {
        let (event_tx, _rx) = broadcast::channel(event_broadcast_capacity);
        Self {
            inner: Arc::new(CoreBusInner {
                event_tx,
                event_handlers: RwLock::new(HashMap::new()),
                command_handlers: RwLock::new(HashMap::new()),
                next_handler_id: AtomicU64::new(1),
                stats: CoreBusMetrics::default(),
            }),
        }
    }

    pub fn subscribe_events(&self) -> broadcast::Receiver<CoreEvent> {
        self.inner.event_tx.subscribe()
    }

    pub fn register_event_handler(
        &self,
        kind: CoreEventKind,
        handler: Arc<dyn CoreEventHandler>,
    ) -> HandlerRegistration {
        let id = self.inner.next_id();
        let mut handlers = self
            .inner
            .event_handlers
            .write()
            .expect("event handler registry lock poisoned");
        handlers
            .entry(kind.clone())
            .or_default()
            .push(RegisteredEventHandler { id, handler });
        HandlerRegistration {
            id,
            kind: RegistrationKind::Event(kind),
            inner: Arc::downgrade(&self.inner),
        }
    }

    pub fn register_command_handler(
        &self,
        kind: CoreCommandKind,
        handler: Arc<dyn CoreCommandHandler>,
    ) -> HandlerRegistration {
        let id = self.inner.next_id();
        let mut handlers = self
            .inner
            .command_handlers
            .write()
            .expect("command handler registry lock poisoned");
        handlers
            .entry(kind.clone())
            .or_default()
            .push(RegisteredCommandHandler { id, handler });
        HandlerRegistration {
            id,
            kind: RegistrationKind::Command(kind),
            inner: Arc::downgrade(&self.inner),
        }
    }

    pub fn event_handler_count(&self, kind: CoreEventKind) -> usize {
        self.inner
            .event_handlers
            .read()
            .expect("event handler registry lock poisoned")
            .get(&kind)
            .map_or(0, Vec::len)
    }

    pub fn command_handler_count(&self, kind: CoreCommandKind) -> usize {
        self.inner
            .command_handlers
            .read()
            .expect("command handler registry lock poisoned")
            .get(&kind)
            .map_or(0, Vec::len)
    }

    pub fn stats(&self) -> CoreBusStats {
        self.inner.stats.snapshot()
    }

    pub async fn emit(&self, event: CoreEvent) -> Result<usize> {
        self.inner
            .stats
            .emitted_events
            .fetch_add(1, Ordering::Relaxed);
        match self.inner.event_tx.send(event.clone()) {
            Ok(receiver_count) => {
                self.inner
                    .stats
                    .broadcast_observer_deliveries
                    .fetch_add(receiver_count as u64, Ordering::Relaxed);
            }
            Err(_) => {
                self.inner
                    .stats
                    .broadcast_no_receivers
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
        let kind = event.kind();
        let handlers = self
            .inner
            .event_handlers
            .read()
            .expect("event handler registry lock poisoned")
            .get(&kind)
            .cloned()
            .unwrap_or_default();

        let mut delivered = 0usize;
        for registered in handlers {
            let result = registered
                .handler
                .handle_event(
                    event.clone(),
                    EventContext {
                        bus: self.clone(),
                        handler_id: registered.id,
                    },
                )
                .await;
            if let Err(err) = result {
                self.inner
                    .stats
                    .event_handler_errors
                    .fetch_add(1, Ordering::Relaxed);
                return Err(err);
            }
            self.inner
                .stats
                .event_handler_deliveries
                .fetch_add(1, Ordering::Relaxed);
            delivered += 1;
        }
        Ok(delivered)
    }

    pub async fn dispatch_command(&self, command: CoreCommand) -> Result<usize> {
        self.inner
            .stats
            .dispatched_commands
            .fetch_add(1, Ordering::Relaxed);
        let kind = command.kind();
        let handlers = self
            .inner
            .command_handlers
            .read()
            .expect("command handler registry lock poisoned")
            .get(&kind)
            .cloned()
            .unwrap_or_default();

        if handlers.is_empty() {
            self.inner
                .stats
                .missing_command_handlers
                .fetch_add(1, Ordering::Relaxed);
            return Err(anyhow::anyhow!("no handler registered for {:?}", kind));
        }

        let mut delivered = 0usize;
        for registered in handlers {
            let result = registered
                .handler
                .handle_command(
                    command.clone(),
                    CommandContext {
                        bus: self.clone(),
                        handler_id: registered.id,
                    },
                )
                .await;
            if let Err(err) = result {
                self.inner
                    .stats
                    .command_handler_errors
                    .fetch_add(1, Ordering::Relaxed);
                return Err(err);
            }
            self.inner
                .stats
                .command_handler_deliveries
                .fetch_add(1, Ordering::Relaxed);
            delivered += 1;
        }
        Ok(delivered)
    }
}

struct CoreBusInner {
    event_tx: broadcast::Sender<CoreEvent>,
    event_handlers: RwLock<HashMap<CoreEventKind, Vec<RegisteredEventHandler>>>,
    command_handlers: RwLock<HashMap<CoreCommandKind, Vec<RegisteredCommandHandler>>>,
    next_handler_id: AtomicU64,
    stats: CoreBusMetrics,
}

#[derive(Default)]
struct CoreBusMetrics {
    emitted_events: AtomicU64,
    broadcast_observer_deliveries: AtomicU64,
    broadcast_no_receivers: AtomicU64,
    event_handler_deliveries: AtomicU64,
    event_handler_errors: AtomicU64,
    dispatched_commands: AtomicU64,
    command_handler_deliveries: AtomicU64,
    command_handler_errors: AtomicU64,
    missing_command_handlers: AtomicU64,
}

impl CoreBusMetrics {
    fn snapshot(&self) -> CoreBusStats {
        CoreBusStats {
            emitted_events: self.emitted_events.load(Ordering::Relaxed),
            broadcast_observer_deliveries: self
                .broadcast_observer_deliveries
                .load(Ordering::Relaxed),
            broadcast_no_receivers: self.broadcast_no_receivers.load(Ordering::Relaxed),
            event_handler_deliveries: self.event_handler_deliveries.load(Ordering::Relaxed),
            event_handler_errors: self.event_handler_errors.load(Ordering::Relaxed),
            dispatched_commands: self.dispatched_commands.load(Ordering::Relaxed),
            command_handler_deliveries: self.command_handler_deliveries.load(Ordering::Relaxed),
            command_handler_errors: self.command_handler_errors.load(Ordering::Relaxed),
            missing_command_handlers: self.missing_command_handlers.load(Ordering::Relaxed),
        }
    }
}

impl CoreBusInner {
    fn next_id(&self) -> HandlerId {
        HandlerId(self.next_handler_id.fetch_add(1, Ordering::Relaxed))
    }

    fn unregister_event(&self, kind: CoreEventKind, id: HandlerId) -> bool {
        let mut handlers = self
            .event_handlers
            .write()
            .expect("event handler registry lock poisoned");
        remove_handler(handlers.get_mut(&kind), id)
    }

    fn unregister_command(&self, kind: CoreCommandKind, id: HandlerId) -> bool {
        let mut handlers = self
            .command_handlers
            .write()
            .expect("command handler registry lock poisoned");
        remove_handler(handlers.get_mut(&kind), id)
    }
}

fn remove_handler<T: RegisteredHandler>(handlers: Option<&mut Vec<T>>, id: HandlerId) -> bool {
    let Some(handlers) = handlers else {
        return false;
    };
    let len_before = handlers.len();
    handlers.retain(|h| h.id() != id);
    len_before != handlers.len()
}

trait RegisteredHandler {
    fn id(&self) -> HandlerId;
}

#[derive(Clone)]
struct RegisteredEventHandler {
    id: HandlerId,
    handler: Arc<dyn CoreEventHandler>,
}

impl RegisteredHandler for RegisteredEventHandler {
    fn id(&self) -> HandlerId {
        self.id
    }
}

#[derive(Clone)]
struct RegisteredCommandHandler {
    id: HandlerId,
    handler: Arc<dyn CoreCommandHandler>,
}

impl RegisteredHandler for RegisteredCommandHandler {
    fn id(&self) -> HandlerId {
        self.id
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;
    use crate::event_core::commands::{LifecycleAction, LifecycleCommand};
    use crate::event_core::events::{
        LifecycleEvent, ServiceDescriptor, ServiceKind, ServiceStatus,
    };

    struct CountingEventHandler {
        count: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl CoreEventHandler for CountingEventHandler {
        async fn handle_event(&self, _event: CoreEvent, _ctx: EventContext) -> Result<()> {
            self.count.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
    }

    struct FailingEventHandler;

    #[async_trait]
    impl CoreEventHandler for FailingEventHandler {
        async fn handle_event(&self, _event: CoreEvent, _ctx: EventContext) -> Result<()> {
            Err(anyhow::anyhow!("event handler failed"))
        }
    }

    struct CountingCommandHandler {
        count: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl CoreCommandHandler for CountingCommandHandler {
        async fn handle_command(&self, _command: CoreCommand, ctx: CommandContext) -> Result<()> {
            self.count.fetch_add(1, Ordering::Relaxed);
            let _ = ctx
                .emit(CoreEvent::Lifecycle(LifecycleEvent {
                    service: ServiceDescriptor::new("router", ServiceKind::Router),
                    status: ServiceStatus::Ready,
                    generation: 1,
                    reason: None,
                }))
                .await?;
            Ok(())
        }
    }

    struct FailingCommandHandler;

    #[async_trait]
    impl CoreCommandHandler for FailingCommandHandler {
        async fn handle_command(&self, _command: CoreCommand, _ctx: CommandContext) -> Result<()> {
            Err(anyhow::anyhow!("command handler failed"))
        }
    }

    fn lifecycle_event() -> CoreEvent {
        CoreEvent::Lifecycle(LifecycleEvent {
            service: ServiceDescriptor::new("runtime", ServiceKind::Runtime),
            status: ServiceStatus::Ready,
            generation: 1,
            reason: None,
        })
    }

    fn lifecycle_command() -> CoreCommand {
        CoreCommand::Lifecycle(LifecycleCommand {
            service: ServiceDescriptor::new("runtime", ServiceKind::Runtime),
            action: LifecycleAction::Start,
        })
    }

    #[tokio::test]
    async fn event_handler_dispatches_and_unregisters() {
        let bus = CoreBus::new(8);
        let count = Arc::new(AtomicUsize::new(0));
        let registration = bus.register_event_handler(
            CoreEventKind::Lifecycle,
            Arc::new(CountingEventHandler {
                count: count.clone(),
            }),
        );

        assert_eq!(bus.emit(lifecycle_event()).await.unwrap(), 1);
        assert_eq!(count.load(Ordering::Relaxed), 1);
        assert!(registration.unregister());
        assert_eq!(bus.event_handler_count(CoreEventKind::Lifecycle), 0);
        assert_eq!(bus.emit(lifecycle_event()).await.unwrap(), 0);
        assert_eq!(count.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn command_handler_dispatches_and_can_emit_events() {
        let bus = CoreBus::new(8);
        let mut observer = bus.subscribe_events();
        let count = Arc::new(AtomicUsize::new(0));
        bus.register_command_handler(
            CoreCommandKind::Lifecycle,
            Arc::new(CountingCommandHandler {
                count: count.clone(),
            }),
        );

        assert_eq!(bus.dispatch_command(lifecycle_command()).await.unwrap(), 1);
        assert_eq!(count.load(Ordering::Relaxed), 1);

        let observed = observer.recv().await.unwrap();
        assert!(matches!(observed, CoreEvent::Lifecycle(_)));
    }

    #[tokio::test]
    async fn command_without_owner_is_an_error() {
        let bus = CoreBus::new(8);
        let err = bus.dispatch_command(lifecycle_command()).await.unwrap_err();
        assert!(err.to_string().contains("no handler registered"));
    }

    #[tokio::test]
    async fn stats_count_event_broadcast_and_handler_delivery() {
        let bus = CoreBus::new(8);
        let count = Arc::new(AtomicUsize::new(0));
        bus.register_event_handler(
            CoreEventKind::Lifecycle,
            Arc::new(CountingEventHandler {
                count: count.clone(),
            }),
        );

        assert_eq!(bus.emit(lifecycle_event()).await.unwrap(), 1);

        let stats = bus.stats();
        assert_eq!(stats.emitted_events, 1);
        assert_eq!(stats.broadcast_no_receivers, 1);
        assert_eq!(stats.broadcast_observer_deliveries, 0);
        assert_eq!(stats.event_handler_deliveries, 1);
        assert_eq!(stats.event_handler_errors, 0);
    }

    #[tokio::test]
    async fn stats_count_observer_delivery_when_subscribed() {
        let bus = CoreBus::new(8);
        let mut observer = bus.subscribe_events();

        assert_eq!(bus.emit(lifecycle_event()).await.unwrap(), 0);
        let observed = observer.recv().await.unwrap();
        assert!(matches!(observed, CoreEvent::Lifecycle(_)));

        let stats = bus.stats();
        assert_eq!(stats.emitted_events, 1);
        assert_eq!(stats.broadcast_no_receivers, 0);
        assert_eq!(stats.broadcast_observer_deliveries, 1);
        assert_eq!(stats.event_handler_deliveries, 0);
    }

    #[tokio::test]
    async fn stats_count_handler_errors_without_hiding_error() {
        let bus = CoreBus::new(8);
        let count = Arc::new(AtomicUsize::new(0));
        bus.register_event_handler(
            CoreEventKind::Lifecycle,
            Arc::new(CountingEventHandler {
                count: count.clone(),
            }),
        );
        bus.register_event_handler(CoreEventKind::Lifecycle, Arc::new(FailingEventHandler));

        let err = bus.emit(lifecycle_event()).await.unwrap_err();

        assert!(err.to_string().contains("event handler failed"));
        assert_eq!(count.load(Ordering::Relaxed), 1);
        let stats = bus.stats();
        assert_eq!(stats.event_handler_deliveries, 1);
        assert_eq!(stats.event_handler_errors, 1);
    }

    #[tokio::test]
    async fn stats_count_command_errors_and_missing_handlers() {
        let bus = CoreBus::new(8);
        let err = bus.dispatch_command(lifecycle_command()).await.unwrap_err();
        assert!(err.to_string().contains("no handler registered"));
        let stats = bus.stats();
        assert_eq!(stats.dispatched_commands, 1);
        assert_eq!(stats.missing_command_handlers, 1);

        bus.register_command_handler(CoreCommandKind::Lifecycle, Arc::new(FailingCommandHandler));
        let err = bus.dispatch_command(lifecycle_command()).await.unwrap_err();
        assert!(err.to_string().contains("command handler failed"));
        let stats = bus.stats();
        assert_eq!(stats.dispatched_commands, 2);
        assert_eq!(stats.command_handler_deliveries, 0);
        assert_eq!(stats.command_handler_errors, 1);
        assert_eq!(stats.missing_command_handlers, 1);
    }
}
