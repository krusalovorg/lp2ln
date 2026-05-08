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

    pub async fn emit(&self, event: CoreEvent) -> Result<usize> {
        let _ = self.inner.event_tx.send(event.clone());
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
            registered
                .handler
                .handle_event(
                    event.clone(),
                    EventContext {
                        bus: self.clone(),
                        handler_id: registered.id,
                    },
                )
                .await?;
            delivered += 1;
        }
        Ok(delivered)
    }

    pub async fn dispatch_command(&self, command: CoreCommand) -> Result<usize> {
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
            return Err(anyhow::anyhow!("no handler registered for {:?}", kind));
        }

        let mut delivered = 0usize;
        for registered in handlers {
            registered
                .handler
                .handle_command(
                    command.clone(),
                    CommandContext {
                        bus: self.clone(),
                        handler_id: registered.id,
                    },
                )
                .await?;
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
}
