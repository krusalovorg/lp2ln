use crate::connection::Connection;
use crate::manager::types::ConnectionType;
use crate::packets::TransportPacket;
use std::sync::Arc;

/// Результат обработки пакета пользовательским обработчиком
#[derive(Debug, Clone)]
pub enum PacketHandlerResult {
    /// Пакет обработан пользовательским обработчиком, стандартная обработка не требуется
    Handled,
    /// Пакет обработан, но нужно отправить ответ
    HandledWithResponse(TransportPacket),
    /// Пакет не обработан, передать стандартной обработке
    Pass,
}

/// Trait для пользовательских обработчиков пакетов
/// Похоже на систему обработчиков в libp2p
#[async_trait::async_trait]
pub trait PacketHandler: Send + Sync + 'static {
    /// Обработать входящий пакет
    /// 
    /// # Arguments
    /// * `packet` - входящий пакет
    /// * `connection_type` - тип соединения
    /// * `connection` - опциональное соединение
    /// 
    /// # Returns
    /// * `PacketHandlerResult::Handled` - пакет обработан, стандартная обработка не нужна
    /// * `PacketHandlerResult::HandledWithResponse(packet)` - пакет обработан, отправить ответ
    /// * `PacketHandlerResult::Pass` - пропустить пакет для стандартной обработки
    async fn handle_packet(
        &self,
        packet: &TransportPacket,
        connection_type: &ConnectionType,
        connection: &Option<Arc<Connection>>,
    ) -> PacketHandlerResult;
}

/// Обертка для PacketHandler, которая решает проблемы с lifetime в DashMap
#[derive(Clone)]
pub struct PacketHandlerWrapper {
    inner: Arc<dyn PacketHandler>,
}

impl PacketHandlerWrapper {
    pub fn new(handler: Arc<dyn PacketHandler>) -> Self {
        Self { inner: handler }
    }

    pub async fn handle_packet(
        &self,
        packet: &TransportPacket,
        connection_type: &ConnectionType,
        connection: &Option<Arc<Connection>>,
    ) -> PacketHandlerResult {
        self.inner.handle_packet(packet, connection_type, connection).await
    }
}

