export enum OutboundMessageSendStatus {
  SentToSession = 'SentToSession',
  SentToTransport = 'SentToTransport',
  QueuedForPickup = 'QueuedForPickup',
  Undeliverable = 'Undeliverable',
}
