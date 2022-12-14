import type { Handler } from '../Handler'

import { parseMessageType } from '../../utils/messageType'
import { AgentMessage } from '../AgentMessage'
import { MessageHandlerRegistry } from '../HandlerRegistry'

class ConnectionInvitationTestMessage extends AgentMessage {
  public static readonly type = parseMessageType('https://didcomm.org/connections/1.0/invitation')
}
class ConnectionRequestTestMessage extends AgentMessage {
  public static readonly type = parseMessageType('https://didcomm.org/connections/1.0/request')
}

class ConnectionResponseTestMessage extends AgentMessage {
  public static readonly type = parseMessageType('https://didcomm.org/connections/1.0/response')
}

class NotificationAckTestMessage extends AgentMessage {
  public static readonly type = parseMessageType('https://didcomm.org/notification/1.0/ack')
}
class CredentialProposalTestMessage extends AgentMessage {
  public readonly type = CredentialProposalTestMessage.type.messageTypeUri
  public static readonly type = parseMessageType('https://didcomm.org/issue-credential/1.0/credential-proposal')
}

class CustomProtocolMessage extends AgentMessage {
  public readonly type = CustomProtocolMessage.type.messageTypeUri
  public static readonly type = parseMessageType('https://didcomm.org/fake-protocol/1.5/message')
}

class TestHandler implements Handler {
  // We want to pass various classes to test various behaviours so we dont need to strictly type it.
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  public constructor(classes: any[]) {
    this.supportedMessages = classes
  }

  public supportedMessages

  // We don't need an implementation in test handler so we can disable lint.
  // eslint-disable-next-line @typescript-eslint/no-empty-function
  public async handle() {}
}

describe('MessageHandlerRegistry', () => {
  const fakeProtocolHandler = new TestHandler([CustomProtocolMessage])
  const connectionHandler = new TestHandler([
    ConnectionInvitationTestMessage,
    ConnectionRequestTestMessage,
    ConnectionResponseTestMessage,
  ])

  const messageHandlerRegistry = new MessageHandlerRegistry()

  messageHandlerRegistry.registerHandler(connectionHandler)
  messageHandlerRegistry.registerHandler(new TestHandler([NotificationAckTestMessage]))
  messageHandlerRegistry.registerHandler(new TestHandler([CredentialProposalTestMessage]))
  messageHandlerRegistry.registerHandler(fakeProtocolHandler)

  describe('supportedMessageTypes', () => {
    test('return all supported message types URIs', async () => {
      const messageTypes = messageHandlerRegistry.supportedMessageTypes

      expect(messageTypes).toMatchObject([
        { messageTypeUri: 'https://didcomm.org/connections/1.0/invitation' },
        { messageTypeUri: 'https://didcomm.org/connections/1.0/request' },
        { messageTypeUri: 'https://didcomm.org/connections/1.0/response' },
        { messageTypeUri: 'https://didcomm.org/notification/1.0/ack' },
        { messageTypeUri: 'https://didcomm.org/issue-credential/1.0/credential-proposal' },
        { messageTypeUri: 'https://didcomm.org/fake-protocol/1.5/message' },
      ])
    })
  })

  describe('supportedProtocols', () => {
    test('return all supported message protocols URIs', async () => {
      const messageTypes = messageHandlerRegistry.supportedProtocols

      expect(messageTypes).toEqual([
        'https://didcomm.org/connections/1.0',
        'https://didcomm.org/notification/1.0',
        'https://didcomm.org/issue-credential/1.0',
        'https://didcomm.org/fake-protocol/1.5',
      ])
    })
  })

  describe('filterSupportedProtocolsByMessageFamilies', () => {
    it('should return empty array when input is empty array', async () => {
      const supportedProtocols = messageHandlerRegistry.filterSupportedProtocolsByMessageFamilies([])
      expect(supportedProtocols).toEqual([])
    })

    it('should return empty array when input contains only unsupported protocol', async () => {
      const supportedProtocols = messageHandlerRegistry.filterSupportedProtocolsByMessageFamilies([
        'https://didcomm.org/unsupported-protocol/1.0',
      ])
      expect(supportedProtocols).toEqual([])
    })

    it('should return array with only supported protocol when input contains supported and unsupported protocol', async () => {
      const supportedProtocols = messageHandlerRegistry.filterSupportedProtocolsByMessageFamilies([
        'https://didcomm.org/connections',
        'https://didcomm.org/didexchange',
      ])
      expect(supportedProtocols).toEqual(['https://didcomm.org/connections/1.0'])
    })
  })

  describe('getMessageClassForMessageType()', () => {
    it('should return the correct message class for a registered message type', () => {
      const messageClass = messageHandlerRegistry.getMessageClassForMessageType(
        'https://didcomm.org/connections/1.0/invitation'
      )
      expect(messageClass).toBe(ConnectionInvitationTestMessage)
    })

    it('should return undefined if no message class is registered for the message type', () => {
      const messageClass = messageHandlerRegistry.getMessageClassForMessageType(
        'https://didcomm.org/non-existing/1.0/invitation'
      )
      expect(messageClass).toBeUndefined()
    })

    it('should return the message class with a higher minor version for the message type', () => {
      const messageClass = messageHandlerRegistry.getMessageClassForMessageType(
        'https://didcomm.org/fake-protocol/1.0/message'
      )
      expect(messageClass).toBe(CustomProtocolMessage)
    })

    it('should not return the message class with a different major version', () => {
      const messageClass = messageHandlerRegistry.getMessageClassForMessageType(
        'https://didcomm.org/fake-protocol/2.0/message'
      )
      expect(messageClass).toBeUndefined()
    })
  })
})
