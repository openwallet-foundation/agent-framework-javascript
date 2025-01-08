import { ClassValidationError } from '../../../core/src/error/ClassValidationError'
import { JsonTransformer } from '../../../core/src/utils'
import { AgentMessage } from '../AgentMessage'
import { TestMessage } from '../util/__tests__/messageType.test'
import { IsValidMessageType, parseMessageType } from '../util/messageType'

class CustomProtocolMessage extends AgentMessage {
  @IsValidMessageType(CustomProtocolMessage.type)
  public readonly type = CustomProtocolMessage.type.messageTypeUri
  public static readonly type = parseMessageType('https://didcomm.org/fake-protocol/1.5/message')
}

class LegacyDidSovPrefixMessage extends AgentMessage {
  public readonly allowDidSovPrefix = true

  @IsValidMessageType(LegacyDidSovPrefixMessage.type)
  public readonly type = LegacyDidSovPrefixMessage.type.messageTypeUri
  public static readonly type = parseMessageType('https://didcomm.org/fake-protocol/1.5/another-message')
}

describe('AgentMessage', () => {
  describe('toJSON', () => {
    it('should only use did:sov message prefix if useDidSovPrefixWhereAllowed and allowDidSovPrefix are both true', () => {
      const message = new TestMessage()
      const legacyPrefixMessage = new LegacyDidSovPrefixMessage()

      // useDidSovPrefixWhereAllowed & allowDidSovPrefix are both false
      let testMessageJson = message.toJSON()
      expect(testMessageJson['@type']).toBe('https://didcomm.org/fake-protocol/1.5/invitation')

      // useDidSovPrefixWhereAllowed is true, but allowDidSovPrefix is false
      testMessageJson = message.toJSON({ useDidSovPrefixWhereAllowed: true })
      expect(testMessageJson['@type']).toBe('https://didcomm.org/fake-protocol/1.5/invitation')

      // useDidSovPrefixWhereAllowed is false, but allowDidSovPrefix is true
      testMessageJson = legacyPrefixMessage.toJSON()
      expect(testMessageJson['@type']).toBe('https://didcomm.org/fake-protocol/1.5/another-message')

      // useDidSovPrefixWhereAllowed & allowDidSovPrefix are both true
      testMessageJson = legacyPrefixMessage.toJSON({ useDidSovPrefixWhereAllowed: true })
      expect(testMessageJson['@type']).toBe('did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/fake-protocol/1.5/another-message')
    })
  })

  describe('@IsValidMessageType', () => {
    it('successfully validates if the message type is exactly the supported message type', async () => {
      const json = {
        '@id': 'd61c7e3d-d4af-469b-8d42-33fd14262e17',
        '@type': 'https://didcomm.org/fake-protocol/1.5/message',
      }

      const message = JsonTransformer.fromJSON(json, CustomProtocolMessage)

      expect(message).toBeInstanceOf(CustomProtocolMessage)
    })

    it('successfully validates if the message type minor version is lower than the supported message type', async () => {
      const json = {
        '@id': 'd61c7e3d-d4af-469b-8d42-33fd14262e17',
        '@type': 'https://didcomm.org/fake-protocol/1.2/message',
      }

      const message = JsonTransformer.fromJSON(json, CustomProtocolMessage)

      expect(message).toBeInstanceOf(CustomProtocolMessage)
    })

    it('successfully validates if the message type minor version is higher than the supported message type', () => {
      const json = {
        '@id': 'd61c7e3d-d4af-469b-8d42-33fd14262e17',
        '@type': 'https://didcomm.org/fake-protocol/1.8/message',
      }

      const message = JsonTransformer.fromJSON(json, CustomProtocolMessage)

      expect(message).toBeInstanceOf(CustomProtocolMessage)
    })

    it('throws a validation error if the message type major version differs from the supported message type', () => {
      const json = {
        '@id': 'd61c7e3d-d4af-469b-8d42-33fd14262e17',
        '@type': 'https://didcomm.org/fake-protocol/2.0/message',
      }

      expect(() => JsonTransformer.fromJSON(json, CustomProtocolMessage)).toThrowError(ClassValidationError)
      try {
        JsonTransformer.fromJSON(json, CustomProtocolMessage)
      } catch (error) {
        const thrownError = error as ClassValidationError
        expect(thrownError.message).toEqual(
          'CustomProtocolMessage: Failed to validate class.\nAn instance of CustomProtocolMessage has failed the validation:\n - property type has failed the following constraints: type does not match the expected message type (only minor version may be lower) \n'
        )
        expect(thrownError.validationErrors).toMatchObject([
          {
            target: {
              appendedAttachments: undefined,
              id: 'd61c7e3d-d4af-469b-8d42-33fd14262e17',
              l10n: undefined,
              pleaseAck: undefined,
              service: undefined,
              thread: undefined,
              timing: undefined,
              transport: undefined,
              type: 'https://didcomm.org/fake-protocol/2.0/message',
            },
            value: 'https://didcomm.org/fake-protocol/2.0/message',
            property: 'type',
            children: [],
            constraints: {
              isValidMessageType: 'type does not match the expected message type (only minor version may be lower)',
            },
          },
        ])
      }
    })
  })
})
