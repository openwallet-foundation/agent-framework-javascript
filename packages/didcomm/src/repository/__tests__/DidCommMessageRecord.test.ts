import { ConnectionInvitationMessage } from '../../modules'
import { DidCommMessageRecord } from '../DidCommMessageRecord'
import { DidCommMessageRole } from '../DidCommMessageRole'

describe('DidCommMessageRecord', () => {
  it('correctly computes message type tags', () => {
    const didCommMessage = {
      '@id': '7eb74118-7f91-4ba9-9960-c709b036aa86',
      '@type': 'https://didcomm.org/test-protocol/1.0/send-test',
      some: { other: 'property' },
      '~thread': {
        thid: 'ea24e14a-4fc4-40f4-85a0-f6fcf02bfc1c',
      },
    }

    const didCommeMessageRecord = new DidCommMessageRecord({
      message: didCommMessage,
      role: DidCommMessageRole.Receiver,
      associatedRecordId: '16ca6665-29f6-4333-a80e-d34db6bfe0b0',
    })

    expect(didCommeMessageRecord.getTags()).toEqual({
      role: DidCommMessageRole.Receiver,
      associatedRecordId: '16ca6665-29f6-4333-a80e-d34db6bfe0b0',

      // Computed properties based on message id and type
      threadId: 'ea24e14a-4fc4-40f4-85a0-f6fcf02bfc1c',
      protocolName: 'test-protocol',
      messageName: 'send-test',
      protocolMajorVersion: '1',
      protocolMinorVersion: '0',
      messageType: 'https://didcomm.org/test-protocol/1.0/send-test',
      messageId: '7eb74118-7f91-4ba9-9960-c709b036aa86',
    })
  })

  it('correctly returns a message class instance', () => {
    const invitationJson = {
      '@type': 'https://didcomm.org/connections/1.0/invitation',
      '@id': '04a2c382-999e-4de9-a1d2-9dec0b2fa5e4',
      recipientKeys: ['recipientKeyOne', 'recipientKeyTwo'],
      serviceEndpoint: 'https://example.com',
      label: 'test',
    }

    const didCommeMessageRecord = new DidCommMessageRecord({
      message: invitationJson,
      role: DidCommMessageRole.Receiver,
      associatedRecordId: '16ca6665-29f6-4333-a80e-d34db6bfe0b0',
    })

    const invitation = didCommeMessageRecord.getMessageInstance(ConnectionInvitationMessage)

    expect(invitation).toBeInstanceOf(ConnectionInvitationMessage)
  })
})
