import type { ClassValidationError } from '../../../../error/ClassValidationError'

import { Attachment } from '../../../decorators/attachment/Attachment'
import { MessageValidator } from '../../../../utils'
import { JsonEncoder } from '../../../../utils/JsonEncoder'
import { JsonTransformer } from '../../../../utils/JsonTransformer'
import { HandshakeProtocol } from '../../connections'
import { OutOfBandDidCommService } from '../domain'
import { OutOfBandInvitation } from '../messages/OutOfBandInvitation'

describe('toUrl', () => {
  test('encode the message into the URL containing the base64 encoded invitation as the oob query parameter', async () => {
    const domain = 'https://example.com/ssi'
    const json = {
      '@type': 'https://didcomm.org/out-of-band/1.1/invitation',
      services: ['did:sov:LjgpST2rjsoxYegQDRm7EL'],
      '@id': '69212a3a-d068-4f9d-a2dd-4741bca89af3',
      label: 'Faber College',
      goal_code: 'issue-vc',
      goal: 'To issue a Faber College Graduate credential',
      handshake_protocols: ['https://didcomm.org/didexchange/1.0', 'https://didcomm.org/connections/1.0'],
    }
    const invitation = JsonTransformer.fromJSON(json, OutOfBandInvitation)
    const invitationUrl = invitation.toUrl({
      domain,
    })

    expect(invitationUrl).toBe(`${domain}?oob=${JsonEncoder.toBase64URL(json)}`)
  })
})

describe('validation', () => {
  test('Out-of-Band Invitation instance with did as service', async () => {
    const invitation = new OutOfBandInvitation({
      id: '69212a3a-d068-4f9d-a2dd-4741bca89af3',
      label: 'Faber College',
      services: ['did:sov:LjgpST2rjsoxYegQDRm7EL'],
      handshakeProtocols: [HandshakeProtocol.DidExchange],
    })

    expect(() => MessageValidator.validateSync(invitation)).not.toThrow()
  })

  test('Out-of-Band Invitation instance with object as service', async () => {
    const invitation = new OutOfBandInvitation({
      id: '69212a3a-d068-4f9d-a2dd-4741bca89af3',
      label: 'Faber College',
      services: [
        new OutOfBandDidCommService({
          id: 'didcomm',
          serviceEndpoint: 'http://endpoint',
          recipientKeys: ['did:key:z6MkqgkLrRyLg6bqk27djwbbaQWgaSYgFVCKq9YKxZbNkpVv'],
        }),
      ],
      handshakeProtocols: [HandshakeProtocol.DidExchange],
    })

    expect(() => MessageValidator.validateSync(invitation)).not.toThrow()
  })

  test('Out-of-Band Invitation instance with string and object as services', async () => {
    const invitation = new OutOfBandInvitation({
      id: '69212a3a-d068-4f9d-a2dd-4741bca89af3',
      label: 'Faber College',
      services: [
        'did:sov:LjgpST2rjsoxYegQDRm7EL',
        new OutOfBandDidCommService({
          id: 'didcomm',
          serviceEndpoint: 'http://endpoint',
          recipientKeys: ['did:key:z6MkqgkLrRyLg6bqk27djwbbaQWgaSYgFVCKq9YKxZbNkpVv'],
        }),
      ],
      handshakeProtocols: [HandshakeProtocol.DidExchange],
    })

    expect(() => MessageValidator.validateSync(invitation)).not.toThrow()
  })
})

describe('fromUrl', () => {
  test('decode the URL containing the base64 encoded invitation as the oob parameter into an `OutOfBandInvitation`', () => {
    const invitationUrl =
      'http://example.com/ssi?oob=eyJAdHlwZSI6Imh0dHBzOi8vZGlkY29tbS5vcmcvb3V0LW9mLWJhbmQvMS4xL2ludml0YXRpb24iLCJAaWQiOiI2OTIxMmEzYS1kMDY4LTRmOWQtYTJkZC00NzQxYmNhODlhZjMiLCJsYWJlbCI6IkZhYmVyIENvbGxlZ2UiLCJnb2FsX2NvZGUiOiJpc3N1ZS12YyIsImdvYWwiOiJUbyBpc3N1ZSBhIEZhYmVyIENvbGxlZ2UgR3JhZHVhdGUgY3JlZGVudGlhbCIsImhhbmRzaGFrZV9wcm90b2NvbHMiOlsiaHR0cHM6Ly9kaWRjb21tLm9yZy9kaWRleGNoYW5nZS8xLjAiLCJodHRwczovL2RpZGNvbW0ub3JnL2Nvbm5lY3Rpb25zLzEuMCJdLCJzZXJ2aWNlcyI6WyJkaWQ6c292OkxqZ3BTVDJyanNveFllZ1FEUm03RUwiXX0K'

    const invitation = OutOfBandInvitation.fromUrl(invitationUrl)
    const json = JsonTransformer.toJSON(invitation)
    expect(json).toEqual({
      '@type': 'https://didcomm.org/out-of-band/1.1/invitation',
      '@id': '69212a3a-d068-4f9d-a2dd-4741bca89af3',
      label: 'Faber College',
      goal_code: 'issue-vc',
      goal: 'To issue a Faber College Graduate credential',
      handshake_protocols: ['https://didcomm.org/didexchange/1.0', 'https://didcomm.org/connections/1.0'],
      services: ['did:sov:LjgpST2rjsoxYegQDRm7EL'],
    })
  })
})

describe('fromJson', () => {
  test('create an instance of `OutOfBandInvitation` from JSON object', () => {
    const json = {
      '@type': 'https://didcomm.org/out-of-band/1.1/invitation',
      '@id': '69212a3a-d068-4f9d-a2dd-4741bca89af3',
      label: 'Faber College',
      goal_code: 'issue-vc',
      goal: 'To issue a Faber College Graduate credential',
      handshake_protocols: ['https://didcomm.org/didexchange/1.0', 'https://didcomm.org/connections/1.0'],
      services: ['did:sov:LjgpST2rjsoxYegQDRm7EL'],
    }

    const invitation = OutOfBandInvitation.fromJson(json)

    expect(invitation).toBeDefined()
    expect(invitation).toBeInstanceOf(OutOfBandInvitation)
  })

  test('create an instance of `OutOfBandInvitation` from JSON object with inline service', () => {
    const json = {
      '@type': 'https://didcomm.org/out-of-band/1.1/invitation',
      '@id': '69212a3a-d068-4f9d-a2dd-4741bca89af3',
      label: 'Faber College',
      goal_code: 'issue-vc',
      goal: 'To issue a Faber College Graduate credential',
      handshake_protocols: ['https://didcomm.org/didexchange/1.0', 'https://didcomm.org/connections/1.0'],
      services: [
        {
          id: '#inline',
          recipientKeys: ['did:key:z6MkmjY8GnV5i9YTDtPETC2uUAW6ejw3nk5mXF5yci5ab7th'],
          routingKeys: ['did:key:z6MkmjY8GnV5i9YTDtPETC2uUAW6ejw3nk5mXF5yci5ab7th'],
          serviceEndpoint: 'https://example.com/ssi',
        },
      ],
    }

    const invitation = OutOfBandInvitation.fromJson(json)
    expect(invitation).toBeDefined()
    expect(invitation).toBeInstanceOf(OutOfBandInvitation)
  })

  test('create an instance of `OutOfBandInvitation` from JSON object with appended attachments', () => {
    const json = {
      '@type': 'https://didcomm.org/out-of-band/1.1/invitation',
      '@id': '69212a3a-d068-4f9d-a2dd-4741bca89af3',
      label: 'Faber College',
      goal_code: 'issue-vc',
      goal: 'To issue a Faber College Graduate credential',
      handshake_protocols: ['https://didcomm.org/didexchange/1.0', 'https://didcomm.org/connections/1.0'],
      services: ['did:sov:LjgpST2rjsoxYegQDRm7EL'],
      '~attach': [
        {
          '@id': 'view-1',
          'mime-type': 'image/png',
          filename: 'IMG1092348.png',
          lastmod_time: '2018-12-24 18:24:07Z',
          description: 'view from doorway, facing east, with lights off',
          data: {
            base64: 'dmlldyBmcm9tIGRvb3J3YXksIGZhY2luZyBlYXN0LCB3aXRoIGxpZ2h0cyBvZmY=',
          },
        },
        {
          '@id': 'view-2',
          'mime-type': 'image/png',
          filename: 'IMG1092349.png',
          lastmod_time: '2018-12-24 18:25:49Z',
          description: 'view with lamp in the background',
          data: {
            base64: 'dmlldyB3aXRoIGxhbXAgaW4gdGhlIGJhY2tncm91bmQ=',
          },
        },
      ],
    }

    const invitation = OutOfBandInvitation.fromJson(json)
    expect(invitation).toBeDefined()
    expect(invitation).toBeInstanceOf(OutOfBandInvitation)
    expect(invitation.appendedAttachments).toBeDefined()
    expect(invitation.appendedAttachments?.length).toEqual(2)
    expect(invitation.getAppendedAttachmentById('view-1')).toEqual(
      new Attachment({
        id: 'view-1',
        mimeType: 'image/png',
        filename: 'IMG1092348.png',
        lastmodTime: new Date('2018-12-24 18:24:07Z'),
        description: 'view from doorway, facing east, with lights off',
        data: {
          base64: 'dmlldyBmcm9tIGRvb3J3YXksIGZhY2luZyBlYXN0LCB3aXRoIGxpZ2h0cyBvZmY=',
        },
      })
    )
    expect(invitation.getAppendedAttachmentById('view-2')).toEqual(
      new Attachment({
        id: 'view-2',
        mimeType: 'image/png',
        filename: 'IMG1092349.png',
        lastmodTime: new Date('2018-12-24 18:25:49Z'),
        description: 'view with lamp in the background',
        data: {
          base64: 'dmlldyB3aXRoIGxhbXAgaW4gdGhlIGJhY2tncm91bmQ=',
        },
      })
    )
  })

  test('throw validation error when services attribute is empty', () => {
    const json = {
      '@type': 'https://didcomm.org/out-of-band/1.1/invitation',
      '@id': '69212a3a-d068-4f9d-a2dd-4741bca89af3',
      label: 'Faber College',
      goal_code: 'issue-vc',
      goal: 'To issue a Faber College Graduate credential',
      handshake_protocols: ['https://didcomm.org/didexchange/1.0', 'https://didcomm.org/connections/1.0'],
      services: [],
    }

    expect.assertions(1)
    try {
      OutOfBandInvitation.fromJson(json)
    } catch (error) {
      const firstError = error as ClassValidationError
      expect(firstError.validationErrors[0]).toMatchObject({
        children: [],
        constraints: { arrayNotEmpty: 'services should not be empty' },
        property: 'services',
        target: {
          goal: 'To issue a Faber College Graduate credential',
          label: 'Faber College',
          services: [],
        },
        value: [],
      })
    }
  })

  test('transforms legacy prefix message @type and handshake_protocols to https://didcomm.org prefix', () => {
    const json = {
      '@type': 'did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/out-of-band/1.1/invitation',
      '@id': '69212a3a-d068-4f9d-a2dd-4741bca89af3',
      label: 'Faber College',
      goal_code: 'issue-vc',
      goal: 'To issue a Faber College Graduate credential',
      handshake_protocols: [
        'did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/didexchange/1.0',
        'did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/connections/1.0',
      ],
      services: ['did:sov:123'],
    }

    const invitation = OutOfBandInvitation.fromJson(json)

    expect(invitation.type).toBe('https://didcomm.org/out-of-band/1.1/invitation')
    expect(invitation.handshakeProtocols).toEqual([
      'https://didcomm.org/didexchange/1.0',
      'https://didcomm.org/connections/1.0',
    ])
  })

  // Check if options @Transform for legacy did:sov prefix doesn't fail if handshake_protocols is not present
  test('should successfully transform if no handshake_protocols is present', () => {
    const json = {
      '@type': 'did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/out-of-band/1.1/invitation',
      '@id': '69212a3a-d068-4f9d-a2dd-4741bca89af3',
      label: 'Faber College',
      goal_code: 'issue-vc',
      goal: 'To issue a Faber College Graduate credential',
      services: ['did:sov:123'],
    }

    const invitation = OutOfBandInvitation.fromJson(json)

    expect(invitation.type).toBe('https://didcomm.org/out-of-band/1.1/invitation')
    expect(invitation.handshakeProtocols).toBeUndefined()
  })

  test('throw validation error when incorrect service object present in services attribute', async () => {
    const json = {
      '@type': 'https://didcomm.org/out-of-band/1.1/invitation',
      '@id': '69212a3a-d068-4f9d-a2dd-4741bca89af3',
      label: 'Faber College',
      goal_code: 'issue-vc',
      goal: 'To issue a Faber College Graduate credential',
      handshake_protocols: ['https://didcomm.org/didexchange/1.0', 'https://didcomm.org/connections/1.0'],
      services: [
        {
          id: '#inline',
          routingKeys: ['did:sov:LjgpST2rjsoxYegQDRm7EL'],
          serviceEndpoint: 'https://example.com/ssi',
        },
      ],
    }

    expect.assertions(1)
    try {
      OutOfBandInvitation.fromJson(json)
    } catch (error) {
      const firstError = error as ClassValidationError
      expect(firstError.validationErrors[0]).toMatchObject({
        children: [],
        constraints: {
          arrayNotEmpty: 'recipientKeys should not be empty',
          isDidKeyString: 'each value in recipientKeys must be a did:key string',
        },
        property: 'recipientKeys',
        target: {
          id: '#inline',
          routingKeys: ['did:sov:LjgpST2rjsoxYegQDRm7EL'],
          serviceEndpoint: 'https://example.com/ssi',
          type: 'did-communication',
        },
        value: undefined,
      })
    }
  })
})
