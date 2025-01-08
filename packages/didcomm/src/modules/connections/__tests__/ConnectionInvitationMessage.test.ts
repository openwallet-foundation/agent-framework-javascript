import { validateOrReject } from 'class-validator'
import { parseUrl } from 'query-string'

import { Attachment } from '../../../decorators/attachment/Attachment'
import { ClassValidationError } from '@credo-ts/core/src/error/ClassValidationError'
import { JsonEncoder } from '@credo-ts/core/src/utils/JsonEncoder'
import { JsonTransformer } from '@credo-ts/core/src/utils/JsonTransformer'
import { ConnectionInvitationMessage } from '../messages/ConnectionInvitationMessage'

describe('ConnectionInvitationMessage', () => {
  it('should allow routingKeys to be left out of inline invitation', async () => {
    const json = {
      '@type': ConnectionInvitationMessage.type.messageTypeUri,
      '@id': '04a2c382-999e-4de9-a1d2-9dec0b2fa5e4',
      recipientKeys: ['recipientKeyOne', 'recipientKeyTwo'],
      serviceEndpoint: 'https://example.com',
      label: 'test',
    }
    const invitation = JsonTransformer.fromJSON(json, ConnectionInvitationMessage)
    expect(invitation).toBeInstanceOf(ConnectionInvitationMessage)
  })

  it('should throw error if both did and inline keys / endpoint are missing', async () => {
    const json = {
      '@type': ConnectionInvitationMessage.type.messageTypeUri,
      '@id': '04a2c382-999e-4de9-a1d2-9dec0b2fa5e4',
      label: 'test',
    }

    expect(() => JsonTransformer.fromJSON(json, ConnectionInvitationMessage)).toThrowError(ClassValidationError)
  })

  it('should replace legacy did:sov:BzCbsNYhMrjHiqZDTUASHg;spec prefix with https://didcomm.org in message type', async () => {
    const json = {
      '@type': 'did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/connections/1.0/invitation',
      '@id': '04a2c382-999e-4de9-a1d2-9dec0b2fa5e4',
      recipientKeys: ['recipientKeyOne', 'recipientKeyTwo'],
      serviceEndpoint: 'https://example.com',
      label: 'test',
    }
    const invitation = JsonTransformer.fromJSON(json, ConnectionInvitationMessage)

    // Assert type
    expect(invitation.type).toBe('https://didcomm.org/connections/1.0/invitation')

    // Assert validation also works with the transformation
    expect(invitation).toBeInstanceOf(ConnectionInvitationMessage)
  })

  describe('toUrl', () => {
    it('should correctly include the base64 encoded invitation in the url as the c_i query parameter', async () => {
      const domain = 'https://example.com/ssi'
      const json = {
        '@type': 'https://didcomm.org/connections/1.0/invitation',
        '@id': '04a2c382-999e-4de9-a1d2-9dec0b2fa5e4',
        recipientKeys: ['recipientKeyOne', 'recipientKeyTwo'],
        serviceEndpoint: 'https://example.com',
        label: 'test',
      }
      const invitation = JsonTransformer.fromJSON(json, ConnectionInvitationMessage)
      const invitationUrl = invitation.toUrl({
        domain,
      })

      expect(invitationUrl).toBe(`${domain}?c_i=${JsonEncoder.toBase64URL(json)}`)
    })

    it('should use did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/connections/1.0/invitation as type if useDidSovPrefixWhereAllowed is set to true', async () => {
      const invitation = new ConnectionInvitationMessage({
        id: '04a2c382-999e-4de9-a1d2-9dec0b2fa5e4',
        recipientKeys: ['recipientKeyOne', 'recipientKeyTwo'],
        serviceEndpoint: 'https://example.com',
        label: 'test',
        imageUrl: 'test-image-path',
        appendedAttachments: [
          new Attachment({
            id: 'test-attachment',
            data: {
              json: {
                value: 'test',
              },
            },
          }),
        ],
      })

      const invitationUrl = invitation.toUrl({
        domain: 'https://example.com',
        useDidSovPrefixWhereAllowed: true,
      })

      const parsedUrl = parseUrl(invitationUrl).query
      const encodedInvitation = (parsedUrl['c_i'] ?? parsedUrl['d_m']) as string

      expect(JsonEncoder.fromBase64(encodedInvitation)['@type']).toBe(
        'did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/connections/1.0/invitation'
      )
    })
  })

  describe('fromUrl', () => {
    it('should correctly convert a valid invitation url to a `ConnectionInvitationMessage` with `d_m` as parameter', () => {
      const invitationUrl =
        'https://trinsic.studio/link/?d_m=eyJsYWJlbCI6InRlc3QiLCJpbWFnZVVybCI6Imh0dHBzOi8vdHJpbnNpY2FwaWFzc2V0cy5henVyZWVkZ2UubmV0L2ZpbGVzL2IyODhkMTE3LTNjMmMtNGFjNC05MzVhLWE1MDBkODQzYzFlOV9kMGYxN2I0OS0wNWQ5LTQ4ZDAtODJlMy1jNjg3MGI4MjNjMTUucG5nIiwic2VydmljZUVuZHBvaW50IjoiaHR0cHM6Ly9hcGkucG9ydGFsLnN0cmVldGNyZWQuaWQvYWdlbnQvTVZob1VaQjlHdUl6bVJzSTNIWUNuZHpBcXVKY1ZNdFUiLCJyb3V0aW5nS2V5cyI6WyJCaFZRdEZHdGJ4NzZhMm13Y3RQVkJuZWtLaG1iMTdtUHdFMktXWlVYTDFNaSJdLCJyZWNpcGllbnRLZXlzIjpbIkcyOVF6bXBlVXN0dUVHYzlXNzlYNnV2aUhTUTR6UlV2VWFFOHpXV2VZYjduIl0sIkBpZCI6IjgxYzZiNDUzLWNkMTUtNDQwMC04MWU5LTkwZTJjM2NhY2I1NCIsIkB0eXBlIjoiZGlkOnNvdjpCekNic05ZaE1yakhpcVpEVFVBU0hnO3NwZWMvY29ubmVjdGlvbnMvMS4wL2ludml0YXRpb24ifQ%3D%3D&orig=https://trinsic.studio/url/6dd56daf-e153-40dd-b849-2b345b6853f6'

      const invitation = ConnectionInvitationMessage.fromUrl(invitationUrl)

      expect(validateOrReject(invitation)).resolves.toBeUndefined()
    })
    it('should correctly convert a valid invitation url to a `ConnectionInvitationMessage` with `c_i` as parameter', () => {
      const invitationUrl =
        'https://example.com?c_i=eyJAdHlwZSI6ICJkaWQ6c292OkJ6Q2JzTlloTXJqSGlxWkRUVUFTSGc7c3BlYy9jb25uZWN0aW9ucy8xLjAvaW52aXRhdGlvbiIsICJAaWQiOiAiZmM3ODFlMDItMjA1YS00NGUzLWE5ZTQtYjU1Y2U0OTE5YmVmIiwgInNlcnZpY2VFbmRwb2ludCI6ICJodHRwczovL2RpZGNvbW0uZmFiZXIuYWdlbnQuYW5pbW8uaWQiLCAibGFiZWwiOiAiQW5pbW8gRmFiZXIgQWdlbnQiLCAicmVjaXBpZW50S2V5cyI6IFsiR0hGczFQdFRabjdmYU5LRGVnMUFzU3B6QVAyQmpVckVjZlR2bjc3SnBRTUQiXX0='

      const invitation = ConnectionInvitationMessage.fromUrl(invitationUrl)

      expect(validateOrReject(invitation)).resolves.toBeUndefined()
    })

    it('should throw error if url does not contain `c_i` or `d_m`', () => {
      const invitationUrl = 'https://example.com?param=123'

      expect(() => ConnectionInvitationMessage.fromUrl(invitationUrl)).toThrowError()
    })
  })
})
