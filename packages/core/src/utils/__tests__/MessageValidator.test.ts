import { ConnectionInvitationMessage } from '../../../../didcomm/src/modules/connections'
import { ClassValidationError } from '../../error/ClassValidationError'
import { MessageValidator } from '../MessageValidator'

describe('MessageValidator', () => {
  describe('validateSync', () => {
    it('validates a class instance correctly', () => {
      const invitation = new ConnectionInvitationMessage({
        did: 'did:sov:test1234',
        id: 'afe2867e-58c3-4a8d-85b2-23370dd9c9f0',
        label: 'test-label',
      })

      expect(MessageValidator.validateSync(invitation)).toBeUndefined()
    })
    it('throws an error for invalid class instance', () => {
      const invitation = new ConnectionInvitationMessage({
        did: 'did:sov:test1234',
        id: 'afe2867e-58c3-4a8d-85b2-23370dd9c9f0',
        label: 'test-label',
      })
      invitation.did = undefined

      expect(() => MessageValidator.validateSync(invitation)).toThrow(ClassValidationError)
    })
  })
})
