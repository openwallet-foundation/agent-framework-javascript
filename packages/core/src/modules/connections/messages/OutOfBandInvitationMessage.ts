import type { DIDCommV2MessageParams } from '../../../agent/didcomm'
import type { DidCommService } from '../../dids'
import type { AcceptProtocol, Transport } from '../../routing/services/MediationRecipientService'

import { Expose } from 'class-transformer'
import { Equals, ValidateNested } from 'class-validator'
import { parseUrl } from 'query-string'

import { DIDCommV2Message } from '../../../agent/didcomm'
import { AriesFrameworkError } from '../../../error'
import { JsonEncoder, JsonTransformer } from '../../../utils'
import { MessageValidator } from '../../../utils/MessageValidator'

export interface OutOfBandInvitationBody {
  label?: string
  imageUrl?: string
  goalCode?: string
  accept?: AcceptProtocol[]
  service?: DidCommService
  transport?: Transport
}

type OutOfBandInvitationOptions = DIDCommV2MessageParams & {
  body: OutOfBandInvitationBody
}

export class OutOfBandInvitationMessage extends DIDCommV2Message {
  public constructor(options: OutOfBandInvitationOptions) {
    super(options)
  }

  @Equals(OutOfBandInvitationMessage.type)
  public readonly type = OutOfBandInvitationMessage.type
  public static readonly type = 'https://didcomm.org/out-of-band/2.0/invitation'

  @Expose({ name: 'body' })
  @ValidateNested()
  public body!: OutOfBandInvitationBody

  public static async fromUrl(invitationUrl: string) {
    const parsedUrl = parseUrl(invitationUrl).query
    const encodedInvitation = parsedUrl['oob'] ?? parsedUrl['d_m']

    if (typeof encodedInvitation === 'string') {
      const invitationJson = JsonEncoder.fromBase64(encodedInvitation)
      const invitation = JsonTransformer.fromJSON(invitationJson, OutOfBandInvitationMessage)

      await MessageValidator.validate(invitation)

      return invitation
    } else {
      throw new AriesFrameworkError(
        'InvitationUrl is invalid. It needs to contain one, and only one, of the following parameters; `oob` or `d_m`'
      )
    }
  }
}
