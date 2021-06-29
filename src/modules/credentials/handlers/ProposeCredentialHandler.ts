import type { AgentConfig } from '../../../agent/AgentConfig'
import type { Handler, HandlerInboundMessage } from '../../../agent/Handler'
import type { CredentialRecord } from '../repository/CredentialRecord'
import type { CredentialService } from '../services'

import { createOutboundMessage } from '../../../agent/helpers'
import { AriesFrameworkError } from '../../../error'
import { AutoAcceptCredential } from '../../../types'
import { CredentialUtils } from '../CredentialUtils'
import { ProposeCredentialMessage } from '../messages'

export class ProposeCredentialHandler implements Handler {
  private credentialService: CredentialService
  private agentConfig: AgentConfig
  public supportedMessages = [ProposeCredentialMessage]

  public constructor(credentialService: CredentialService, agentConfig: AgentConfig) {
    this.credentialService = credentialService
    this.agentConfig = agentConfig
  }

  public async handle(messageContext: HandlerInboundMessage<ProposeCredentialHandler>) {
    const credentialRecord = await this.credentialService.processProposal(messageContext)

    const autoAccept = CredentialUtils.composeAutoAccept(
      credentialRecord.autoAcceptCredential,
      this.agentConfig.autoAcceptCredentials
    )

    if (autoAccept === AutoAcceptCredential.always) {
      return await this.nextStep(credentialRecord, messageContext)
    } else if (autoAccept === AutoAcceptCredential.contentApproved) {
      if (credentialRecord.proposalMessage && credentialRecord.offerMessage) {
        const proposalValues = CredentialUtils.convertAttributesToValues(
          // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
          credentialRecord.proposalMessage.credentialProposal!.attributes
        )

        const proposalCredentialDefinitionId = credentialRecord.proposalMessage.credentialDefinitionId

        const offerValues = CredentialUtils.convertAttributesToValues(
          credentialRecord.offerMessage.credentialPreview.attributes
        )

        const offerCredentialDefinitionId = credentialRecord.offerMessage.indyCredentialOffer?.cred_def_id

        if (
          CredentialUtils.checkValuesMatch(proposalValues, offerValues) &&
          proposalCredentialDefinitionId === offerCredentialDefinitionId
        ) {
          return await this.nextStep(credentialRecord, messageContext)
        }
      }
    }
  }

  private async nextStep(
    credentialRecord: CredentialRecord,
    messageContext: HandlerInboundMessage<ProposeCredentialHandler>
  ) {
    if (!credentialRecord.proposalMessage?.credentialProposal) {
      throw new AriesFrameworkError(
        `Credential record with id ${credentialRecord.id} is missing required credential proposal`
      )
    }
    if (!credentialRecord.proposalMessage.credentialDefinitionId) {
      throw new AriesFrameworkError('Missing required credential definition id')
    }
    const { message } = await this.credentialService.createOfferAsResponse(credentialRecord, {
      credentialDefinitionId: credentialRecord.proposalMessage.credentialDefinitionId,
      preview: credentialRecord.proposalMessage.credentialProposal,
    })
    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    return createOutboundMessage(messageContext.connection!, message)
  }
}
