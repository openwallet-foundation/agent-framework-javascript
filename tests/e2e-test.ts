import type { Agent, BaseEvent, CredentialStateChangedEvent, ProofStateChangedEvent } from '@aries-framework/core'

import { sleep } from '../packages/core/src/utils/sleep'
import {
  issueLegacyAnonCredsCredential,
  presentLegacyAnonCredsProof,
  prepareForAnonCredsIssuance,
  AnonCredsTestsAgent,
} from '../packages/anoncreds/tests/legacyAnonCredsSetup'
import { makeConnection } from '../packages/core/tests/helpers'

import { V1CredentialPreview, CredentialState, MediationState, ProofState } from '@aries-framework/core'
import { ReplaySubject } from 'rxjs'

export async function e2eTest({
  mediatorAgent,
  recipientAgent,
  senderAgent,
}: {
  mediatorAgent: AnonCredsTestsAgent
  recipientAgent: AnonCredsTestsAgent
  senderAgent: AnonCredsTestsAgent
}) {
  const senderReplay = new ReplaySubject<BaseEvent>()
  const recipientReplay = new ReplaySubject<BaseEvent>()

  // Make connection between mediator and recipient
  const [mediatorRecipientConnection, recipientMediatorConnection] = await makeConnection(mediatorAgent, recipientAgent)
  expect(recipientMediatorConnection).toBeConnectedWith(mediatorRecipientConnection)

  // Request mediation from mediator
  const mediationRecord = await recipientAgent.mediationRecipient.requestAndAwaitGrant(recipientMediatorConnection)
  expect(mediationRecord.state).toBe(MediationState.Granted)

  // Set mediator as default for recipient, start picking up messages
  await recipientAgent.mediationRecipient.setDefaultMediator(mediationRecord)
  await recipientAgent.mediationRecipient.initiateMessagePickup(mediationRecord)
  const defaultMediator = await recipientAgent.mediationRecipient.findDefaultMediator()
  expect(defaultMediator?.id).toBe(mediationRecord.id)

  // Make connection between sender and recipient
  const [recipientSenderConnection, senderRecipientConnection] = await makeConnection(recipientAgent, senderAgent)
  expect(recipientSenderConnection).toBeConnectedWith(senderRecipientConnection)

  // Issue credential from sender to recipient
  const { credentialDefinition } = await prepareForAnonCredsIssuance(senderAgent, {
    attributeNames: ['name', 'age', 'dateOfBirth'],
    // TODO: update to dynamic created did
    issuerId: senderAgent.publicDid?.did as string,
  })
  const { holderCredentialExchangeRecord, issuerCredentialExchangeRecord } = await issueLegacyAnonCredsCredential({
    issuerAgent: senderAgent,
    issuerReplay: senderReplay,
    holderAgent: recipientAgent,
    holderReplay: recipientReplay,

    issuerHolderConnectionId: senderRecipientConnection.id,
    offer: {
      credentialDefinitionId: credentialDefinition.credentialDefinitionId,
      attributes: V1CredentialPreview.fromRecord({
        name: 'John',
        age: '25',
        // year month day
        dateOfBirth: '19950725',
      }).attributes,
    },
  })

  expect(holderCredentialExchangeRecord.state).toBe(CredentialState.Done)
  expect(issuerCredentialExchangeRecord.state).toBe(CredentialState.Done)

  // Present Proof from recipient to sender
  const { holderProofExchangeRecord, verifierProofExchangeRecord } = await presentLegacyAnonCredsProof({
    verifierAgent: senderAgent,
    verifierReplay: senderReplay,

    holderAgent: recipientAgent,
    holderReplay: recipientReplay,

    verifierHolderConnectionId: senderRecipientConnection.id,
    request: {
      attributes: {
        name: {
          name: 'name',
          restrictions: [
            {
              cred_def_id: credentialDefinition.credentialDefinitionId,
            },
          ],
        },
      },
      predicates: {
        olderThan21: {
          name: 'age',
          restrictions: [
            {
              cred_def_id: credentialDefinition.credentialDefinitionId,
            },
          ],
          p_type: '<=',
          p_value: 20000712,
        },
      },
    },
  })

  expect(holderProofExchangeRecord.state).toBe(ProofState.Done)
  expect(verifierProofExchangeRecord.state).toBe(ProofState.Done)

  // We want to stop the mediator polling before the agent is shutdown.
  await recipientAgent.mediationRecipient.stopMessagePickup()
  await sleep(2000)
}
