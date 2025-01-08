import type { AnonCredsTestsAgent } from '../packages/anoncreds/tests/anoncredsSetup'
import type { AgentMessageProcessedEvent, AgentMessageSentEvent } from '@credo-ts/didcomm'

import { filter, firstValueFrom, map } from 'rxjs'

import { presentAnonCredsProof, issueAnonCredsCredential } from '../packages/anoncreds/tests/anoncredsSetup'
import {
  anoncredsDefinitionFourAttributesNoRevocation,
  storePreCreatedAnonCredsDefinition,
} from '../packages/anoncreds/tests/preCreatedAnonCredsDefinition'
import { setupEventReplaySubjects } from '../packages/core/tests'
import { makeConnection } from '../packages/core/tests/helpers'

import {
  V2CredentialPreview,
  V1BatchMessage,
  V1BatchPickupMessage,
  V2DeliveryRequestMessage,
  V2MessageDeliveryMessage,
  CredentialState,
  MediationState,
  ProofState,
  CredentialEventTypes,
  ProofEventTypes,
  AgentEventTypes,
} from '@credo-ts/didcomm'

export async function e2eTest({
  mediatorAgent,
  recipientAgent,
  senderAgent,
}: {
  mediatorAgent: AnonCredsTestsAgent
  recipientAgent: AnonCredsTestsAgent
  senderAgent: AnonCredsTestsAgent
}) {
  const [senderReplay, recipientReplay] = setupEventReplaySubjects(
    [senderAgent, recipientAgent, mediatorAgent],
    [
      CredentialEventTypes.CredentialStateChanged,
      ProofEventTypes.ProofStateChanged,
      AgentEventTypes.AgentMessageProcessed,
      AgentEventTypes.AgentMessageSent,
    ]
  )

  // Make connection between mediator and recipient
  const [mediatorRecipientConnection, recipientMediatorConnection] = await makeConnection(mediatorAgent, recipientAgent)
  expect(recipientMediatorConnection).toBeConnectedWith(mediatorRecipientConnection)

  // Request mediation from mediator
  const mediationRecord = await recipientAgent.modules.mediationRecipient.requestAndAwaitGrant(
    recipientMediatorConnection
  )
  expect(mediationRecord.state).toBe(MediationState.Granted)

  // Set mediator as default for recipient, start picking up messages
  await recipientAgent.modules.mediationRecipient.setDefaultMediator(mediationRecord)
  await recipientAgent.modules.mediationRecipient.initiateMessagePickup(mediationRecord)
  const defaultMediator = await recipientAgent.modules.mediationRecipient.findDefaultMediator()
  expect(defaultMediator?.id).toBe(mediationRecord.id)

  // Make connection between sender and recipient
  const [recipientSenderConnection, senderRecipientConnection] = await makeConnection(recipientAgent, senderAgent)
  expect(recipientSenderConnection).toBeConnectedWith(senderRecipientConnection)

  const { credentialDefinitionId } = await storePreCreatedAnonCredsDefinition(
    senderAgent,
    anoncredsDefinitionFourAttributesNoRevocation
  )

  const { holderCredentialExchangeRecord, issuerCredentialExchangeRecord } = await issueAnonCredsCredential({
    issuerAgent: senderAgent,
    issuerReplay: senderReplay,
    holderAgent: recipientAgent,
    holderReplay: recipientReplay,
    revocationRegistryDefinitionId: null,

    issuerHolderConnectionId: senderRecipientConnection.id,
    offer: {
      credentialDefinitionId,
      attributes: V2CredentialPreview.fromRecord({
        name: 'John',
        age: '25',
        'x-ray': 'not taken',
        profile_picture: 'looking good',
      }).attributes,
    },
  })

  expect(holderCredentialExchangeRecord.state).toBe(CredentialState.Done)
  expect(issuerCredentialExchangeRecord.state).toBe(CredentialState.Done)

  // Present Proof from recipient to sender
  const { holderProofExchangeRecord, verifierProofExchangeRecord } = await presentAnonCredsProof({
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
              cred_def_id: credentialDefinitionId,
            },
          ],
        },
      },
      predicates: {
        olderThan21: {
          name: 'age',
          restrictions: [
            {
              cred_def_id: credentialDefinitionId,
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
  await recipientAgent.modules.mediationRecipient.stopMessagePickup()

  const pickupRequestMessages = [V2DeliveryRequestMessage.type.messageTypeUri, V1BatchPickupMessage.type.messageTypeUri]
  const deliveryMessages = [V2MessageDeliveryMessage.type.messageTypeUri, V1BatchMessage.type.messageTypeUri]

  let lastSentPickupMessageThreadId: undefined | string = undefined
  recipientReplay
    .pipe(
      filter((e): e is AgentMessageSentEvent => e.type === AgentEventTypes.AgentMessageSent),
      filter((e) => pickupRequestMessages.includes(e.payload.message.message.type)),
      map((e) => e.payload.message.message.threadId)
    )
    .subscribe((threadId) => (lastSentPickupMessageThreadId = threadId))

  // Wait for the response to the pickup message to be processed
  if (lastSentPickupMessageThreadId) {
    await firstValueFrom(
      recipientReplay.pipe(
        filter((e): e is AgentMessageProcessedEvent => e.type === AgentEventTypes.AgentMessageProcessed),
        filter((e) => deliveryMessages.includes(e.payload.message.type)),
        filter((e) => e.payload.message.threadId === lastSentPickupMessageThreadId)
      )
    )
  }

  // FIXME: we should add some fancy logic here that checks whether the last sent message has been received by the other
  // agent and possibly wait for the response. So e.g. if pickup v1 is used, we wait for the delivery message to be returned
  // as that is the final message that will be exchange after we've called stopMessagePickup. We can hook into the
  // replay subject AgentMessageProcessed and AgentMessageSent events.
  // await sleep(5000)
}
