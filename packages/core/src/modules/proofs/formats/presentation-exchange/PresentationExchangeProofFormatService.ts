import type {
  PresentationExchangePresentation,
  PresentationExchangeProofFormat,
  PresentationExchangeProposal,
  PresentationExchangeRequest,
} from './PresentationExchangeProofFormat'
import type { AgentContext } from '../../../../agent'
import type { JsonValue } from '../../../../types'
import type { InputDescriptorToCredentials } from '../../../presentation-exchange'
import type { W3cVerifiablePresentation, W3cVerifyPresentationResult } from '../../../vc'
import type { ProofFormatService } from '../ProofFormatService'
import type {
  ProofFormatCreateProposalOptions,
  ProofFormatCreateReturn,
  ProofFormatProcessOptions,
  ProofFormatAcceptProposalOptions,
  FormatCreateRequestOptions,
  ProofFormatAcceptRequestOptions,
  ProofFormatProcessPresentationOptions,
  ProofFormatGetCredentialsForRequestOptions,
  ProofFormatSelectCredentialsForRequestOptions,
  ProofFormatAutoRespondProposalOptions,
  ProofFormatAutoRespondRequestOptions,
  ProofFormatAutoRespondPresentationOptions,
} from '../ProofFormatServiceOptions'

import { Attachment, AttachmentData } from '../../../../decorators/attachment/Attachment'
import { AriesFrameworkError } from '../../../../error'
import { deepEquality, JsonTransformer } from '../../../../utils'
import { PresentationExchangeService } from '../../../presentation-exchange/PresentationExchangeService'
import {
  W3cCredentialService,
  ClaimFormat,
  W3cJsonLdVerifiablePresentation,
  W3cJwtVerifiablePresentation,
} from '../../../vc'
import { ProofFormatSpec } from '../../models'

const PRESENTATION_EXCHANGE_PRESENTATION_PROPOSAL = 'dif/presentation-exchange/definitions@v1.0'
const PRESENTATION_EXCHANGE_PRESENTATION_REQUEST = 'dif/presentation-exchange/definitions@v1.0'
const PRESENTATION_EXCHANGE_PRESENTATION = 'dif/presentation-exchange/submission@v1.0'

export class PresentationExchangeProofFormatService implements ProofFormatService<PresentationExchangeProofFormat> {
  public readonly formatKey = 'presentationExchange' as const

  private presentationExchangeService(agentContext: AgentContext) {
    if (!agentContext.dependencyManager.isRegistered(PresentationExchangeService)) {
      throw new AriesFrameworkError(
        'PresentationExchangeService is not registered on the Agent. Please provide the PresentationExchangeModule as a module on the agent'
      )
    }

    return agentContext.dependencyManager.resolve(PresentationExchangeService)
  }

  public supportsFormat(formatIdentifier: string): boolean {
    return [
      PRESENTATION_EXCHANGE_PRESENTATION_PROPOSAL,
      PRESENTATION_EXCHANGE_PRESENTATION_REQUEST,
      PRESENTATION_EXCHANGE_PRESENTATION,
    ].includes(formatIdentifier)
  }

  public async createProposal(
    agentContext: AgentContext,
    { proofFormats, attachmentId }: ProofFormatCreateProposalOptions<PresentationExchangeProofFormat>
  ): Promise<ProofFormatCreateReturn> {
    const ps = this.presentationExchangeService(agentContext)

    const pexFormat = proofFormats.presentationExchange
    if (!pexFormat) {
      throw new AriesFrameworkError('Missing Presentation Exchange format in create proposal attachment format')
    }

    const { presentationDefinition } = pexFormat

    ps.validatePresentationDefinition(presentationDefinition)

    const format = new ProofFormatSpec({ format: PRESENTATION_EXCHANGE_PRESENTATION_PROPOSAL, attachmentId })

    const attachment = this.getFormatData(presentationDefinition, format.attachmentId)

    return { format, attachment }
  }

  public async processProposal(agentContext: AgentContext, { attachment }: ProofFormatProcessOptions): Promise<void> {
    const ps = this.presentationExchangeService(agentContext)
    const proposal = attachment.getDataAsJson<PresentationExchangeProposal>()
    ps.validatePresentationDefinition(proposal)
  }

  public async acceptProposal(
    agentContext: AgentContext,
    {
      attachmentId,
      proposalAttachment,
      proofFormats,
    }: ProofFormatAcceptProposalOptions<PresentationExchangeProofFormat>
  ): Promise<ProofFormatCreateReturn> {
    const ps = this.presentationExchangeService(agentContext)

    const presentationExchangeFormat = proofFormats?.presentationExchange

    const format = new ProofFormatSpec({
      format: PRESENTATION_EXCHANGE_PRESENTATION_REQUEST,
      attachmentId,
    })

    const presentationDefinition = proposalAttachment.getDataAsJson<PresentationExchangeProposal>()
    ps.validatePresentationDefinition(presentationDefinition)

    const attachment = this.getFormatData(
      {
        presentation_definition: presentationDefinition,
        options: {
          // NOTE: we always want to include a challenge to prevent replay attacks
          challenge: presentationExchangeFormat?.options?.challenge ?? (await agentContext.wallet.generateNonce()),
          domain: presentationExchangeFormat?.options?.domain,
        },
      } satisfies PresentationExchangeRequest,
      format.attachmentId
    )

    return { format, attachment }
  }

  public async createRequest(
    agentContext: AgentContext,
    { attachmentId, proofFormats }: FormatCreateRequestOptions<PresentationExchangeProofFormat>
  ): Promise<ProofFormatCreateReturn> {
    const ps = this.presentationExchangeService(agentContext)

    const presentationExchangeFormat = proofFormats.presentationExchange
    if (!presentationExchangeFormat) {
      throw Error('Missing presentation exchange format in create request attachment format')
    }

    const { presentationDefinition, options } = presentationExchangeFormat

    ps.validatePresentationDefinition(presentationDefinition)

    const format = new ProofFormatSpec({
      format: PRESENTATION_EXCHANGE_PRESENTATION_REQUEST,
      attachmentId,
    })

    const attachment = this.getFormatData(
      {
        presentation_definition: presentationDefinition,
        options: {
          // NOTE: we always want to include a challenge to prevent replay attacks
          challenge: options?.challenge ?? (await agentContext.wallet.generateNonce()),
          domain: options?.domain,
        },
      } satisfies PresentationExchangeRequest,
      format.attachmentId
    )

    return { attachment, format }
  }

  public async processRequest(agentContext: AgentContext, { attachment }: ProofFormatProcessOptions): Promise<void> {
    const ps = this.presentationExchangeService(agentContext)
    const { presentation_definition: presentationDefinition } = attachment.getDataAsJson<PresentationExchangeRequest>()
    ps.validatePresentationDefinition(presentationDefinition)
  }

  public async acceptRequest(
    agentContext: AgentContext,
    { attachmentId, requestAttachment, proofFormats }: ProofFormatAcceptRequestOptions<PresentationExchangeProofFormat>
  ): Promise<ProofFormatCreateReturn> {
    const ps = this.presentationExchangeService(agentContext)

    const format = new ProofFormatSpec({
      format: PRESENTATION_EXCHANGE_PRESENTATION,
      attachmentId,
    })

    const { presentation_definition: presentationDefinition, options } =
      requestAttachment.getDataAsJson<PresentationExchangeRequest>()

    const credentials: InputDescriptorToCredentials = proofFormats?.presentationExchange?.credentials ?? {}
    if (Object.keys(credentials).length === 0) {
      const { areRequirementsSatisfied, requirements } = await ps.getCredentialsForRequest(
        agentContext,
        presentationDefinition
      )

      if (!areRequirementsSatisfied) {
        throw new AriesFrameworkError('Requirements of the presentation definition could not be satisfied')
      }

      requirements.forEach((r) => {
        r.submissionEntry.forEach((r) => {
          credentials[r.inputDescriptorId] = r.verifiableCredentials.map((c) => c.credential)
        })
      })
    }

    const presentation = await ps.createPresentation(agentContext, {
      presentationDefinition,
      credentialsForInputDescriptor: credentials,
      challenge: options?.challenge,
      domain: options?.domain,
    })

    if (presentation.verifiablePresentations.length > 1) {
      throw new AriesFrameworkError('Invalid amount of verifiable presentations. Only one is allowed.')
    }

    const firstPresentation = presentation.verifiablePresentations[0]
    const attachmentData = firstPresentation.encoded as PresentationExchangePresentation
    const attachment = this.getFormatData(attachmentData, format.attachmentId)

    return { attachment, format }
  }

  public async processPresentation(
    agentContext: AgentContext,
    { requestAttachment, attachment }: ProofFormatProcessPresentationOptions
  ): Promise<boolean> {
    const ps = this.presentationExchangeService(agentContext)
    const w3cCredentialService = agentContext.dependencyManager.resolve(W3cCredentialService)

    const request = requestAttachment.getDataAsJson<PresentationExchangeRequest>()
    const presentation = attachment.getDataAsJson<PresentationExchangePresentation>()
    let parsedPresentation: W3cVerifiablePresentation

    // TODO: we should probably move this transformation logic into the VC module, so it
    // can be reused in AFJ when we need to go from encoded -> parsed
    if (typeof presentation === 'string') {
      parsedPresentation = W3cJwtVerifiablePresentation.fromSerializedJwt(presentation)
    } else {
      parsedPresentation = JsonTransformer.fromJSON(presentation, W3cJsonLdVerifiablePresentation)
    }

    if (!parsedPresentation.presentationSubmission) {
      agentContext.config.logger.error(
        'Received presentation in PEX proof format without presentation submission. This should not happen.'
      )
      return false
    }

    if (!request.options?.challenge) {
      agentContext.config.logger.error(
        'Received presentation in PEX proof format without challenge. This should not happen.'
      )
      return false
    }

    try {
      ps.validatePresentationDefinition(request.presentation_definition)
      ps.validatePresentationSubmission(parsedPresentation.presentationSubmission)
      ps.validatePresentation(request.presentation_definition, parsedPresentation)

      let verificationResult: W3cVerifyPresentationResult

      // FIXME: for some reason it won't accept the input if it doesn't know
      // whether it's a JWT or JSON-LD VP even though the input is the same.
      // Not sure how to fix
      if (parsedPresentation.claimFormat === ClaimFormat.JwtVp) {
        verificationResult = await w3cCredentialService.verifyPresentation(agentContext, {
          presentation: parsedPresentation,
          challenge: request.options.challenge,
          domain: request.options.domain,
        })
      } else {
        verificationResult = await w3cCredentialService.verifyPresentation(agentContext, {
          presentation: parsedPresentation,
          challenge: request.options.challenge,
          domain: request.options.domain,
        })
      }

      if (!verificationResult.isValid) {
        agentContext.config.logger.error(
          `Received presentation in PEX proof format that could not be verified: ${verificationResult.error}`,
          { verificationResult }
        )
        return false
      }

      return true
    } catch (e) {
      agentContext.config.logger.error(`Failed to verify presentation in PEX proof format service: ${e.message}`, {
        cause: e,
      })
      return false
    }
  }

  public async getCredentialsForRequest(
    agentContext: AgentContext,
    { requestAttachment }: ProofFormatGetCredentialsForRequestOptions<PresentationExchangeProofFormat>
  ) {
    const ps = this.presentationExchangeService(agentContext)
    const { presentation_definition: presentationDefinition } =
      requestAttachment.getDataAsJson<PresentationExchangeRequest>()

    ps.validatePresentationDefinition(presentationDefinition)

    const presentationSubmission = await ps.getCredentialsForRequest(agentContext, presentationDefinition)
    return presentationSubmission
  }

  public async selectCredentialsForRequest(
    agentContext: AgentContext,
    { requestAttachment }: ProofFormatSelectCredentialsForRequestOptions<PresentationExchangeProofFormat>
  ) {
    const ps = this.presentationExchangeService(agentContext)
    const { presentation_definition: presentationDefinition } =
      requestAttachment.getDataAsJson<PresentationExchangeRequest>()

    const credentialsForRequest = await ps.getCredentialsForRequest(agentContext, presentationDefinition)
    return { credentials: ps.selectCredentialsForRequest(credentialsForRequest) }
  }

  public async shouldAutoRespondToProposal(
    _agentContext: AgentContext,
    { requestAttachment, proposalAttachment }: ProofFormatAutoRespondProposalOptions
  ): Promise<boolean> {
    const proposalData = proposalAttachment.getDataAsJson<PresentationExchangeProposal>()
    const requestData = requestAttachment.getDataAsJson<PresentationExchangeRequest>()

    return deepEquality(requestData, proposalData)
  }

  public async shouldAutoRespondToRequest(
    _agentContext: AgentContext,
    { requestAttachment, proposalAttachment }: ProofFormatAutoRespondRequestOptions
  ): Promise<boolean> {
    const proposalData = proposalAttachment.getDataAsJson<PresentationExchangeProposal>()
    const requestData = requestAttachment.getDataAsJson<PresentationExchangeRequest>()

    return deepEquality(requestData, proposalData)
  }
  /**
   *
   * The presentation is already verified in processPresentation, so we can just return true here.
   * It's only an ack, so it's just that we received the presentation.
   *
   */
  public async shouldAutoRespondToPresentation(
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    _agentContext: AgentContext,
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    _options: ProofFormatAutoRespondPresentationOptions
  ): Promise<boolean> {
    return true
  }

  private getFormatData(data: unknown, id: string): Attachment {
    const attachment = new Attachment({
      id,
      mimeType: 'application/json',
      data: new AttachmentData({
        json: data as JsonValue,
      }),
    })

    return attachment
  }
}
