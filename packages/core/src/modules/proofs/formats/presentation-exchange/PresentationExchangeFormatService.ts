import type { W3cCredential } from '../../../vc/models'
import type { SignPresentationOptions } from '../../../vc/models/W3cCredentialServiceOptions'
import type {
  AutoSelectCredentialOptions,
  ProofRequestFormats,
  RequestedCredentialsFormats,
} from '../../models/SharedOptions'
import type { GetRequestedCredentialsFormat } from '../IndyProofFormatsServiceOptions'
import type { ProofAttachmentFormat } from '../models/ProofAttachmentFormat'
import type {
  CreatePresentationFormatsOptions,
  CreatePresentationOptions,
  CreateProposalOptions,
  CreateRequestAsResponseOptions,
  CreateRequestOptions,
  ProcessPresentationOptions,
  ProcessProposalOptions,
} from '../models/ProofFormatServiceOptions'
import type { InputDescriptorsSchemaOptions, SchemaOptions } from './models'

import { BbsBlsSignature2020 } from '@mattrglobal/jsonld-signatures-bbs'
import { Lifecycle, scoped } from 'tsyringe'

import { AgentConfig } from '../../../../agent/AgentConfig'
import { Attachment, AttachmentData } from '../../../../decorators/attachment/Attachment'
import { AriesFrameworkError } from '../../../../error'
import { DidCommMessageRepository } from '../../../../storage/didcomm/DidCommMessageRepository'
import { JsonTransformer } from '../../../../utils'
import { uuid } from '../../../../utils/uuid'
import { IndyHolderService, IndyVerifierService, IndyRevocationService } from '../../../indy'
import { IndyLedgerService } from '../../../ledger'
import { W3cCredentialService } from '../../../vc'
import { W3cVerifiableCredential } from '../../../vc/models'
import { LinkedDataProof } from '../../../vc/models/LinkedDataProof'
import { ProofFormatService } from '../ProofFormatService'
import {
  V2_PRESENTATION_EXCHANGE_PRESENTATION,
  V2_PRESENTATION_EXCHANGE_PRESENTATION_PROPOSAL,
  V2_PRESENTATION_EXCHANGE_PRESENTATION_REQUEST,
} from '../ProofFormats'
import { ProofFormatSpec } from '../models/ProofFormatSpec'

import { InputDescriptors, InputDescriptorsSchema } from './models'
import { ClaimFormatSchema, PresentationDefinition, RequestPresentation } from './models/RequestPresentation'

@scoped(Lifecycle.ContainerScoped)
export class PresentationExchangeFormatService extends ProofFormatService {
  private indyHolderService: IndyHolderService
  private indyVerifierService: IndyVerifierService
  private indyRevocationService: IndyRevocationService
  private ledgerService: IndyLedgerService
  private w3cCredentialService: W3cCredentialService

  public constructor(
    agentConfig: AgentConfig,
    indyHolderService: IndyHolderService,
    indyVerifierService: IndyVerifierService,
    indyRevocationService: IndyRevocationService,
    ledgerService: IndyLedgerService,
    didCommMessageRepository: DidCommMessageRepository,
    w3cCredentialService: W3cCredentialService
  ) {
    super(didCommMessageRepository, agentConfig)
    this.indyHolderService = indyHolderService
    this.indyVerifierService = indyVerifierService
    this.indyRevocationService = indyRevocationService
    this.ledgerService = ledgerService
    this.w3cCredentialService = w3cCredentialService
  }

  public async createProofRequestFromProposal(options: CreatePresentationFormatsOptions): Promise<ProofRequestFormats> {
    const inputDescriptorsJson = options.presentationAttachment.getDataAsJson<InputDescriptorsSchema>() ?? null

    const presentationDefinition: PresentationDefinition = new PresentationDefinition({
      inputDescriptors: inputDescriptorsJson['input_descriptors'],
      format: {
        ldpVc: {
          proofType: ['Ed25519Signature2018'],
        },
      },
    })

    const presentationExchangeRequestMessage: RequestPresentation = new RequestPresentation({
      options: {
        challenge: '',
        domain: '',
      },
      presentationDefinition: presentationDefinition,
    })

    return {
      presentationExchange: presentationExchangeRequestMessage,
    }
  }

  public createProposal(options: CreateProposalOptions): Promise<ProofAttachmentFormat> {
    throw new Error('Method not implemented.')
  }

  public processProposal(options: ProcessProposalOptions): void {
    throw new Error('Method not implemented.')
  }

  public async createRequest(options: CreateRequestOptions): Promise<ProofAttachmentFormat> {
    if (!options.formats.presentationExchange) {
      throw Error('Presentation Exchange format missing')
    }

    const presentationDefinition = JsonTransformer.fromJSON(
      options.formats.presentationExchange,
      PresentationDefinition
    )

    if (!presentationDefinition.inputDescriptors) {
      throw Error('Input Descriptor missing while creating the request in presentation exchange service.')
    }

    const inputDescriptorsSchemaOptions: InputDescriptorsSchemaOptions = {
      inputDescriptors: presentationDefinition.inputDescriptors,
    }

    const proposalInputDescriptor = new InputDescriptorsSchema(inputDescriptorsSchemaOptions)
    const attachId = options.attachId ?? uuid()

    const format = new ProofFormatSpec({
      attachmentId: attachId,
      format: V2_PRESENTATION_EXCHANGE_PRESENTATION_REQUEST,
    })

    const attachment = new Attachment({
      id: attachId,
      mimeType: 'application/json',
      data: new AttachmentData({
        json: proposalInputDescriptor.toJSON(),
      }),
    })

    return { format, attachment }
  }

  public async createRequestAsResponse(options: CreateRequestAsResponseOptions): Promise<ProofAttachmentFormat> {
    if (!options.formats.presentationExchange) {
      throw Error('Presentation Exchange format missing while creating proof request as response.')
    }

    if (!options.formats.presentationExchange) {
      throw Error('Input Descriptor missing while creating proof request as response.')
    }

    const presentationExchangeRequestMessage: RequestPresentation = new RequestPresentation({
      options: options.formats.presentationExchange.options,
      presentationDefinition: options.formats.presentationExchange.presentationDefinition,
    })

    const attachId = options.attachId ?? uuid()

    const format = new ProofFormatSpec({
      attachmentId: attachId,
      format: V2_PRESENTATION_EXCHANGE_PRESENTATION_REQUEST,
    })

    const attachment = new Attachment({
      id: attachId,
      mimeType: 'application/json',
      data: new AttachmentData({
        json: presentationExchangeRequestMessage.toJSON(),
      }),
    })

    return { format, attachment }
  }

  public async createPresentation(options: CreatePresentationOptions): Promise<ProofAttachmentFormat> {
    if (!options.formats.presentationExchange) {
      throw Error('Presentation Exchange format missing while creating presentation in presentation exchange service.')
    }

    console.log('options in PE service to createPresentation', JSON.stringify(options, null, 2))

    const w3cVerifiableCredentials = JsonTransformer.fromJSON(
      options.formats.presentationExchange,
      W3cVerifiableCredential
    )

    const proof = JsonTransformer.fromJSON(w3cVerifiableCredentials.proof, LinkedDataProof)

    console.log('w3cVerifiableCredentials', JSON.stringify(w3cVerifiableCredentials, null, 2))

    const presentation = await this.w3cCredentialService.createPresentation({
      credentials: w3cVerifiableCredentials,
    })

    console.log('presentation:::\n', JSON.stringify(presentation, null, 2))

    const signPresentationOptions: SignPresentationOptions = {
      presentation,
      purpose: proof.proofPurpose,
      signatureType: proof.type,
      verificationMethod: proof.verificationMethod,
    }
    console.log('signPresentationOptions:\n', JSON.stringify(signPresentationOptions, null, 2))

    const signedPresentation = await this.w3cCredentialService.signPresentation(signPresentationOptions)
    console.log('signedPresentation:::\n', signedPresentation)

    const attachId = options.attachId ?? uuid()

    const format = new ProofFormatSpec({
      attachmentId: attachId,
      format: V2_PRESENTATION_EXCHANGE_PRESENTATION,
    })

    const attachment = new Attachment({
      id: attachId,
      mimeType: 'application/json',
      data: new AttachmentData({
        json: presentation.toJSON(),
      }),
    })

    return { format, attachment }
  }

  public async processPresentation(options: ProcessPresentationOptions): Promise<boolean> {
    throw new Error('Method not implemented.')
  }

  public async getRequestedCredentialsForProofRequest(
    options: GetRequestedCredentialsFormat
  ): Promise<AutoSelectCredentialOptions> {
    const requestMessageJson = options.attachment.getDataAsJson<RequestPresentation>()
    const requestMessage = JsonTransformer.fromJSON(requestMessageJson, RequestPresentation)
    const presentationDefinition = JsonTransformer.fromJSON(
      requestMessage.presentationDefinition,
      PresentationDefinition
    )

    const claimFormat = JsonTransformer.fromJSON(presentationDefinition.format, ClaimFormatSchema)

    let credentialsList: W3cCredential[] = []
    // const claimFormat = presentationDefinition.format
    let difHandlerProofType
    for (const inputDescriptor of presentationDefinition.inputDescriptors) {
      let proofType: string[] = []
      const limitDisclosure = inputDescriptor.constraints.limitDisclosure

      const uriList = []
      // const oneOfUriGroups = []

      // if (inputDescriptor.schema['oneOf_filter']) {
      //   oneOfUriGroups.push(await this.retrieveUriListFromSchemaFilter(inputDescriptor.schema['uri_groups']))
      // } else {
      const schemaUris = inputDescriptor.schema[0]
      uriList.push(schemaUris.uri)
      // }

      if (uriList.length === 0) {
        uriList.splice(0)
      }
      // if (oneOfUriGroups.length === 0) {
      //   oneOfUriGroups.splice(0)
      // }
      if (limitDisclosure) {
        proofType = BbsBlsSignature2020.proofType
        difHandlerProofType = BbsBlsSignature2020.proofType
      }

      // if (claimFormat) {
      //   if (claimFormat.ldpVp) {
      //     if (proofType.includes()) {

      //     }
      //   }
      // }
      const searched = await this.w3cCredentialService.findCredentialByQuery({ contexts: uriList })

      // TODO pex select

      if (!searched) {
        throw new AriesFrameworkError('No credential found')
      }

      credentialsList = searched
    }
    return {
      presentationExchange: credentialsList,
    }
  }

  public async autoSelectCredentialsForProofRequest(
    options: AutoSelectCredentialOptions
  ): Promise<RequestedCredentialsFormats> {
    const presentationExchange = options.presentationExchange

    if (!presentationExchange) {
      throw new AriesFrameworkError('No presentation options provided')
    }

    return {
      presentationExchange: await presentationExchange[0],
    }
    // throw new Error('Method not implemented.')
  }

  public proposalAndRequestAreEqual(
    proposalAttachments: ProofAttachmentFormat[],
    requestAttachments: ProofAttachmentFormat[]
  ): boolean {
    throw new Error('Method not implemented.')
  }

  public supportsFormat(formatIdentifier: string): boolean {
    const supportedFormats = [
      V2_PRESENTATION_EXCHANGE_PRESENTATION_PROPOSAL,
      V2_PRESENTATION_EXCHANGE_PRESENTATION_REQUEST,
      V2_PRESENTATION_EXCHANGE_PRESENTATION,
    ]
    return supportedFormats.includes(formatIdentifier)
  }

  private async retrieveUriListFromSchemaFilter(schemaUriGroups: SchemaOptions[][]): Promise<string[]> {
    // Retrieve list of schema uri from uri_group.
    const groupSchemaUriList = []

    for (const schemaGroup of schemaUriGroups) {
      const uriList = []
      for (const schema in schemaGroup) {
        uriList.push(schema)
      }
      if (uriList.length > 0) {
        groupSchemaUriList.push(uriList)
      }
    }
    return ['']
  }
}
