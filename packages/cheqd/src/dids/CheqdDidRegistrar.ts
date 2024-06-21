import type { CheqdNetwork, DIDDocument, DidStdFee, TVerificationKey, VerificationMethods } from '@cheqd/sdk'
import type { SignInfo } from '@cheqd/ts-proto/cheqd/did/v2'
import type {
  AgentContext,
  DidRegistrar,
  DidCreateOptions,
  DidCreateResult,
  DidDeactivateResult,
  DidUpdateResult,
  DidUpdateOptions,
} from '@credo-ts/core'

import { MethodSpecificIdAlgo, createDidVerificationMethod } from '@cheqd/sdk'
import { MsgCreateResourcePayload } from '@cheqd/ts-proto/cheqd/resource/v2'
import {
  DidDocument,
  DidDocumentRole,
  DidRecord,
  DidRepository,
  KeyType,
  Buffer,
  isValidPrivateKey,
  utils,
  TypedArrayEncoder,
  getKeyFromVerificationMethod,
  JsonTransformer,
  VerificationMethod,
} from '@credo-ts/core'

import { parseCheqdDid } from '../anoncreds/utils/identifiers'
import { CheqdLedgerService } from '../ledger'

import {
  createMsgCreateDidDocPayloadToSign,
  generateDidDoc,
  validateSpecCompliantPayload,
  createMsgDeactivateDidDocPayloadToSign,
} from './didCheqdUtil'

export class CheqdDidRegistrar implements DidRegistrar {
  public readonly supportedMethods = ['cheqd']

  public async create(agentContext: AgentContext, options: CheqdDidCreateOptions): Promise<DidCreateResult> {
    const didRepository = agentContext.dependencyManager.resolve(DidRepository)
    const cheqdLedgerService = agentContext.dependencyManager.resolve(CheqdLedgerService)

    let didDocument: DidDocument
    const versionId = options.options?.versionId ?? utils.uuid()

    try {
      if (options.didDocument && validateSpecCompliantPayload(options.didDocument)) {
        didDocument = options.didDocument

        const cheqdDid = parseCheqdDid(options.didDocument.id)
        if (!cheqdDid) {
          return {
            didDocumentMetadata: {},
            didRegistrationMetadata: {},
            didState: {
              state: 'failed',
              reason: `Unable to parse cheqd did ${options.didDocument.id}`,
            },
          }
        }
      } else if (options.secret?.verificationMethod) {
        const withoutDidDocumentOptions = options as CheqdDidCreateWithoutDidDocumentOptions
        const verificationMethod = withoutDidDocumentOptions.secret.verificationMethod
        const methodSpecificIdAlgo = withoutDidDocumentOptions.options.methodSpecificIdAlgo
        const privateKey = verificationMethod.privateKey
        if (privateKey && !isValidPrivateKey(privateKey, KeyType.Ed25519)) {
          return {
            didDocumentMetadata: {},
            didRegistrationMetadata: {},
            didState: {
              state: 'failed',
              reason: 'Invalid private key provided',
            },
          }
        }

        const key = await agentContext.wallet.createKey({
          keyType: KeyType.Ed25519,
          privateKey: privateKey,
        })

        didDocument = generateDidDoc({
          verificationMethod: verificationMethod.type as VerificationMethods,
          verificationMethodId: verificationMethod.id || 'key-1',
          methodSpecificIdAlgo: (methodSpecificIdAlgo as MethodSpecificIdAlgo) || MethodSpecificIdAlgo.Uuid,
          network: withoutDidDocumentOptions.options.network as CheqdNetwork,
          publicKey: TypedArrayEncoder.toHex(key.publicKey),
        })

        const contextMapping = {
          Ed25519VerificationKey2018: 'https://w3id.org/security/suites/ed25519-2018/v1',
          Ed25519VerificationKey2020: 'https://w3id.org/security/suites/ed25519-2020/v1',
          JsonWebKey2020: 'https://w3id.org/security/suites/jws-2020/v1',
        }
        const contextUrl = contextMapping[verificationMethod.type]

        // Add the context to the did document
        // NOTE: cheqd sdk uses https://www.w3.org/ns/did/v1 while Credo did doc uses https://w3id.org/did/v1
        // We should align these at some point. For now we just return a consistent value.
        didDocument.context = ['https://www.w3.org/ns/did/v1', contextUrl]
      } else {
        return {
          didDocumentMetadata: {},
          didRegistrationMetadata: {},
          didState: {
            state: 'failed',
            reason: 'Provide a didDocument or at least one verificationMethod with seed in secret',
          },
        }
      }

      const didDocumentJson = didDocument.toJSON() as DIDDocument

      const payloadToSign = await createMsgCreateDidDocPayloadToSign(didDocumentJson, versionId)
      const signInputs = await this.signPayload(agentContext, payloadToSign, didDocument.verificationMethod)

      const response = await cheqdLedgerService.create(didDocumentJson, signInputs, versionId)
      if (response.code !== 0) {
        throw new Error(`${response.rawLog}`)
      }

      // Save the did so we know we created it and can issue with it
      const didRecord = new DidRecord({
        did: didDocument.id,
        role: DidDocumentRole.Created,
        didDocument,
      })
      await didRepository.save(agentContext, didRecord)

      return {
        didDocumentMetadata: {},
        didRegistrationMetadata: {},
        didState: {
          state: 'finished',
          did: didDocument.id,
          didDocument,
          secret: options.secret,
        },
      }
    } catch (error) {
      agentContext.config.logger.error(`Error registering DID`, error)
      return {
        didDocumentMetadata: {},
        didRegistrationMetadata: {},
        didState: {
          state: 'failed',
          reason: `unknownError: ${error.message}`,
        },
      }
    }
  }

  public async update(agentContext: AgentContext, options: CheqdDidUpdateOptions): Promise<DidUpdateResult> {
    const didRepository = agentContext.dependencyManager.resolve(DidRepository)
    const cheqdLedgerService = agentContext.dependencyManager.resolve(CheqdLedgerService)

    const versionId = options.options?.versionId || utils.uuid()
    const verificationMethod = options.secret?.verificationMethod
    let didDocument: DidDocument
    let didRecord: DidRecord | null

    try {
      if (options.didDocument && validateSpecCompliantPayload(options.didDocument)) {
        didDocument = options.didDocument
        const resolvedDocument = await cheqdLedgerService.resolve(didDocument.id)
        didRecord = await didRepository.findCreatedDid(agentContext, didDocument.id)
        if (!resolvedDocument.didDocument || resolvedDocument.didDocumentMetadata.deactivated || !didRecord) {
          return {
            didDocumentMetadata: {},
            didRegistrationMetadata: {},
            didState: {
              state: 'failed',
              reason: 'Did not found',
            },
          }
        }

        if (verificationMethod) {
          const privateKey = verificationMethod.privateKey
          if (privateKey && !isValidPrivateKey(privateKey, KeyType.Ed25519)) {
            return {
              didDocumentMetadata: {},
              didRegistrationMetadata: {},
              didState: {
                state: 'failed',
                reason: 'Invalid private key provided',
              },
            }
          }

          const key = await agentContext.wallet.createKey({
            keyType: KeyType.Ed25519,
            privateKey: privateKey,
          })

          didDocument.verificationMethod?.concat(
            JsonTransformer.fromJSON(
              createDidVerificationMethod(
                [verificationMethod.type as VerificationMethods],
                [
                  {
                    methodSpecificId: didDocument.id.split(':')[3],
                    didUrl: didDocument.id,
                    keyId: `${didDocument.id}#${verificationMethod.id}`,
                    publicKey: TypedArrayEncoder.toHex(key.publicKey),
                  },
                ]
              ),
              VerificationMethod
            )
          )
        }
      } else {
        return {
          didDocumentMetadata: {},
          didRegistrationMetadata: {},
          didState: {
            state: 'failed',
            reason: 'Provide a valid didDocument',
          },
        }
      }

      const payloadToSign = await createMsgCreateDidDocPayloadToSign(didDocument as DIDDocument, versionId)
      const signInputs = await this.signPayload(agentContext, payloadToSign, didDocument.verificationMethod)

      const response = await cheqdLedgerService.update(didDocument as DIDDocument, signInputs, versionId)
      if (response.code !== 0) {
        throw new Error(`${response.rawLog}`)
      }

      // Save the did so we know we created it and can issue with it
      didRecord.didDocument = didDocument
      await didRepository.update(agentContext, didRecord)

      return {
        didDocumentMetadata: {},
        didRegistrationMetadata: {},
        didState: {
          state: 'finished',
          did: didDocument.id,
          didDocument,
          secret: options.secret,
        },
      }
    } catch (error) {
      agentContext.config.logger.error(`Error updating DID`, error)
      return {
        didDocumentMetadata: {},
        didRegistrationMetadata: {},
        didState: {
          state: 'failed',
          reason: `unknownError: ${error.message}`,
        },
      }
    }
  }

  public async deactivate(
    agentContext: AgentContext,
    options: CheqdDidDeactivateOptions
  ): Promise<DidDeactivateResult> {
    const didRepository = agentContext.dependencyManager.resolve(DidRepository)
    const cheqdLedgerService = agentContext.dependencyManager.resolve(CheqdLedgerService)

    const did = options.did
    const versionId = options.options?.versionId || utils.uuid()

    try {
      const { didDocument, didDocumentMetadata } = await cheqdLedgerService.resolve(did)

      const didRecord = await didRepository.findCreatedDid(agentContext, did)
      if (!didDocument || didDocumentMetadata.deactivated || !didRecord) {
        return {
          didDocumentMetadata: {},
          didRegistrationMetadata: {},
          didState: {
            state: 'failed',
            reason: 'Did not found',
          },
        }
      }
      const payloadToSign = createMsgDeactivateDidDocPayloadToSign(didDocument, versionId)
      const didDocumentInstance = JsonTransformer.fromJSON(didDocument, DidDocument)
      const signInputs = await this.signPayload(agentContext, payloadToSign, didDocumentInstance.verificationMethod)
      const response = await cheqdLedgerService.deactivate(didDocument, signInputs, versionId)
      if (response.code !== 0) {
        throw new Error(`${response.rawLog}`)
      }

      await didRepository.update(agentContext, didRecord)

      return {
        didDocumentMetadata: {},
        didRegistrationMetadata: {},
        didState: {
          state: 'finished',
          did: didDocument.id,
          didDocument: JsonTransformer.fromJSON(didDocument, DidDocument),
          secret: options.secret,
        },
      }
    } catch (error) {
      agentContext.config.logger.error(`Error deactivating DID`, error)
      return {
        didDocumentMetadata: {},
        didRegistrationMetadata: {},
        didState: {
          state: 'failed',
          reason: `unknownError: ${error.message}`,
        },
      }
    }
  }

  public async createResource(agentContext: AgentContext, did: string, resource: CheqdCreateResourceOptions) {
    const didRepository = agentContext.dependencyManager.resolve(DidRepository)
    const cheqdLedgerService = agentContext.dependencyManager.resolve(CheqdLedgerService)
    const { didDocument, didDocumentMetadata } = await cheqdLedgerService.resolve(did)
    const didRecord = await didRepository.findCreatedDid(agentContext, did)
    if (!didDocument || didDocumentMetadata.deactivated || !didRecord) {
      return {
        resourceMetadata: {},
        resourceRegistrationMetadata: {},
        resourceState: {
          state: 'failed',
          reason: `DID: ${did} not found`,
        },
      }
    }

    try {
      let data: Uint8Array
      if (typeof resource.data === 'string') {
        data = TypedArrayEncoder.fromBase64(resource.data)
      } else if (typeof resource.data == 'object') {
        data = TypedArrayEncoder.fromString(JSON.stringify(resource.data))
      } else {
        data = resource.data
      }

      const resourcePayload = MsgCreateResourcePayload.fromPartial({
        collectionId: did.split(':')[3],
        id: resource.id,
        resourceType: resource.resourceType,
        name: resource.name,
        version: resource.version,
        alsoKnownAs: resource.alsoKnownAs,
        data,
      })
      const payloadToSign = MsgCreateResourcePayload.encode(resourcePayload).finish()

      const didDocumentInstance = JsonTransformer.fromJSON(didDocument, DidDocument)
      const signInputs = await this.signPayload(agentContext, payloadToSign, didDocumentInstance.verificationMethod)
      const response = await cheqdLedgerService.createResource(did, resourcePayload, signInputs)
      if (response.code !== 0) {
        throw new Error(`${response.rawLog}`)
      }

      return {
        resourceMetadata: {},
        resourceRegistrationMetadata: {},
        resourceState: {
          state: 'finished',
          resourceId: resourcePayload.id,
          resource: resourcePayload,
        },
      }
    } catch (error) {
      return {
        resourceMetadata: {},
        resourceRegistrationMetadata: {},
        resourceState: {
          state: 'failed',
          reason: `unknownError: ${error.message}`,
        },
      }
    }
  }

  private async signPayload(
    agentContext: AgentContext,
    payload: Uint8Array,
    verificationMethod: VerificationMethod[] = []
  ) {
    return await Promise.all(
      verificationMethod.map(async (method) => {
        const key = getKeyFromVerificationMethod(method)
        return {
          verificationMethodId: method.id,
          signature: await agentContext.wallet.sign({ data: Buffer.from(payload), key }),
        } satisfies SignInfo
      })
    )
  }
}

export interface CheqdDidCreateWithoutDidDocumentOptions extends DidCreateOptions {
  method: 'cheqd'
  did?: undefined
  didDocument?: undefined
  options: {
    network: `${CheqdNetwork}`
    fee?: DidStdFee
    versionId?: string
    methodSpecificIdAlgo?: `${MethodSpecificIdAlgo}`
  }
  secret: {
    verificationMethod: IVerificationMethod
  }
}

export interface CheqdDidCreateFromDidDocumentOptions extends DidCreateOptions {
  method: 'cheqd'
  did?: undefined
  didDocument: DidDocument
  options?: {
    fee?: DidStdFee
    versionId?: string
  }
}

export type CheqdDidCreateOptions = CheqdDidCreateFromDidDocumentOptions | CheqdDidCreateWithoutDidDocumentOptions

export interface CheqdDidUpdateOptions extends DidUpdateOptions {
  did: string
  didDocument: DidDocument
  options: {
    fee?: DidStdFee
    versionId?: string
  }
  secret?: {
    verificationMethod: IVerificationMethod
  }
}

export interface CheqdDidDeactivateOptions extends DidCreateOptions {
  method: 'cheqd'
  did: string
  options: {
    fee?: DidStdFee
    versionId?: string
  }
}

export interface CheqdCreateResourceOptions extends Omit<Partial<MsgCreateResourcePayload>, 'data'> {
  data: string | Uint8Array | object
}

interface IVerificationMethod {
  type: `${VerificationMethods}`
  id: TVerificationKey<string, number>
  privateKey?: Buffer
}
