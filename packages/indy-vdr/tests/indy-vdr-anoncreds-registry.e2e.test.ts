import type { IndyVdrDidCreateOptions, IndyVdrDidCreateResult } from '../src/dids/IndyVdrIndyDidRegistrar'

import {
  getUnqualifiedRevocationRegistryDefinitionId,
  parseIndyDid,
  parseIndyRevocationRegistryId,
} from '@credo-ts/anoncreds'
import { Agent, DidsModule, TypedArrayEncoder } from '@credo-ts/core'
import { indyVdr } from '@hyperledger/indy-vdr-nodejs'

import { getInMemoryAgentOptions, importExistingIndyDidFromPrivateKey } from '../../core/tests/helpers'
import { IndyVdrIndyDidResolver, IndyVdrModule, IndyVdrSovDidResolver } from '../src'
import { IndyVdrAnonCredsRegistry } from '../src/anoncreds/IndyVdrAnonCredsRegistry'
import { IndyVdrIndyDidRegistrar } from '../src/dids/IndyVdrIndyDidRegistrar'
import { IndyVdrPoolService } from '../src/pool'

import { credentialDefinitionValue, revocationRegistryDefinitionValue } from './__fixtures__/anoncreds'
import { indyVdrModuleConfig } from './helpers'

const indyVdrAnonCredsRegistry = new IndyVdrAnonCredsRegistry()

const endorser = new Agent(
  getInMemoryAgentOptions(
    'IndyVdrAnonCredsRegistryEndorser',
    {},
    {
      indyVdr: new IndyVdrModule({
        indyVdr,
        networks: indyVdrModuleConfig.networks,
      }),
      dids: new DidsModule({
        registrars: [new IndyVdrIndyDidRegistrar()],
        resolvers: [new IndyVdrSovDidResolver(), new IndyVdrIndyDidResolver()],
      }),
    }
  )
)

const agent = new Agent(
  getInMemoryAgentOptions(
    'IndyVdrAnonCredsRegistryAgent',
    {},
    {
      indyVdr: new IndyVdrModule({
        indyVdr,
        networks: indyVdrModuleConfig.networks,
      }),
      dids: new DidsModule({
        registrars: [new IndyVdrIndyDidRegistrar()],
        resolvers: [new IndyVdrSovDidResolver(), new IndyVdrIndyDidResolver()],
      }),
    }
  )
)

const indyVdrPoolService = endorser.dependencyManager.resolve(IndyVdrPoolService)

// FIXME: this test is very slow, probably due to the sleeps. Can we speed it up?
describe('IndyVdrAnonCredsRegistry', () => {
  let endorserDid: string
  let agentDid: string
  beforeAll(async () => {
    await endorser.initialize()
    await agent.initialize()
    const unqualifiedSubmitterDid = await importExistingIndyDidFromPrivateKey(
      endorser,
      TypedArrayEncoder.fromString('00000000000000000000000Endorser9')
    )
    endorserDid = `did:indy:pool:localtest:${unqualifiedSubmitterDid}`
    const agentUnqualifiedSubmitterDid = await importExistingIndyDidFromPrivateKey(
      agent,
      TypedArrayEncoder.fromString('00000000000000000000000Endorser9')
    )
    agentDid = `did:indy:pool:localtest:${agentUnqualifiedSubmitterDid}`
  })

  afterAll(async () => {
    for (const pool of indyVdrPoolService.pools) {
      pool.close()
    }

    await endorser.shutdown()
    await endorser.wallet.delete()
    await agent.shutdown()
    await agent.wallet.delete()
  })

  test('register and resolve a schema and credential definition (internal, issuerDid != endorserDid)', async () => {
    const didCreateResult = (await endorser.dids.create<IndyVdrDidCreateOptions>({
      method: 'indy',
      options: {
        endorserMode: 'internal',
        endorserDid,
      },
    })) as IndyVdrDidCreateResult

    if (didCreateResult.didState.state !== 'finished') throw Error('did was not successfully created')

    const didIndyIssuerId = didCreateResult.didState.did
    const { namespaceIdentifier: legacyIssuerId } = parseIndyDid(didIndyIssuerId)
    const dynamicVersion = `1.${Math.random() * 100}`
    const legacySchemaId = `${legacyIssuerId}:2:test:${dynamicVersion}`
    const didIndySchemaId = `did:indy:pool:localtest:${legacyIssuerId}/anoncreds/v0/SCHEMA/test/${dynamicVersion}`

    const schemaResult = await indyVdrAnonCredsRegistry.registerSchema(endorser.context, {
      options: {
        endorserMode: 'internal',
        endorserDid,
      },
      schema: {
        attrNames: ['age'],
        issuerId: didIndyIssuerId,
        name: 'test',
        version: dynamicVersion,
      },
    })
    const schemaSeqNo = schemaResult.schemaMetadata.indyLedgerSeqNo as number

    expect(schemaResult).toMatchObject({
      schemaState: {
        state: 'finished',
        schema: {
          attrNames: ['age'],
          issuerId: didIndyIssuerId,
          name: 'test',
          version: dynamicVersion,
        },
        schemaId: didIndySchemaId,
      },
      registrationMetadata: {},
      schemaMetadata: {
        indyLedgerSeqNo: expect.any(Number),
      },
    })

    // Wait some time before resolving credential definition object
    await new Promise((res) => setTimeout(res, 1000))

    const legacySchema = await indyVdrAnonCredsRegistry.getSchema(endorser.context, legacySchemaId)
    expect(legacySchema).toMatchObject({
      schema: {
        attrNames: ['age'],
        name: 'test',
        version: dynamicVersion,
        issuerId: legacyIssuerId,
      },
      schemaId: legacySchemaId,
      resolutionMetadata: {},
      schemaMetadata: {
        didIndyNamespace: 'pool:localtest',
        indyLedgerSeqNo: expect.any(Number),
      },
    })

    // Resolve using did indy schema id
    const didIndySchema = await indyVdrAnonCredsRegistry.getSchema(endorser.context, didIndySchemaId)
    expect(didIndySchema).toMatchObject({
      schema: {
        attrNames: ['age'],
        name: 'test',
        version: dynamicVersion,
        issuerId: didIndyIssuerId,
      },
      schemaId: didIndySchemaId,
      resolutionMetadata: {},
      schemaMetadata: {
        didIndyNamespace: 'pool:localtest',
        indyLedgerSeqNo: expect.any(Number),
      },
    })

    const legacyCredentialDefinitionId = `${legacyIssuerId}:3:CL:${schemaSeqNo}:TAG`
    const didIndyCredentialDefinitionId = `did:indy:pool:localtest:${legacyIssuerId}/anoncreds/v0/CLAIM_DEF/${schemaSeqNo}/TAG`
    const credentialDefinitionResult = await indyVdrAnonCredsRegistry.registerCredentialDefinition(endorser.context, {
      credentialDefinition: {
        issuerId: didIndyIssuerId,
        tag: 'TAG',
        schemaId: didIndySchemaId,
        type: 'CL',
        value: credentialDefinitionValue,
      },
      options: {
        endorserMode: 'internal',
        endorserDid: endorserDid,
      },
    })

    expect(credentialDefinitionResult).toMatchObject({
      credentialDefinitionMetadata: {},
      credentialDefinitionState: {
        credentialDefinition: {
          issuerId: didIndyIssuerId,
          tag: 'TAG',
          schemaId: didIndySchemaId,
          type: 'CL',
          value: credentialDefinitionValue,
        },
        credentialDefinitionId: didIndyCredentialDefinitionId,
        state: 'finished',
      },
      registrationMetadata: {},
    })

    // Wait some time before resolving credential definition object
    await new Promise((res) => setTimeout(res, 1000))

    const legacyCredentialDefinition = await indyVdrAnonCredsRegistry.getCredentialDefinition(
      endorser.context,
      legacyCredentialDefinitionId
    )

    expect(legacyCredentialDefinition).toMatchObject({
      credentialDefinitionId: legacyCredentialDefinitionId,
      credentialDefinition: {
        issuerId: legacyIssuerId,
        schemaId: legacySchemaId,
        tag: 'TAG',
        type: 'CL',
        value: credentialDefinitionValue,
      },
      credentialDefinitionMetadata: {
        didIndyNamespace: 'pool:localtest',
      },
      resolutionMetadata: {},
    })

    // resolve using did indy credential definition id
    const didIndyCredentialDefinition = await indyVdrAnonCredsRegistry.getCredentialDefinition(
      endorser.context,
      didIndyCredentialDefinitionId
    )

    expect(didIndyCredentialDefinition).toMatchObject({
      credentialDefinitionId: didIndyCredentialDefinitionId,
      credentialDefinition: {
        issuerId: didIndyIssuerId,
        schemaId: didIndySchemaId,
        tag: 'TAG',
        type: 'CL',
        value: credentialDefinitionValue,
      },
      credentialDefinitionMetadata: {
        didIndyNamespace: 'pool:localtest',
      },
      resolutionMetadata: {},
    })

    const {
      revocationRegistryDefinitionState: { revocationRegistryDefinitionId: didIndyRevocationRegistryDefinitionId },
    } = await indyVdrAnonCredsRegistry.registerRevocationRegistryDefinition(endorser.context, {
      revocationRegistryDefinition: {
        tag: 'REV_TAG',
        issuerId: didIndyIssuerId,
        credDefId: didIndyCredentialDefinitionId,
        revocDefType: 'CL_ACCUM',
        value: {
          maxCredNum: 100,
          publicKeys: {
            accumKey: {
              z: '1 1812B206EB395D3AEBD4BBF53EBB0FFC3371D8BD6175316AB32C1C5F65452051 1 22A079D49C5351EFDC1410C81A1F6D8B2E3B79CFF20A30690C118FE2050F72CB 1 0FFC28B923A4654E261DB4CB5B9BABEFCB4DB189B20F52412B0CC9CCCBB8A3B2 1 1EE967C43EF1A3F487061D21B07076A26C126AAF7712E7B5CF5A53688DDD5CC0 1 009ED4D65879CA81DA8227D34CEA3B759B4627E1E2FFB273E9645CD4F3B10F19 1 1CF070212E1E213AEB472F56EDFC9D48009796C77B2D8CC16F2836E37B8715C2 1 04954F0B7B468781BAAE3291DD0E6FFA7F1AF66CAA4094D37B24363CC34606FB 1 115367CB755E9DB18781B3825CB1AEE2C334558B2C038E13DF57BB57CE1CF847 1 110D37EC05862EE2757A7DF39E814876FC97376FF8105D2D29619CB575537BDE 1 13C559A9563FCE083B3B39AE7E8FCA4099BEF3A4C8C6672E543D521F9DA88F96 1 137D87CC22ACC1B6B8C20EABE59F6ED456A58FE4CBEEFDFC4FA9B87E3EF32D17 1 00A2A9711737AAF0404F35AE502887AC6172B2B57D236BD4A40B45F659BFC696',
            },
          },
          tailsHash: 'HLKresYcDSZYSKogq8wive4zyXNY84669MygftLFBG1i',
          tailsLocation:
            '/var/folders/l3/xy8jzyvj4p5_d9g1123rt4bw0000gn/T/HLKresYcDSZYSKogq8wive4zyXNY84669MygftLFBG1i',
        },
      },
      options: {
        endorserMode: 'internal',
        endorserDid: endorserDid,
      },
    })

    if (!didIndyRevocationRegistryDefinitionId) {
      throw Error('revocation registry definition was not created correctly')
    }

    const { credentialDefinitionTag, revocationRegistryTag } = parseIndyRevocationRegistryId(
      didIndyRevocationRegistryDefinitionId
    )
    const legacyRevocationRegistryDefinitionId = getUnqualifiedRevocationRegistryDefinitionId(
      legacyIssuerId,
      schemaSeqNo,
      credentialDefinitionTag,
      revocationRegistryTag
    )

    // Wait some time before resolving revocation registry definition object
    await new Promise((res) => setTimeout(res, 1000))

    const legacyRevocationRegistryDefinition = await indyVdrAnonCredsRegistry.getRevocationRegistryDefinition(
      endorser.context,
      legacyRevocationRegistryDefinitionId
    )

    expect(legacyRevocationRegistryDefinition).toMatchObject({
      revocationRegistryDefinitionId: legacyRevocationRegistryDefinitionId,
      revocationRegistryDefinition: {
        issuerId: legacyIssuerId,
        revocDefType: 'CL_ACCUM',
        value: {
          maxCredNum: 100,
          tailsHash: 'HLKresYcDSZYSKogq8wive4zyXNY84669MygftLFBG1i',
          tailsLocation:
            '/var/folders/l3/xy8jzyvj4p5_d9g1123rt4bw0000gn/T/HLKresYcDSZYSKogq8wive4zyXNY84669MygftLFBG1i',
          publicKeys: {
            accumKey: {
              z: '1 1812B206EB395D3AEBD4BBF53EBB0FFC3371D8BD6175316AB32C1C5F65452051 1 22A079D49C5351EFDC1410C81A1F6D8B2E3B79CFF20A30690C118FE2050F72CB 1 0FFC28B923A4654E261DB4CB5B9BABEFCB4DB189B20F52412B0CC9CCCBB8A3B2 1 1EE967C43EF1A3F487061D21B07076A26C126AAF7712E7B5CF5A53688DDD5CC0 1 009ED4D65879CA81DA8227D34CEA3B759B4627E1E2FFB273E9645CD4F3B10F19 1 1CF070212E1E213AEB472F56EDFC9D48009796C77B2D8CC16F2836E37B8715C2 1 04954F0B7B468781BAAE3291DD0E6FFA7F1AF66CAA4094D37B24363CC34606FB 1 115367CB755E9DB18781B3825CB1AEE2C334558B2C038E13DF57BB57CE1CF847 1 110D37EC05862EE2757A7DF39E814876FC97376FF8105D2D29619CB575537BDE 1 13C559A9563FCE083B3B39AE7E8FCA4099BEF3A4C8C6672E543D521F9DA88F96 1 137D87CC22ACC1B6B8C20EABE59F6ED456A58FE4CBEEFDFC4FA9B87E3EF32D17 1 00A2A9711737AAF0404F35AE502887AC6172B2B57D236BD4A40B45F659BFC696',
            },
          },
        },
        tag: 'REV_TAG',
        credDefId: legacyCredentialDefinitionId,
      },
      revocationRegistryDefinitionMetadata: {
        issuanceType: 'ISSUANCE_BY_DEFAULT',
        didIndyNamespace: 'pool:localtest',
      },
      resolutionMetadata: {},
    })

    const didIndyRevocationRegistryDefinition = await indyVdrAnonCredsRegistry.getRevocationRegistryDefinition(
      endorser.context,
      didIndyRevocationRegistryDefinitionId
    )

    expect(didIndyRevocationRegistryDefinition).toMatchObject({
      revocationRegistryDefinitionId: didIndyRevocationRegistryDefinitionId,
      revocationRegistryDefinition: {
        issuerId: didIndyIssuerId,
        revocDefType: 'CL_ACCUM',
        value: {
          maxCredNum: 100,
          tailsHash: 'HLKresYcDSZYSKogq8wive4zyXNY84669MygftLFBG1i',
          tailsLocation:
            '/var/folders/l3/xy8jzyvj4p5_d9g1123rt4bw0000gn/T/HLKresYcDSZYSKogq8wive4zyXNY84669MygftLFBG1i',
          publicKeys: {
            accumKey: {
              z: '1 1812B206EB395D3AEBD4BBF53EBB0FFC3371D8BD6175316AB32C1C5F65452051 1 22A079D49C5351EFDC1410C81A1F6D8B2E3B79CFF20A30690C118FE2050F72CB 1 0FFC28B923A4654E261DB4CB5B9BABEFCB4DB189B20F52412B0CC9CCCBB8A3B2 1 1EE967C43EF1A3F487061D21B07076A26C126AAF7712E7B5CF5A53688DDD5CC0 1 009ED4D65879CA81DA8227D34CEA3B759B4627E1E2FFB273E9645CD4F3B10F19 1 1CF070212E1E213AEB472F56EDFC9D48009796C77B2D8CC16F2836E37B8715C2 1 04954F0B7B468781BAAE3291DD0E6FFA7F1AF66CAA4094D37B24363CC34606FB 1 115367CB755E9DB18781B3825CB1AEE2C334558B2C038E13DF57BB57CE1CF847 1 110D37EC05862EE2757A7DF39E814876FC97376FF8105D2D29619CB575537BDE 1 13C559A9563FCE083B3B39AE7E8FCA4099BEF3A4C8C6672E543D521F9DA88F96 1 137D87CC22ACC1B6B8C20EABE59F6ED456A58FE4CBEEFDFC4FA9B87E3EF32D17 1 00A2A9711737AAF0404F35AE502887AC6172B2B57D236BD4A40B45F659BFC696',
            },
          },
        },
        tag: 'REV_TAG',
        credDefId: didIndyCredentialDefinitionId,
      },
      revocationRegistryDefinitionMetadata: {
        issuanceType: 'ISSUANCE_BY_DEFAULT',
        didIndyNamespace: 'pool:localtest',
      },
      resolutionMetadata: {},
    })

    const registerStatusListResult = await indyVdrAnonCredsRegistry.registerRevocationStatusList(endorser.context, {
      revocationStatusList: {
        issuerId: didIndyIssuerId,
        revRegDefId: didIndyRevocationRegistryDefinitionId,
        revocationList: new Array(100).fill(0),
        currentAccumulator: '1',
      },
      options: {
        endorserMode: 'internal',
        endorserDid: endorserDid,
      },
    })

    if (registerStatusListResult.revocationStatusListState.state !== 'finished') {
      throw new Error(`Unable to register status list: ${JSON.stringify(registerStatusListResult)}`)
    }

    // Wait some time before resolving revocation status list object
    await new Promise((res) => setTimeout(res, 1000))

    const legacyRevocationStatusList = await indyVdrAnonCredsRegistry.getRevocationStatusList(
      endorser.context,
      legacyRevocationRegistryDefinitionId,
      registerStatusListResult.revocationStatusListState.revocationStatusList.timestamp
    )

    expect(legacyRevocationStatusList).toMatchObject({
      resolutionMetadata: {},
      revocationStatusList: {
        issuerId: legacyIssuerId,
        currentAccumulator: '1',
        revRegDefId: legacyRevocationRegistryDefinitionId,
        revocationList: [
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ],
        timestamp: registerStatusListResult.revocationStatusListState.revocationStatusList.timestamp,
      },
      revocationStatusListMetadata: {
        didIndyNamespace: 'pool:localtest',
      },
    })

    const didIndyRevocationStatusList = await indyVdrAnonCredsRegistry.getRevocationStatusList(
      endorser.context,
      didIndyRevocationRegistryDefinitionId,
      registerStatusListResult.revocationStatusListState.revocationStatusList.timestamp
    )

    expect(didIndyRevocationStatusList).toMatchObject({
      resolutionMetadata: {},
      revocationStatusList: {
        issuerId: didIndyIssuerId,
        currentAccumulator: '1',
        revRegDefId: didIndyRevocationRegistryDefinitionId,
        revocationList: [
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ],
        timestamp: registerStatusListResult.revocationStatusListState.revocationStatusList.timestamp,
      },
      revocationStatusListMetadata: {
        didIndyNamespace: 'pool:localtest',
      },
    })
  })

  test('register and resolve a schema and credential definition (internal, issuerDid == endorserDid)', async () => {
    const dynamicVersion = `1.${Math.random() * 100}`

    const legacyIssuerId = 'DJKobikPAaYWAu9vfhEEo5'
    const didIndyIssuerId = 'did:indy:pool:localtest:DJKobikPAaYWAu9vfhEEo5'
    const legacySchemaId = `DJKobikPAaYWAu9vfhEEo5:2:test:${dynamicVersion}`
    const didIndySchemaId = `did:indy:pool:localtest:DJKobikPAaYWAu9vfhEEo5/anoncreds/v0/SCHEMA/test/${dynamicVersion}`

    const schemaResult = await indyVdrAnonCredsRegistry.registerSchema(endorser.context, {
      options: {
        endorserMode: 'internal',
        endorserDid,
      },
      schema: {
        attrNames: ['age'],
        issuerId: didIndyIssuerId,
        name: 'test',
        version: dynamicVersion,
      },
    })

    const schemaSeqNo = schemaResult.schemaMetadata.indyLedgerSeqNo as number

    expect(schemaResult).toMatchObject({
      schemaState: {
        state: 'finished',
        schema: {
          attrNames: ['age'],
          issuerId: didIndyIssuerId,
          name: 'test',
          version: dynamicVersion,
        },
        schemaId: didIndySchemaId,
      },
      registrationMetadata: {},
      schemaMetadata: {
        indyLedgerSeqNo: expect.any(Number),
      },
    })

    // Wait some time before resolving credential definition object
    await new Promise((res) => setTimeout(res, 1000))

    const legacySchema = await indyVdrAnonCredsRegistry.getSchema(endorser.context, legacySchemaId)
    expect(legacySchema).toMatchObject({
      schema: {
        attrNames: ['age'],
        name: 'test',
        version: dynamicVersion,
        issuerId: legacyIssuerId,
      },
      schemaId: legacySchemaId,
      resolutionMetadata: {},
      schemaMetadata: {
        didIndyNamespace: 'pool:localtest',
        indyLedgerSeqNo: expect.any(Number),
      },
    })

    // Resolve using did indy schema id
    const didIndySchema = await indyVdrAnonCredsRegistry.getSchema(endorser.context, didIndySchemaId)
    expect(didIndySchema).toMatchObject({
      schema: {
        attrNames: ['age'],
        name: 'test',
        version: dynamicVersion,
        issuerId: didIndyIssuerId,
      },
      schemaId: didIndySchemaId,
      resolutionMetadata: {},
      schemaMetadata: {
        didIndyNamespace: 'pool:localtest',
        indyLedgerSeqNo: expect.any(Number),
      },
    })

    const legacyCredentialDefinitionId = `DJKobikPAaYWAu9vfhEEo5:3:CL:${schemaSeqNo}:TAG`
    const didIndyCredentialDefinitionId = `did:indy:pool:localtest:DJKobikPAaYWAu9vfhEEo5/anoncreds/v0/CLAIM_DEF/${schemaSeqNo}/TAG`
    const credentialDefinitionResult = await indyVdrAnonCredsRegistry.registerCredentialDefinition(endorser.context, {
      credentialDefinition: {
        issuerId: didIndyIssuerId,
        tag: 'TAG',
        schemaId: didIndySchemaId,
        type: 'CL',
        value: credentialDefinitionValue,
      },
      options: {
        endorserMode: 'internal',
        endorserDid: endorserDid,
      },
    })

    expect(credentialDefinitionResult).toMatchObject({
      credentialDefinitionMetadata: {},
      credentialDefinitionState: {
        credentialDefinition: {
          issuerId: didIndyIssuerId,
          tag: 'TAG',
          schemaId: didIndySchemaId,
          type: 'CL',
          value: credentialDefinitionValue,
        },
        credentialDefinitionId: didIndyCredentialDefinitionId,
        state: 'finished',
      },
      registrationMetadata: {},
    })

    // Wait some time before resolving credential definition object
    await new Promise((res) => setTimeout(res, 1000))

    const legacyCredentialDefinition = await indyVdrAnonCredsRegistry.getCredentialDefinition(
      endorser.context,
      legacyCredentialDefinitionId
    )

    expect(legacyCredentialDefinition).toMatchObject({
      credentialDefinitionId: legacyCredentialDefinitionId,
      credentialDefinition: {
        issuerId: legacyIssuerId,
        schemaId: legacySchemaId,
        tag: 'TAG',
        type: 'CL',
        value: credentialDefinitionValue,
      },
      credentialDefinitionMetadata: {
        didIndyNamespace: 'pool:localtest',
      },
      resolutionMetadata: {},
    })

    // resolve using did indy credential definition id
    const didIndyCredentialDefinition = await indyVdrAnonCredsRegistry.getCredentialDefinition(
      endorser.context,
      didIndyCredentialDefinitionId
    )

    expect(didIndyCredentialDefinition).toMatchObject({
      credentialDefinitionId: didIndyCredentialDefinitionId,
      credentialDefinition: {
        issuerId: didIndyIssuerId,
        schemaId: didIndySchemaId,
        tag: 'TAG',
        type: 'CL',
        value: credentialDefinitionValue,
      },
      credentialDefinitionMetadata: {
        didIndyNamespace: 'pool:localtest',
      },
      resolutionMetadata: {},
    })

    const {
      revocationRegistryDefinitionState: { revocationRegistryDefinitionId: didIndyRevocationRegistryDefinitionId },
    } = await indyVdrAnonCredsRegistry.registerRevocationRegistryDefinition(endorser.context, {
      revocationRegistryDefinition: {
        tag: 'REV_TAG',
        issuerId: didIndyIssuerId,
        credDefId: didIndyCredentialDefinitionId,
        revocDefType: 'CL_ACCUM',
        value: {
          maxCredNum: 100,
          publicKeys: {
            accumKey: {
              z: '1 1812B206EB395D3AEBD4BBF53EBB0FFC3371D8BD6175316AB32C1C5F65452051 1 22A079D49C5351EFDC1410C81A1F6D8B2E3B79CFF20A30690C118FE2050F72CB 1 0FFC28B923A4654E261DB4CB5B9BABEFCB4DB189B20F52412B0CC9CCCBB8A3B2 1 1EE967C43EF1A3F487061D21B07076A26C126AAF7712E7B5CF5A53688DDD5CC0 1 009ED4D65879CA81DA8227D34CEA3B759B4627E1E2FFB273E9645CD4F3B10F19 1 1CF070212E1E213AEB472F56EDFC9D48009796C77B2D8CC16F2836E37B8715C2 1 04954F0B7B468781BAAE3291DD0E6FFA7F1AF66CAA4094D37B24363CC34606FB 1 115367CB755E9DB18781B3825CB1AEE2C334558B2C038E13DF57BB57CE1CF847 1 110D37EC05862EE2757A7DF39E814876FC97376FF8105D2D29619CB575537BDE 1 13C559A9563FCE083B3B39AE7E8FCA4099BEF3A4C8C6672E543D521F9DA88F96 1 137D87CC22ACC1B6B8C20EABE59F6ED456A58FE4CBEEFDFC4FA9B87E3EF32D17 1 00A2A9711737AAF0404F35AE502887AC6172B2B57D236BD4A40B45F659BFC696',
            },
          },
          tailsHash: 'HLKresYcDSZYSKogq8wive4zyXNY84669MygftLFBG1i',
          tailsLocation:
            '/var/folders/l3/xy8jzyvj4p5_d9g1123rt4bw0000gn/T/HLKresYcDSZYSKogq8wive4zyXNY84669MygftLFBG1i',
        },
      },
      options: {
        endorserMode: 'internal',
        endorserDid: endorserDid,
      },
    })

    if (!didIndyRevocationRegistryDefinitionId) {
      throw Error('revocation registry definition was not created correctly')
    }

    const { credentialDefinitionTag, revocationRegistryTag } = parseIndyRevocationRegistryId(
      didIndyRevocationRegistryDefinitionId
    )
    const legacyRevocationRegistryDefinitionId = getUnqualifiedRevocationRegistryDefinitionId(
      legacyIssuerId,
      schemaSeqNo,
      credentialDefinitionTag,
      revocationRegistryTag
    )

    // Wait some time before resolving revocation registry definition object
    await new Promise((res) => setTimeout(res, 1000))

    const legacyRevocationRegistryDefinition = await indyVdrAnonCredsRegistry.getRevocationRegistryDefinition(
      endorser.context,
      legacyRevocationRegistryDefinitionId
    )

    expect(legacyRevocationRegistryDefinition).toMatchObject({
      revocationRegistryDefinitionId: legacyRevocationRegistryDefinitionId,
      revocationRegistryDefinition: {
        issuerId: legacyIssuerId,
        revocDefType: 'CL_ACCUM',
        value: {
          maxCredNum: 100,
          tailsHash: 'HLKresYcDSZYSKogq8wive4zyXNY84669MygftLFBG1i',
          tailsLocation:
            '/var/folders/l3/xy8jzyvj4p5_d9g1123rt4bw0000gn/T/HLKresYcDSZYSKogq8wive4zyXNY84669MygftLFBG1i',
          publicKeys: {
            accumKey: {
              z: '1 1812B206EB395D3AEBD4BBF53EBB0FFC3371D8BD6175316AB32C1C5F65452051 1 22A079D49C5351EFDC1410C81A1F6D8B2E3B79CFF20A30690C118FE2050F72CB 1 0FFC28B923A4654E261DB4CB5B9BABEFCB4DB189B20F52412B0CC9CCCBB8A3B2 1 1EE967C43EF1A3F487061D21B07076A26C126AAF7712E7B5CF5A53688DDD5CC0 1 009ED4D65879CA81DA8227D34CEA3B759B4627E1E2FFB273E9645CD4F3B10F19 1 1CF070212E1E213AEB472F56EDFC9D48009796C77B2D8CC16F2836E37B8715C2 1 04954F0B7B468781BAAE3291DD0E6FFA7F1AF66CAA4094D37B24363CC34606FB 1 115367CB755E9DB18781B3825CB1AEE2C334558B2C038E13DF57BB57CE1CF847 1 110D37EC05862EE2757A7DF39E814876FC97376FF8105D2D29619CB575537BDE 1 13C559A9563FCE083B3B39AE7E8FCA4099BEF3A4C8C6672E543D521F9DA88F96 1 137D87CC22ACC1B6B8C20EABE59F6ED456A58FE4CBEEFDFC4FA9B87E3EF32D17 1 00A2A9711737AAF0404F35AE502887AC6172B2B57D236BD4A40B45F659BFC696',
            },
          },
        },
        tag: 'REV_TAG',
        credDefId: legacyCredentialDefinitionId,
      },
      revocationRegistryDefinitionMetadata: {
        issuanceType: 'ISSUANCE_BY_DEFAULT',
        didIndyNamespace: 'pool:localtest',
      },
      resolutionMetadata: {},
    })

    const didIndyRevocationRegistryDefinition = await indyVdrAnonCredsRegistry.getRevocationRegistryDefinition(
      endorser.context,
      didIndyRevocationRegistryDefinitionId
    )

    expect(didIndyRevocationRegistryDefinition).toMatchObject({
      revocationRegistryDefinitionId: didIndyRevocationRegistryDefinitionId,
      revocationRegistryDefinition: {
        issuerId: didIndyIssuerId,
        revocDefType: 'CL_ACCUM',
        value: {
          maxCredNum: 100,
          tailsHash: 'HLKresYcDSZYSKogq8wive4zyXNY84669MygftLFBG1i',
          tailsLocation:
            '/var/folders/l3/xy8jzyvj4p5_d9g1123rt4bw0000gn/T/HLKresYcDSZYSKogq8wive4zyXNY84669MygftLFBG1i',
          publicKeys: {
            accumKey: {
              z: '1 1812B206EB395D3AEBD4BBF53EBB0FFC3371D8BD6175316AB32C1C5F65452051 1 22A079D49C5351EFDC1410C81A1F6D8B2E3B79CFF20A30690C118FE2050F72CB 1 0FFC28B923A4654E261DB4CB5B9BABEFCB4DB189B20F52412B0CC9CCCBB8A3B2 1 1EE967C43EF1A3F487061D21B07076A26C126AAF7712E7B5CF5A53688DDD5CC0 1 009ED4D65879CA81DA8227D34CEA3B759B4627E1E2FFB273E9645CD4F3B10F19 1 1CF070212E1E213AEB472F56EDFC9D48009796C77B2D8CC16F2836E37B8715C2 1 04954F0B7B468781BAAE3291DD0E6FFA7F1AF66CAA4094D37B24363CC34606FB 1 115367CB755E9DB18781B3825CB1AEE2C334558B2C038E13DF57BB57CE1CF847 1 110D37EC05862EE2757A7DF39E814876FC97376FF8105D2D29619CB575537BDE 1 13C559A9563FCE083B3B39AE7E8FCA4099BEF3A4C8C6672E543D521F9DA88F96 1 137D87CC22ACC1B6B8C20EABE59F6ED456A58FE4CBEEFDFC4FA9B87E3EF32D17 1 00A2A9711737AAF0404F35AE502887AC6172B2B57D236BD4A40B45F659BFC696',
            },
          },
        },
        tag: 'REV_TAG',
        credDefId: didIndyCredentialDefinitionId,
      },
      revocationRegistryDefinitionMetadata: {
        issuanceType: 'ISSUANCE_BY_DEFAULT',
        didIndyNamespace: 'pool:localtest',
      },
      resolutionMetadata: {},
    })

    const registerStatusListResult = await indyVdrAnonCredsRegistry.registerRevocationStatusList(endorser.context, {
      revocationStatusList: {
        issuerId: didIndyIssuerId,
        revRegDefId: didIndyRevocationRegistryDefinitionId,
        revocationList: new Array(100).fill(0),
        currentAccumulator: '1',
      },
      options: {
        endorserMode: 'internal',
        endorserDid: endorserDid,
      },
    })

    if (registerStatusListResult.revocationStatusListState.state !== 'finished') {
      throw new Error(`Unable to register status list: ${JSON.stringify(registerStatusListResult)}`)
    }

    // Wait some time before resolving revocation status list object
    await new Promise((res) => setTimeout(res, 1000))

    const legacyRevocationStatusList = await indyVdrAnonCredsRegistry.getRevocationStatusList(
      endorser.context,
      legacyRevocationRegistryDefinitionId,
      registerStatusListResult.revocationStatusListState.revocationStatusList.timestamp
    )

    expect(legacyRevocationStatusList).toMatchObject({
      resolutionMetadata: {},
      revocationStatusList: {
        issuerId: legacyIssuerId,
        currentAccumulator: '1',
        revRegDefId: legacyRevocationRegistryDefinitionId,
        revocationList: [
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ],
        timestamp: registerStatusListResult.revocationStatusListState.revocationStatusList.timestamp,
      },
      revocationStatusListMetadata: {
        didIndyNamespace: 'pool:localtest',
      },
    })

    const didIndyRevocationStatusList = await indyVdrAnonCredsRegistry.getRevocationStatusList(
      endorser.context,
      didIndyRevocationRegistryDefinitionId,
      registerStatusListResult.revocationStatusListState.revocationStatusList.timestamp
    )

    expect(didIndyRevocationStatusList).toMatchObject({
      resolutionMetadata: {},
      revocationStatusList: {
        issuerId: didIndyIssuerId,
        currentAccumulator: '1',
        revRegDefId: didIndyRevocationRegistryDefinitionId,
        revocationList: [
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ],
        timestamp: registerStatusListResult.revocationStatusListState.revocationStatusList.timestamp,
      },
      revocationStatusListMetadata: {
        didIndyNamespace: 'pool:localtest',
      },
    })
  })

  test('register and resolve a schema, credential definition, revocation registry and status list (external)', async () => {
    // ----
    // CREATE DID
    // ----
    const didCreateTxResult = (await agent.dids.create<IndyVdrDidCreateOptions>({
      method: 'indy',
      options: {
        endorserMode: 'external',
        endorserDid,
      },
    })) as IndyVdrDidCreateResult

    const didState = didCreateTxResult.didState
    if (didState.state !== 'action' || didState.action !== 'endorseIndyTransaction') throw Error('unexpected did state')

    const signedNymRequest = await endorser.modules.indyVdr.endorseTransaction(
      didState.nymRequest,
      didState.endorserDid
    )
    const didCreateSubmitResult = await agent.dids.create<IndyVdrDidCreateOptions>({
      did: didState.did,
      options: {
        endorserMode: 'external',
        endorsedTransaction: {
          nymRequest: signedNymRequest,
        },
      },
      secret: didState.secret,
    })

    if (!didCreateSubmitResult.didState.did) throw Error('did was not correctly created')

    const agentDid = didCreateSubmitResult.didState.did
    const { namespaceIdentifier } = parseIndyDid(agentDid)

    const dynamicVersion = `1.${Math.random() * 100}`

    const legacyIssuerId = namespaceIdentifier
    const didIndyIssuerId = agentDid

    // ----
    // CREATE SCHEMA
    // ----
    const legacySchemaId = `${namespaceIdentifier}:2:test:${dynamicVersion}`
    const didIndySchemaId = `did:indy:pool:localtest:${namespaceIdentifier}/anoncreds/v0/SCHEMA/test/${dynamicVersion}`

    const createSchemaTxResult = await indyVdrAnonCredsRegistry.registerSchema(agent.context, {
      options: {
        endorserMode: 'external',
        endorserDid,
      },
      schema: {
        attrNames: ['age'],
        issuerId: didIndyIssuerId,
        name: 'test',
        version: dynamicVersion,
      },
    })

    const { schemaState } = createSchemaTxResult

    if (schemaState.state !== 'action' || schemaState.action !== 'endorseIndyTransaction')
      throw Error('unexpected schema state')

    const endorsedTx = await endorser.modules.indyVdr.endorseTransaction(schemaState.schemaRequest, endorserDid)

    const submitSchemaTxResult = await indyVdrAnonCredsRegistry.registerSchema(agent.context, {
      schema: schemaState.schema,
      options: {
        endorserMode: 'external',
        endorsedTransaction: endorsedTx,
      },
    })

    expect(submitSchemaTxResult).toMatchObject({
      schemaState: {
        state: 'finished',
        schema: {
          attrNames: ['age'],
          issuerId: didIndyIssuerId,
          name: 'test',
          version: dynamicVersion,
        },
        schemaId: didIndySchemaId,
      },
      registrationMetadata: {},
      schemaMetadata: {
        indyLedgerSeqNo: expect.any(Number),
      },
    })

    // Wait some time before resolving credential definition object
    await new Promise((res) => setTimeout(res, 1000))

    const legacySchema = await indyVdrAnonCredsRegistry.getSchema(agent.context, legacySchemaId)
    expect(legacySchema).toMatchObject({
      schema: {
        attrNames: ['age'],
        name: 'test',
        version: dynamicVersion,
        issuerId: legacyIssuerId,
      },
      schemaId: legacySchemaId,
      resolutionMetadata: {},
      schemaMetadata: {
        didIndyNamespace: 'pool:localtest',
        indyLedgerSeqNo: expect.any(Number),
      },
    })

    // Resolve using did indy schema id
    const didIndySchema = await indyVdrAnonCredsRegistry.getSchema(agent.context, didIndySchemaId)
    expect(didIndySchema).toMatchObject({
      schema: {
        attrNames: ['age'],
        name: 'test',
        version: dynamicVersion,
        issuerId: didIndyIssuerId,
      },
      schemaId: didIndySchemaId,
      resolutionMetadata: {},
      schemaMetadata: {
        didIndyNamespace: 'pool:localtest',
        indyLedgerSeqNo: expect.any(Number),
      },
    })

    // ----
    // CREATE CREDENTIAL DEFINITION
    // ----
    const legacyCredentialDefinitionId = `${namespaceIdentifier}:3:CL:${submitSchemaTxResult.schemaMetadata.indyLedgerSeqNo}:TAG`
    const didIndyCredentialDefinitionId = `did:indy:pool:localtest:${namespaceIdentifier}/anoncreds/v0/CLAIM_DEF/${submitSchemaTxResult.schemaMetadata.indyLedgerSeqNo}/TAG`

    const createCredDefTxResult = await indyVdrAnonCredsRegistry.registerCredentialDefinition(agent.context, {
      credentialDefinition: {
        issuerId: didIndyIssuerId,
        tag: 'TAG',
        schemaId: didIndySchemaId,
        type: 'CL',
        value: credentialDefinitionValue,
      },
      options: {
        endorserMode: 'external',
        endorserDid,
      },
    })

    const { credentialDefinitionState } = createCredDefTxResult

    if (credentialDefinitionState.state !== 'action' || credentialDefinitionState.action !== 'endorseIndyTransaction')
      throw Error('unexpected credential definition state')

    const endorsedCredDefTx = await endorser.modules.indyVdr.endorseTransaction(
      credentialDefinitionState.credentialDefinitionRequest,
      endorserDid
    )
    const submitCredDefTxResult = await indyVdrAnonCredsRegistry.registerCredentialDefinition(agent.context, {
      credentialDefinition: credentialDefinitionState.credentialDefinition,
      options: {
        endorserMode: 'external',
        endorsedTransaction: endorsedCredDefTx,
      },
    })

    expect(submitCredDefTxResult).toMatchObject({
      credentialDefinitionMetadata: {},
      credentialDefinitionState: {
        credentialDefinition: {
          issuerId: didIndyIssuerId,
          tag: 'TAG',
          schemaId: didIndySchemaId,
          type: 'CL',
          value: credentialDefinitionValue,
        },
        credentialDefinitionId: didIndyCredentialDefinitionId,
        state: 'finished',
      },
      registrationMetadata: {},
    })

    // Wait some time before resolving credential definition object
    await new Promise((res) => setTimeout(res, 1000))

    const legacyCredentialDefinition = await indyVdrAnonCredsRegistry.getCredentialDefinition(
      agent.context,
      legacyCredentialDefinitionId
    )

    expect(legacyCredentialDefinition).toMatchObject({
      credentialDefinitionId: legacyCredentialDefinitionId,
      credentialDefinition: {
        issuerId: legacyIssuerId,
        schemaId: legacySchemaId,
        tag: 'TAG',
        type: 'CL',
        value: credentialDefinitionValue,
      },
      credentialDefinitionMetadata: {
        didIndyNamespace: 'pool:localtest',
      },
      resolutionMetadata: {},
    })

    // resolve using did indy credential definition id
    const didIndyCredentialDefinition = await indyVdrAnonCredsRegistry.getCredentialDefinition(
      agent.context,
      didIndyCredentialDefinitionId
    )

    expect(didIndyCredentialDefinition).toMatchObject({
      credentialDefinitionId: didIndyCredentialDefinitionId,
      credentialDefinition: {
        issuerId: didIndyIssuerId,
        schemaId: didIndySchemaId,
        tag: 'TAG',
        type: 'CL',
        value: credentialDefinitionValue,
      },
      credentialDefinitionMetadata: {
        didIndyNamespace: 'pool:localtest',
      },
      resolutionMetadata: {},
    })

    // ----
    // CREATE REVOCATION REGISTRY
    // ----
    const legacyRevocationRegistryDefinitionId = `${namespaceIdentifier}:4:${namespaceIdentifier}:3:CL:${submitSchemaTxResult.schemaMetadata.indyLedgerSeqNo}:TAG:CL_ACCUM:REV_TAG`
    const didIndyRevocationRegistryDefinitionId = `did:indy:pool:localtest:${namespaceIdentifier}/anoncreds/v0/REV_REG_DEF/${submitSchemaTxResult.schemaMetadata.indyLedgerSeqNo}/TAG/REV_TAG`

    const createRevRegDefTxResult = await indyVdrAnonCredsRegistry.registerRevocationRegistryDefinition(agent.context, {
      revocationRegistryDefinition: {
        tag: 'REV_TAG',
        revocDefType: 'CL_ACCUM',
        credDefId: didIndyCredentialDefinitionId,
        issuerId: didIndyIssuerId,
        value: revocationRegistryDefinitionValue,
      },
      options: {
        endorserMode: 'external',
        endorserDid,
      },
    })

    const { revocationRegistryDefinitionState } = createRevRegDefTxResult

    if (
      revocationRegistryDefinitionState.state !== 'action' ||
      revocationRegistryDefinitionState.action !== 'endorseIndyTransaction'
    ) {
      throw Error('unexpected revocation registry definition state')
    }

    const endorsedRevRegDefTx = await endorser.modules.indyVdr.endorseTransaction(
      revocationRegistryDefinitionState.revocationRegistryDefinitionRequest,
      endorserDid
    )
    const submitRevRegDefTxResult = await indyVdrAnonCredsRegistry.registerRevocationRegistryDefinition(agent.context, {
      revocationRegistryDefinition: revocationRegistryDefinitionState.revocationRegistryDefinition,
      options: {
        endorserMode: 'external',
        endorsedTransaction: endorsedRevRegDefTx,
      },
    })

    expect(submitRevRegDefTxResult).toMatchObject({
      revocationRegistryDefinitionMetadata: {},
      revocationRegistryDefinitionState: {
        revocationRegistryDefinition: {
          credDefId: didIndyCredentialDefinitionId,
          issuerId: didIndyIssuerId,
          tag: 'REV_TAG',
          value: revocationRegistryDefinitionValue,
        },
        revocationRegistryDefinitionId: didIndyRevocationRegistryDefinitionId,
        state: 'finished',
      },
      registrationMetadata: {},
    })

    await new Promise((res) => setTimeout(res, 1000))

    const legacyRevocationRegistryDefinition = await indyVdrAnonCredsRegistry.getRevocationRegistryDefinition(
      agent.context,
      legacyRevocationRegistryDefinitionId
    )

    expect(legacyRevocationRegistryDefinition).toMatchObject({
      revocationRegistryDefinitionId: legacyRevocationRegistryDefinitionId,
      revocationRegistryDefinition: {
        issuerId: legacyIssuerId,
        revocDefType: 'CL_ACCUM',
        value: revocationRegistryDefinitionValue,
        tag: 'REV_TAG',
        credDefId: legacyCredentialDefinitionId,
      },
      revocationRegistryDefinitionMetadata: {
        issuanceType: 'ISSUANCE_BY_DEFAULT',
        didIndyNamespace: 'pool:localtest',
      },
      resolutionMetadata: {},
    })

    const didIndyRevocationRegistryDefinition = await indyVdrAnonCredsRegistry.getRevocationRegistryDefinition(
      agent.context,
      didIndyRevocationRegistryDefinitionId
    )

    expect(didIndyRevocationRegistryDefinition).toMatchObject({
      revocationRegistryDefinitionId: didIndyRevocationRegistryDefinitionId,
      revocationRegistryDefinition: {
        issuerId: didIndyIssuerId,
        revocDefType: 'CL_ACCUM',
        value: revocationRegistryDefinitionValue,
        tag: 'REV_TAG',
        credDefId: didIndyCredentialDefinitionId,
      },
      revocationRegistryDefinitionMetadata: {
        issuanceType: 'ISSUANCE_BY_DEFAULT',
        didIndyNamespace: 'pool:localtest',
      },
      resolutionMetadata: {},
    })

    // ----
    // CREATE REVOCATION STATUS LIST
    // ----
    const revocationStatusListValue = {
      issuerId: didIndyIssuerId,
      revRegDefId: didIndyRevocationRegistryDefinitionId,
      revocationList: [1, 0, 1, 1, 1, 1, 0, 1, 1, 1, 0],
      currentAccumulator: '1',
    }

    const createRevStatusListTxResult = await indyVdrAnonCredsRegistry.registerRevocationStatusList(agent.context, {
      options: {
        endorserMode: 'external',
        endorserDid,
      },
      revocationStatusList: revocationStatusListValue,
    })

    const { revocationStatusListState } = createRevStatusListTxResult

    if (revocationStatusListState.state !== 'action' || revocationStatusListState.action !== 'endorseIndyTransaction') {
      throw Error('unexpected revocation status list state')
    }

    const endorsedRevStatusListTx = await endorser.modules.indyVdr.endorseTransaction(
      revocationStatusListState.revocationStatusListRequest,
      endorserDid
    )

    const submitRevStatusListTxResult = await indyVdrAnonCredsRegistry.registerRevocationStatusList(agent.context, {
      revocationStatusList: revocationStatusListState.revocationStatusList,
      options: {
        endorserMode: 'external',
        endorsedTransaction: endorsedRevStatusListTx,
      },
    })

    expect(submitRevStatusListTxResult).toMatchObject({
      revocationStatusListMetadata: {},
      revocationStatusListState: {
        revocationStatusList: { ...revocationStatusListValue, timestamp: expect.any(Number) },
        state: 'finished',
      },
      registrationMetadata: {},
    })

    // Wait some time before resolving status list
    await new Promise((res) => setTimeout(res, 1000))

    const legacyRevocationStatusList = await indyVdrAnonCredsRegistry.getRevocationStatusList(
      agent.context,
      legacyRevocationRegistryDefinitionId,
      submitRevStatusListTxResult.revocationStatusListState.revocationStatusList?.timestamp as number
    )

    expect(legacyRevocationStatusList).toMatchObject({
      resolutionMetadata: {},
      revocationStatusList: {
        issuerId: legacyIssuerId,
        currentAccumulator: '1',
        revRegDefId: legacyRevocationRegistryDefinitionId,
        revocationList: revocationStatusListValue.revocationList,
        timestamp: submitRevStatusListTxResult.revocationStatusListState.revocationStatusList?.timestamp,
      },
      revocationStatusListMetadata: {
        didIndyNamespace: 'pool:localtest',
      },
    })

    const didIndyRevocationStatusList = await indyVdrAnonCredsRegistry.getRevocationStatusList(
      agent.context,
      didIndyRevocationRegistryDefinitionId,
      submitRevStatusListTxResult.revocationStatusListState.revocationStatusList?.timestamp as number
    )

    expect(didIndyRevocationStatusList).toMatchObject({
      resolutionMetadata: {},
      revocationStatusList: {
        issuerId: didIndyIssuerId,
        currentAccumulator: '1',
        revRegDefId: didIndyRevocationRegistryDefinitionId,
        revocationList: revocationStatusListValue.revocationList,
        timestamp: submitRevStatusListTxResult.revocationStatusListState.revocationStatusList?.timestamp,
      },
      revocationStatusListMetadata: {
        didIndyNamespace: 'pool:localtest',
      },
    })
  })

  test('register and resolve a credential definition (internal,credDefDid != schemaDid)', async () => {
    const didCreateResult = (await endorser.dids.create<IndyVdrDidCreateOptions>({
      method: 'indy',
      options: {
        endorserMode: 'internal',
        endorserDid: endorserDid,
      },
    })) as IndyVdrDidCreateResult

    if (didCreateResult.didState.state !== 'finished') throw Error('did was not successfully created')
    endorser.config.logger.debug(`didIndyIssuerId:: ${didCreateResult.didState.did}`)
    const didIndyIssuerId = didCreateResult.didState.did
    const { namespaceIdentifier: legacyIssuerId } = parseIndyDid(didIndyIssuerId)
    const dynamicVersion = `1.${Math.random() * 100}`
    const legacySchemaId = `${legacyIssuerId}:2:test:${dynamicVersion}`
    const didIndySchemaId = `did:indy:pool:localtest:${legacyIssuerId}/anoncreds/v0/SCHEMA/test/${dynamicVersion}`

    const schemaResult = await indyVdrAnonCredsRegistry.registerSchema(endorser.context, {
      options: {
        endorserMode: 'internal',
        endorserDid,
      },
      schema: {
        attrNames: ['age'],
        issuerId: didIndyIssuerId,
        name: 'test',
        version: dynamicVersion,
      },
    })
    const schemaSeqNo = schemaResult.schemaMetadata.indyLedgerSeqNo as number
    expect(schemaResult).toMatchObject({
      schemaState: {
        state: 'finished',
        schema: {
          attrNames: ['age'],
          issuerId: didIndyIssuerId,
          name: 'test',
          version: dynamicVersion,
        },
        schemaId: didIndySchemaId,
      },
      registrationMetadata: {},
      schemaMetadata: {
        indyLedgerSeqNo: expect.any(Number),
      },
    })
    // Wait some time before resolving credential definition object
    await new Promise((res) => setTimeout(res, 1000))
    const legacySchema = await indyVdrAnonCredsRegistry.getSchema(endorser.context, legacySchemaId)
    expect(legacySchema).toMatchObject({
      schema: {
        attrNames: ['age'],
        name: 'test',
        version: dynamicVersion,
        issuerId: legacyIssuerId,
      },
      schemaId: legacySchemaId,
      resolutionMetadata: {},
      schemaMetadata: {
        didIndyNamespace: 'pool:localtest',
        indyLedgerSeqNo: expect.any(Number),
      },
    })
    // Resolve using did indy schema id
    const didIndySchema = await indyVdrAnonCredsRegistry.getSchema(endorser.context, didIndySchemaId)
    expect(didIndySchema).toMatchObject({
      schema: {
        attrNames: ['age'],
        name: 'test',
        version: dynamicVersion,
        issuerId: didIndyIssuerId,
      },
      schemaId: didIndySchemaId,
      resolutionMetadata: {},
      schemaMetadata: {
        didIndyNamespace: 'pool:localtest',
        indyLedgerSeqNo: expect.any(Number),
      },
    })

    const agentDidCreateResult = (await agent.dids.create<IndyVdrDidCreateOptions>({
      method: 'indy',
      options: {
        endorserDid: agentDid,
        endorserMode: 'internal',
      },
    })) as IndyVdrDidCreateResult

    if (agentDidCreateResult.didState.state !== 'finished') throw Error('did was not successfully created')
    const didIndyAgentIssuerId = agentDidCreateResult.didState.did
    const { namespaceIdentifier: agentLegacyIssuerId } = parseIndyDid(didIndyAgentIssuerId)

    const legacyCredentialDefinitionId = `${agentLegacyIssuerId}:3:CL:${schemaSeqNo}:TAG`
    const didIndyCredentialDefinitionId = `did:indy:pool:localtest:${agentLegacyIssuerId}/anoncreds/v0/CLAIM_DEF/${schemaSeqNo}/TAG`

    const credentialDefinitionResult = await indyVdrAnonCredsRegistry.registerCredentialDefinition(agent.context, {
      credentialDefinition: {
        issuerId: didIndyAgentIssuerId,
        tag: 'TAG',
        schemaId: didIndySchemaId,
        type: 'CL',
        value: credentialDefinitionValue,
      },
      options: {
        endorserMode: 'internal',
        endorserDid: agentDid,
      },
    })

    expect(credentialDefinitionResult).toMatchObject({
      credentialDefinitionMetadata: {},
      credentialDefinitionState: {
        credentialDefinition: {
          issuerId: didIndyAgentIssuerId,
          tag: 'TAG',
          schemaId: didIndySchemaId,
          type: 'CL',
          value: credentialDefinitionValue,
        },
        credentialDefinitionId: didIndyCredentialDefinitionId,
        state: 'finished',
      },
      registrationMetadata: {},
    })

    // // Wait some time before resolving credential definition object
    await new Promise((res) => setTimeout(res, 1000))
    const legacyCredentialDefinition = await indyVdrAnonCredsRegistry.getCredentialDefinition(
      agent.context,
      legacyCredentialDefinitionId
    )

    expect(legacyCredentialDefinition).toMatchObject({
      credentialDefinitionId: legacyCredentialDefinitionId,
      credentialDefinition: {
        issuerId: agentLegacyIssuerId,
        schemaId: legacySchemaId,
        tag: 'TAG',
        type: 'CL',
        value: credentialDefinitionValue,
      },
      credentialDefinitionMetadata: {
        didIndyNamespace: 'pool:localtest',
      },
      resolutionMetadata: {},
    })
    // resolve using did indy credential definition id
    const didIndyCredentialDefinition = await indyVdrAnonCredsRegistry.getCredentialDefinition(
      agent.context,
      didIndyCredentialDefinitionId
    )

    expect(didIndyCredentialDefinition).toMatchObject({
      credentialDefinitionId: didIndyCredentialDefinitionId,
      credentialDefinition: {
        issuerId: didIndyAgentIssuerId,
        schemaId: didIndySchemaId,
        tag: 'TAG',
        type: 'CL',
        value: credentialDefinitionValue,
      },
      credentialDefinitionMetadata: {
        didIndyNamespace: 'pool:localtest',
      },
      resolutionMetadata: {},
    })
  })
})
