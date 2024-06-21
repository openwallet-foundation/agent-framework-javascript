import type { DidRepository, Wallet } from '@credo-ts/core'

import {
  CredentialState,
  Agent,
  CacheModuleConfig,
  CredentialExchangeRecord,
  CredentialRole,
  CredoError,
  DidResolverService,
  DidsModuleConfig,
  EventEmitter,
  InjectionSymbols,
  SignatureSuiteToken,
  W3cCredentialRepository,
  W3cCredentialsModuleConfig,
  CredentialRepository,
} from '@credo-ts/core'
import { Subject } from 'rxjs'

import { InMemoryStorageService } from '../../../../../../tests/InMemoryStorageService'
import { agentDependencies, getAgentConfig, getAgentContext, mockFunction, testLogger } from '../../../../../core/tests'
import { InMemoryAnonCredsRegistry } from '../../../../tests/InMemoryAnonCredsRegistry'
import { AnonCredsModuleConfig } from '../../../AnonCredsModuleConfig'
import { AnonCredsRsHolderService } from '../../../anoncreds-rs'
import { AnonCredsCredentialRecord } from '../../../repository'
import { AnonCredsHolderServiceSymbol, AnonCredsRegistryService } from '../../../services'
import { getUnQualifiedDidIndyDid, getQualifiedDidIndyDid, isUnqualifiedIndyDid } from '../../../utils/indyIdentifiers'
import * as testModule from '../anonCredsCredentialRecord'

import { anoncreds } from './../../../../tests/helpers'

const agentConfig = getAgentConfig('Migration AnonCreds Credential Records 0.4-0.5')
const registry = new InMemoryAnonCredsRegistry()
const anonCredsModuleConfig = new AnonCredsModuleConfig({
  anoncreds,
  registries: [registry],
})

const wallet = { generateNonce: () => Promise.resolve('947121108704767252195123') } as Wallet

const stop = new Subject<boolean>()
const eventEmitter = new EventEmitter(agentDependencies, stop)

const w3cRepo = {
  save: jest.fn(),
  update: jest.fn(),
}

const credentialExchangeRepo = {
  findByQuery: jest.fn(),
  update: jest.fn(),
}

const inMemoryLruCache = {
  get: jest.fn(),
  set: jest.fn(),
  clear: jest.fn(),
  remove: jest.fn(),
}

const cacheModuleConfig = new CacheModuleConfig({
  cache: inMemoryLruCache,
})

const inMemoryStorageService = new InMemoryStorageService()

const agentContext = getAgentContext({
  registerInstances: [
    [CacheModuleConfig, cacheModuleConfig],
    [EventEmitter, eventEmitter],
    [W3cCredentialRepository, w3cRepo],
    [CredentialRepository, credentialExchangeRepo],
    [InjectionSymbols.Stop$, new Subject<boolean>()],
    [InjectionSymbols.AgentDependencies, agentDependencies],
    [InjectionSymbols.FileSystem, new agentDependencies.FileSystem()],
    [InjectionSymbols.StorageService, inMemoryStorageService],
    [AnonCredsRegistryService, new AnonCredsRegistryService()],
    [DidResolverService, new DidResolverService(testLogger, new DidsModuleConfig(), {} as unknown as DidRepository)],
    [InjectionSymbols.Logger, testLogger],
    [W3cCredentialsModuleConfig, new W3cCredentialsModuleConfig()],
    [AnonCredsModuleConfig, anonCredsModuleConfig],
    [AnonCredsHolderServiceSymbol, new AnonCredsRsHolderService()],
    [SignatureSuiteToken, 'default'],
  ],
  agentConfig,
  wallet,
})

const anonCredsRepo = {
  getAll: jest.fn(),
  delete: jest.fn(),
}

jest.mock('../../../../../core/src/agent/Agent', () => {
  return {
    Agent: jest.fn(() => ({
      config: agentConfig,
      context: agentContext,
      dependencyManager: {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        resolve: jest.fn((repo: any) => {
          if (repo.prototype.constructor.name === 'AnonCredsCredentialRepository') {
            return anonCredsRepo
          }
          throw new Error(`Couldn't resolve dependency`)
        }),
      },
    })),
  }
})

// Mock typed object
const AgentMock = Agent as jest.Mock<Agent>

describe('0.4-0.5 | AnonCredsRecord', () => {
  let agent: Agent

  describe('migrateW3cCredentialRecordToV0_5()', () => {
    beforeEach(() => {
      anonCredsRepo.delete.mockClear()
      anonCredsRepo.getAll.mockClear()
      credentialExchangeRepo.findByQuery.mockClear()
      credentialExchangeRepo.update.mockClear()
      w3cRepo.save.mockClear()
      w3cRepo.update.mockClear()
      inMemoryLruCache.clear.mockClear()
      inMemoryLruCache.get.mockClear()
      inMemoryLruCache.set.mockClear()
      inMemoryLruCache.remove.mockClear()

      agent = new AgentMock()
    })

    it('credential with cheqd identifier', async () => {
      await testMigration(agent, {
        issuerId: 'did:cheqd:mainnet:7BPMqYgYLQni258J8JPS8L',
        schemaIssuerId: 'did:cheqd:mainnet:7BPMqYgYLQni258J8JPS8K',
        schemaId: 'did:cheqd:mainnet:7BPMqYgYLQni258J8JPS8K/resources/6259d357-eeb1-4b98-8bee-12a8390d3497',
      })
    })

    it('credential with did:indy (sovrin) identifier', async () => {
      await testMigration(agent, {
        issuerId: 'did:indy:sovrin:7Tqg6BwSSWapxgUDm9KKgg',
        schemaIssuerId: 'did:indy:sovrin:7Tqg6BwSSWapxgUDm9KKgf',
        schemaId: 'did:indy:sovrin:LjgpST2rjsoxYegQDRm7EL/anoncreds/v0/SCHEMA/Employee Credential/1.0.0',
        indyNamespace: 'sovrin',
      })
    })

    it('revocable credential with did:indy (sovrin) identifier', async () => {
      await testMigration(agent, {
        issuerId: 'did:indy:sovrin:7Tqg6BwSSWapxgUDm9KKgg',
        schemaIssuerId: 'did:indy:sovrin:7Tqg6BwSSWapxgUDm9KKgf',
        schemaId: 'did:indy:sovrin:LjgpST2rjsoxYegQDRm7EL/anoncreds/v0/SCHEMA/Employee Credential/1.0.0',
        indyNamespace: 'sovrin',
        revocable: true,
      })
    })

    it('credential with unqualified did:indy (bcovrin:test) identifiers', async () => {
      await testMigration(agent, {
        issuerId: getUnQualifiedDidIndyDid('did:indy:bcovrin:test:SDqTzbVuCowusqGBNbNDjH'),
        schemaIssuerId: getUnQualifiedDidIndyDid('did:indy:bcovrin:test:SDqTzbVuCowusqGBNbNDjG'),
        schemaId: getUnQualifiedDidIndyDid(
          'did:indy:bcovrin:test:SDqTzbVuCowusqGBNbNDjG/anoncreds/v0/SCHEMA/Employee Credential/1.0.0'
        ),
        indyNamespace: 'bcovrin:test',
      })
    })

    it('revocable credential with unqualified did:indy (bcovrin:test) identifiers', async () => {
      await testMigration(agent, {
        issuerId: getUnQualifiedDidIndyDid('did:indy:bcovrin:test:SDqTzbVuCowusqGBNbNDjH'),
        schemaIssuerId: getUnQualifiedDidIndyDid('did:indy:bcovrin:test:SDqTzbVuCowusqGBNbNDjG'),
        schemaId: getUnQualifiedDidIndyDid(
          'did:indy:bcovrin:test:SDqTzbVuCowusqGBNbNDjG/anoncreds/v0/SCHEMA/Employee Credential/1.0.0'
        ),
        indyNamespace: 'bcovrin:test',
        revocable: true,
      })
    })

    it('credential with cached unqualified did:indy (bcovrin:test) identifiers', async () => {
      inMemoryLruCache.get.mockReturnValueOnce({ indyNamespace: 'bcovrin:test' })

      await testMigration(agent, {
        issuerId: getUnQualifiedDidIndyDid('did:indy:bcovrin:test:SDqTzbVuCowusqGBNbNDjH'),
        schemaIssuerId: getUnQualifiedDidIndyDid('did:indy:bcovrin:test:SDqTzbVuCowusqGBNbNDjG'),
        schemaId: getUnQualifiedDidIndyDid(
          'did:indy:bcovrin:test:SDqTzbVuCowusqGBNbNDjG/anoncreds/v0/SCHEMA/Employee Credential/1.0.0'
        ),
        indyNamespace: 'bcovrin:test',
        shouldBeInCache: 'indy',
      })
    })

    it('credential with cached unqualified did:sov identifiers', async () => {
      inMemoryLruCache.get.mockReturnValueOnce(null).mockReturnValueOnce({ indyNamespace: 'sov' })

      await testMigration(agent, {
        issuerId: 'SDqTzbVuCowusqGBNbNDjH',
        schemaIssuerId: 'SDqTzbVuCowusqGBNbNDjG',
        schemaId: 'SDqTzbVuCowusqGBNbNDjG:2:Employee Credential:1.0.0',
        indyNamespace: 'sov',
        shouldBeInCache: 'sov',
      })
    })
  })
})

async function testMigration(
  agent: Agent,
  options: {
    issuerId: string
    schemaIssuerId: string
    schemaId: string
    indyNamespace?: string
    shouldBeInCache?: 'indy' | 'sov'
    revocable?: boolean
  }
) {
  const { issuerId, schemaIssuerId, schemaId, indyNamespace, revocable } = options

  const registry = agentContext.dependencyManager
    .resolve(AnonCredsRegistryService)
    .getRegistryForIdentifier(agentContext, issuerId)

  const { credentialDefinitionState } = await registry.registerCredentialDefinition(agentContext, {
    credentialDefinition: {
      schemaId: indyNamespace ? getQualifiedDidIndyDid(schemaId, indyNamespace) : schemaId,
      type: 'CL',
      tag: 'Employee Credential',
      value: {
        primary: {
          n: '96580316873365712442732878101936646890604119889300256012760004147648019614357085076364923021085826868139621573684543249964678348356482485140527957732786530916400278400000660594438781319168272211306232441102713960203075436899295821371799038925693667322779688360706410505540407867607819490853610928774850151039047069357657140257065718659230885391255982730600838743036039711140083284918623906117435892506848479452322000479436955298502839148769930281251929368562720371560260726440893569655811165804238971700685368149522154328822673070750192788830837447670660152195003043802510899143110060139772708073728514051890251226573',
          s: '75501169085950126423249157998833414929129208062284812993616444532525695129548804062583842133218092574263501104948737639625833940700883624316320978432322582288936701621781896861131284952998380826417162040016550587340823832731945229065884469806723217100370126833740077464404509861175397581089717495779179489233739975691055780558708056569691296866880514640011052194662545371451908889892210433975411453987754134291774476185207289195701174795140189362641644917865101153841235103322243375241496141786303488408131721122704625842138002478498178520263715598899259097315781832554764315008915688899555385079843761690822607379111',
          r: {
            age: '77540670431411230038763922593314057361920691860149780021247345546110594816960144474334769978922558437548167814211078474008950463908860798685487527066465227411414311215109347438752200023045503271169383262727401013107872116564443896905324906462332380026785798806953280066387451803949226448584225962096665020244191229063723249351163778395354282347357165322007286709571349618598645876371030907856017571738360851407364231328550357981247798517795822722356010859380461592920151980368953491924564759581591539937752386114770938355831372517555540534219652937595339962248857890418611836415170566769174263185424389504546847791061',
            name: '56742811203198572257254422595806148480437594543198516349563027967943211653217799525148065500107783030709376059668814822301811566517601408461597171188532787265942263962719966788682945248064629136273708677025304469521003291988851716171767936997105137959854045442533627185824896706311588434426708666794422548240008058413804660062414897767172901561637004230184962449104905433874433106461860673266368007446282814453132977549811373164579634926487398703746240854572636222768903661936542049761028833196194927339141225860442129881312421875004614067598828714629143133815560576383442835845338263420621113398541139833020926358483',
            master_secret:
              '47747144545528691003767568337472105276331891233385663931584274593369979405459771996932889017746007711684586508906823242148854224004122637231405489854166589517019033322603946444431305440324935310636815918200611202700765046091022859325187263050783813756813224792976045471735525150004048149843525973339369133943560241544453714388862237336971069786113757093274533177228170822141225802024684552058049687105759446916872700318309370449824235232087307054291066123530983268176971897233515383614938649406180978604188604030816485303101208443369021847829704196934707372786773595567687934642471997496883786836109942269282274646821',
          },
          rctxt:
            '56624145913410031711009467194049739028044689257231550726399481216874451927585543568732728200991667356553765568186221627220562697315384161695993324560029249334601709666000269987161110370944904361123034293076300325831500797294972192392858769494862446579930065658123775287266632055490150224877768031718759385137678458946705469525103921298013633970637295409365635673547258006414068589487568446936418629870049873056708576696589883095398217681918429160130132727488662842876963800048249179530353781028982129766362865351617486193454223628637074575525915653459208863652607756131262546529918749753409703149380392151341320092701',
          z: '48207831484908089113913456529606728278875173243133137568203149862235480864817131176165695429997836542014395411854617371967345903846590322848315574430219622375108777832406077167357765312048126429295008846417923207098159790545077579480434122704652997388986707634157186643373176212809933891460515705299787583898608744041271224726626894030124816906292858431898018633343059228110335652476641836263281987023563730093708908265403781917908475102010080313484277539579578010231066258146934633395220956275733173978548481848026533424513200278825491847270318469226963088243667105115637069262564294713288882078385391140385504192475',
        },
      },
      issuerId: indyNamespace ? getQualifiedDidIndyDid(issuerId, indyNamespace) : issuerId,
    },
    options: {},
  })

  if (!credentialDefinitionState.credentialDefinitionId)
    throw new CredoError('Registering Credential Definition Failed')

  // We'll use unqualified form in case the inputs are unqualified as well
  const credentialDefinitionId =
    indyNamespace && isUnqualifiedIndyDid(issuerId)
      ? getUnQualifiedDidIndyDid(credentialDefinitionState.credentialDefinitionId)
      : credentialDefinitionState.credentialDefinitionId
  let revocationRegistryDefinitionId: string | undefined

  if (revocable) {
    const { revocationRegistryDefinitionState } = await registry.registerRevocationRegistryDefinition(agentContext, {
      revocationRegistryDefinition: {
        credDefId: credentialDefinitionState.credentialDefinitionId,
        issuerId: indyNamespace ? getQualifiedDidIndyDid(issuerId, indyNamespace) : issuerId,
        revocDefType: 'CL_ACCUM',
        value: {
          publicKeys: {
            accumKey: {
              z: 'ab81257c-be63-4051-9e21-c7d384412f64',
            },
          },
          maxCredNum: 100,
          tailsHash: 'ab81257c-be63-4051-9e21-c7d384412f64',
          tailsLocation: 'http://localhost:7200/tails',
        },
        tag: 'TAG',
      },
      options: {},
    })
    if (!revocationRegistryDefinitionState.revocationRegistryDefinitionId)
      throw new CredoError('Registering Revocation Registry Definition Failed')

    revocationRegistryDefinitionId =
      indyNamespace && isUnqualifiedIndyDid(issuerId)
        ? getUnQualifiedDidIndyDid(revocationRegistryDefinitionState.revocationRegistryDefinitionId)
        : revocationRegistryDefinitionState.revocationRegistryDefinitionId
  }

  const anonCredsRecord = new AnonCredsCredentialRecord({
    credential: {
      schema_id: schemaId,
      cred_def_id: credentialDefinitionId,
      values: {
        name: {
          raw: 'John',
          encoded: '76355713903561865866741292988746191972523015098789458240077478826513114743258',
        },
        age: { raw: '25', encoded: '25' },
      },
      signature: {
        p_credential: {
          m_2: '96181142928573619139692730181044468294945970900261235940698944149443005219418',
          a: '95552886901127172841432400616361951122825637102065915900211722444153579891548765880931308692457984326066263506661706967742637168349111737200116541217341739027256190535822337883555402874901690699603230292607481206740216276736875319709356355255797288879451730329296366840213920367976178079664448005608079197649139477441385127107355597906058676699377491628047651331689288017597714832563994968230904723400034478518535411493372596211553797813567090114739752408151368926090849149021350138796163980103411453098000223493524437564062789271302371287568506870484060911412715559140166845310368136412863128732929561146328431066870',
          e: '259344723055062059907025491480697571938277889515152306249728583105665800713306759149981690559193987143012367913206299323899696942213235956742929837794489002147266183999965799605813',
          v: '8070312275110314663750247899433202850238560575163878956819342967827136399370879736823043902982634515009588016797203155246614708232573921376646871743359587732590693401587607271972304303322060390310307460889523961550612965021232979808509508502354241838342542729225461467834597352210800168107201638861601487760961526713355932504366874557170337152964069325172574449356691055377568302458374147949937789910094307449082152173580675507028369533914480926873196435808261915052547630680304620062203647948590064800546491641963412948122135194369131128319694594446518925913583118382698018169919523769679141724867515604189334120099773703979769794325694804992635522127820413717601811493634024617930397944903746555691677663850240187799372670069559074549528342288602574968520156320273386872799429362106185458798531573424651644586691950218',
        },
        r_credential: null,
      },
      signature_correctness_proof: {
        se: '22707379000451320101568757017184696744124237924783723059712360528872398590682272715197914336834321599243107036831239336605987281577690130807752876870302232265860540101807563741012022740942625464987934377354684266599492895835685698819662114798915664525092894122648542269399563759087759048742378622062870244156257780544523627249100818371255142174054148531811440128609220992508274170196108004985441276737673328642493312249112077836369109453214857237693701603680205115444482751700483514317558743227403858290707747986550689265796031162549838465391957776237071049436590886476581821857234951536091662216488995258175202055258',
        c: '86499530658088050169174214946559930902913340880816576251403968391737698128027',
      },
      rev_reg: revocable
        ? {
            accum:
              '2 1ECC5AB3496DF286013468F9DC94FA57D2E0CB65809130F49493884DA849D88A 2 20F3F79A24E29B3DF958FA5471B68CAF2FBBAF8E3D3A1F8F17BC5E410242A1BE 2 071C3E27F50B72EB048E530E0A07AC87B5578A63678803D009A9D40E5D3E41B8 2 0E9330E77B1A56DE5C70C8D9B02658CF571F4465EA489A7CEA12CFDA1A311AF5 2 095E45DDF417D05FB10933FFC63D474548B7FFFF7888802F07FFFFFF7D07A8A8 1 0000000000000000000000000000000000000000000000000000000000000000',
          }
        : undefined,
      witness: revocable
        ? {
            omega:
              '2 024D139F10D86B41FDFE98064B5794D0AFEE6183192A7CC2007803532F38CDB9 2 0AC11C34FDEDCA60FFD23E4FC37C9FAFB29737990D6B7E81190AA8C1BF654034 2 04CCBF871DA8BAB94769B08CBE777E83994F121F8BE1F64D3DE90EC6E2401EA9 2 1539F896A2C98798624E2AE12A0D2941EE898570BE3F0F40E59928008F95C969 2 095E45DDF417D05FB10933FFC63D474548B7FFFF7888802F07FFFFFF7D07A8A8 1 0000000000000000000000000000000000000000000000000000000000000000',
          }
        : undefined,

      rev_reg_id: revocable ? revocationRegistryDefinitionId : undefined,
    },
    credentialId: 'myCredentialId',
    credentialRevocationId: revocable ? '1' : undefined,
    linkSecretId: 'linkSecretId',
    issuerId,
    schemaIssuerId,
    schemaName: 'schemaName',
    schemaVersion: 'schemaVersion',
    methodName: 'methodName',
  })

  anonCredsRecord.metadata.set('custom', {
    key: 'value',
  })
  const records = [anonCredsRecord]

  mockFunction(anonCredsRepo.getAll).mockResolvedValue(records)

  const initialCredentialExchangeRecord = new CredentialExchangeRecord({
    protocolVersion: 'v2',
    role: CredentialRole.Holder,
    state: CredentialState.Done,
    threadId: 'threadId',
    credentials: [
      {
        credentialRecordId: anonCredsRecord.credentialId,
        credentialRecordType: 'anoncreds',
      },
    ],
    tags: {
      credentialDefinitionId,
      issuerId,
      revocationRegistryId: revocationRegistryDefinitionId,
      schemaId,
      schemaIssuerId,
    },
  })

  mockFunction(credentialExchangeRepo.findByQuery).mockResolvedValue([initialCredentialExchangeRecord])

  await testModule.storeAnonCredsInW3cFormatV0_5(agent)

  const unqualifiedDidIndyDid = isUnqualifiedIndyDid(issuerId)
  if (unqualifiedDidIndyDid) {
    expect(inMemoryLruCache.get).toHaveBeenCalledTimes(
      options.shouldBeInCache === 'sov' || !options.shouldBeInCache ? 2 : 1
    )
    expect(inMemoryLruCache.get).toHaveBeenCalledWith(
      agent.context,
      options.shouldBeInCache === 'sov' || !options.shouldBeInCache
        ? 'IndySdkPoolService:' + issuerId
        : 'IndyVdrPoolService:' + issuerId
    )
  } else {
    expect(inMemoryLruCache.get).toHaveBeenCalledTimes(0)
  }

  expect(anonCredsRepo.getAll).toHaveBeenCalledTimes(1)
  expect(anonCredsRepo.getAll).toHaveBeenCalledWith(agent.context)
  expect(w3cRepo.save).toHaveBeenCalledTimes(1)
  const [context, w3cCredentialRecord] = mockFunction(w3cRepo.save).mock.calls[0]
  expect(context).toMatchObject(agent.context)
  expect(w3cCredentialRecord).toMatchObject({
    metadata: expect.objectContaining({
      data: expect.objectContaining({
        custom: { key: 'value' },
      }),
    }),
  })

  expect(w3cRepo.update).toHaveBeenCalledTimes(1)
  expect(anonCredsRepo.delete).toHaveBeenCalledTimes(1)
  expect(credentialExchangeRepo.findByQuery).toHaveBeenCalledTimes(1)
  expect(credentialExchangeRepo.findByQuery).toHaveBeenCalledWith(agent.context, {
    credentialIds: [anonCredsRecord.credentialId],
  })
  expect(credentialExchangeRepo.update).toHaveBeenCalledTimes(1)
  expect(credentialExchangeRepo.update).toHaveBeenCalledWith(
    agent.context,
    expect.objectContaining({
      credentials: [{ credentialRecordType: 'w3c', credentialRecordId: w3cCredentialRecord.id }],
    })
  )

  if (revocable) {
    // TODO
    expect(credentialExchangeRepo.update).toHaveBeenCalledWith(
      agent.context,
      expect.objectContaining({
        credentials: [{ credentialRecordType: 'w3c', credentialRecordId: w3cCredentialRecord.id }],
      })
    )
  }

  if (unqualifiedDidIndyDid && options.shouldBeInCache) {
    expect(inMemoryLruCache.get).toHaveReturnedWith({ indyNamespace })
  } else if (unqualifiedDidIndyDid && !options.shouldBeInCache) {
    expect(inMemoryLruCache.get).toHaveBeenCalledTimes(2)
  } else {
    expect(inMemoryLruCache.get).toHaveBeenCalledTimes(0)
  }
}
