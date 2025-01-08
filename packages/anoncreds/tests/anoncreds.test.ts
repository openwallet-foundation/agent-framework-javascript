import { Agent, KeyType, TypedArrayEncoder } from '@credo-ts/core'

import { getInMemoryAgentOptions } from '../../core/tests'
import { AnonCredsModule } from '../src'

import { InMemoryAnonCredsRegistry } from './InMemoryAnonCredsRegistry'
import { anoncreds } from './helpers'

const existingSchemas = {
  '7Cd2Yj9yEZNcmNoH54tq9i:2:Test Schema:1.0.0': {
    attrNames: ['one', 'two'],
    issuerId: '7Cd2Yj9yEZNcmNoH54tq9i',
    name: 'Test Schema',
    version: '1.0.0',
  },
}

const existingCredentialDefinitions = {
  'VsKV7grR1BUE29mG2Fm2kX:3:CL:75206:TAG': {
    issuerId: 'VsKV7grR1BUE29mG2Fm2kX',
    tag: 'TAG',
    schemaId: '7Cd2Yj9yEZNcmNoH54tq9i:2:Test Schema:1.0.0',
    type: 'CL',
    value: {
      primary: {
        n: '92511867718854414868106363741369833735017762038454769060600859608405811709675033445666654908195955460485998711087020152978597220168927505650092431295783175164390266561239892662085428655566792056852960599485298025843840058914610127716620252006466964070280255168745873592143068949458568751438337748294055976926080232538440619420568859737673474560851456027625679328271511966332808025880807996449998057729417608399774744254122385012832309402226532031122728445959276178939234308090390331654445053482963947804769291501664200141562885660084823885847247231002821472258218384342423605116504024514572826071246440130942849549441',
        s: '80388543865249952799447792504739237616187770512259677275061283897050980768551818104137338144380636412773836688624071360386172349725818126495487584981520630638409717065318132420766896092370913800616033623618952639023946750307405126873476182540669638841562357523429245685476919178722373320218824590869735129801004394337640642997250464303104754942997839179333543643110326022824394934965538190976474473353762308333205671176627192797138375084260446324344637548455228161138089974447059481109651156379803576163576511072261388342837813901850712083922506433336723723235701670225584863772222447543742649328218950436824219992164',
        r: {
          one: '676933340341980399002624386891134393471002096508227567343731826159610079436978196421307099268754545293545727546242372579987825752872485684085629459107300175443328323289748793060894500514926703654606851666031895448970879827423190730510730624784665299646624113512701254199984520803796529034094958026048762178753193812250643294518237843809104055653333871102658177900702978008644780459400512716361564897282969982554031820285585105004870317861287847206222714589633178648982299799311192432563797220854755882933052881306804544233529886513105815543097685128456041780804442879272476590077760678785460726492895806240870944398',
          master_secret:
            '57770757113548032970308439965749734133430520933173186296299026579579930337912607419798836831937319372744879560676750427054135869214212225572618340088847222727882935159356459822445182287686057012197046378986248048722180093079919306125315662058290895629438767985427829790980355162853804522854494960613869765167538645624719923127052541372069255024631093663068055100579264049925388231368871107383977060590248865498902704546409806115171120555709438784189721957301548212242748685629860268468247494986146122636455769804467583612610341632602695197189514316033637331733820369170763954604394734655429769801516997967996980978751',
          two: '60366631925664005237432731340682977203246802182440530784833565276111958129922833461368205267143124766208499918438803966972947830682551774196763124331578934778868938718942789067536194229546670608604626738087066151521062180022991840618459591148096543440942293686250499935227881144460486543061212259250663566176469333982946568767707989969471450673037590849807300874360022327312564559087769485266016496010132793446151658150957771177955095876947792797176338483943233433284791481746843006255371654617950568875773118157773566188096075078351362095061968279597354733768049622048871890495958175847017320945873812850638157518451',
        },
        rctxt:
          '19574881057684356733946284215946569464410211018678168661028327420122678446653210056362495902735819742274128834330867933095119512313591151219353395069123546495720010325822330866859140765940839241212947354612836044244554152389691282543839111284006009168728161183863936810142428875817934316327118674532328892591410224676539770085459540786747902789677759379901079898127879301595929571621032704093287675668250862222728331030586585586110859977896767318814398026750215625180255041545607499673023585546720788973882263863911222208020438685873501025545464213035270207099419236974668665979962146355749687924650853489277747454993',
        z: '18569464356833363098514177097771727133940629758890641648661259687745137028161881113251218061243607037717553708179509640909238773964066423807945164288256211132195919975343578956381001087353353060599758005375631247614777454313440511375923345538396573548499287265163879524050255226779884271432737062283353279122281220812931572456820130441114446870167673796490210349453498315913599982158253821945225264065364670730546176140788405935081171854642125236557475395879246419105888077042924382595999612137336915304205628167917473420377397118829734604949103124514367857266518654728464539418834291071874052392799652266418817991437',
      },
    },
  },
} as const

const existingRevocationRegistryDefinitions = {
  'VsKV7grR1BUE29mG2Fm2kX:4:VsKV7grR1BUE29mG2Fm2kX:3:CL:75206:TAG:CL_ACCUM:TAG': {
    credDefId: 'VsKV7grR1BUE29mG2Fm2kX:3:CL:75206:TAG',
    issuerId: 'VsKV7grR1BUE29mG2Fm2kX',
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
} as const

const existingRevocationStatusLists = {
  'VsKV7grR1BUE29mG2Fm2kX:4:VsKV7grR1BUE29mG2Fm2kX:3:CL:75206:TAG:CL_ACCUM:TAG': {
    10123: {
      currentAccumulator: 'ab81257c-be63-4051-9e21-c7d384412f64',
      issuerId: 'VsKV7grR1BUE29mG2Fm2kX',
      revocationList: [1, 0, 1],
      revRegDefId: 'VsKV7grR1BUE29mG2Fm2kX:4:VsKV7grR1BUE29mG2Fm2kX:3:CL:75206:TAG:CL_ACCUM:TAG',
      timestamp: 10123,
    },
  },
}

const agent = new Agent(
  getInMemoryAgentOptions(
    'credo-anoncreds-package',
    {},
    {},
    {
      anoncreds: new AnonCredsModule({
        autoCreateLinkSecret: false,
        anoncreds,
        registries: [
          new InMemoryAnonCredsRegistry({
            existingSchemas,
            existingCredentialDefinitions,
            existingRevocationRegistryDefinitions,
            existingRevocationStatusLists,
          }),
        ],
      }),
    }
  )
)

describe('AnonCreds API', () => {
  beforeEach(async () => {
    await agent.initialize()
  })

  afterEach(async () => {
    await agent.wallet.delete()
    await agent.shutdown()
  })

  test('create and get link secret', async () => {
    await agent.modules.anoncreds.createLinkSecret({
      linkSecretId: 'anoncreds-link-secret',
    })

    const linkSecretIds = await agent.modules.anoncreds.getLinkSecretIds()

    expect(linkSecretIds).toEqual(['anoncreds-link-secret'])
  })

  test('register a schema', async () => {
    const schemaResult = await agent.modules.anoncreds.registerSchema({
      options: {},
      schema: {
        attrNames: ['name', 'age'],
        issuerId: 'did:indy:pool:localtest:6xDN7v3AiGgusRp4bqZACZ',
        name: 'Employee Credential',
        version: '1.0.0',
      },
    })

    expect(schemaResult).toEqual({
      registrationMetadata: {},
      schemaMetadata: {},
      schemaState: {
        state: 'finished',
        schema: {
          attrNames: ['name', 'age'],
          issuerId: 'did:indy:pool:localtest:6xDN7v3AiGgusRp4bqZACZ',
          name: 'Employee Credential',
          version: '1.0.0',
        },
        schemaId: 'did:indy:pool:localtest:6xDN7v3AiGgusRp4bqZACZ/anoncreds/v0/SCHEMA/Employee Credential/1.0.0',
      },
    })

    // Check if record was created
    const [schemaRecord] = await agent.modules.anoncreds.getCreatedSchemas({
      schemaId: 'did:indy:pool:localtest:6xDN7v3AiGgusRp4bqZACZ/anoncreds/v0/SCHEMA/Employee Credential/1.0.0',
    })
    expect(schemaRecord).toMatchObject({
      schemaId: 'did:indy:pool:localtest:6xDN7v3AiGgusRp4bqZACZ/anoncreds/v0/SCHEMA/Employee Credential/1.0.0',
      methodName: 'inMemory',
      schema: {
        attrNames: ['name', 'age'],
        issuerId: 'did:indy:pool:localtest:6xDN7v3AiGgusRp4bqZACZ',
        name: 'Employee Credential',
        version: '1.0.0',
      },
    })

    expect(schemaRecord.getTags()).toEqual({
      schemaId: 'did:indy:pool:localtest:6xDN7v3AiGgusRp4bqZACZ/anoncreds/v0/SCHEMA/Employee Credential/1.0.0',
      issuerId: 'did:indy:pool:localtest:6xDN7v3AiGgusRp4bqZACZ',
      schemaName: 'Employee Credential',
      schemaVersion: '1.0.0',
      methodName: 'inMemory',
      unqualifiedSchemaId: '6xDN7v3AiGgusRp4bqZACZ:2:Employee Credential:1.0.0',
    })
  })

  test('resolve a schema', async () => {
    const schemaResult = await agent.modules.anoncreds.getSchema('7Cd2Yj9yEZNcmNoH54tq9i:2:Test Schema:1.0.0')

    expect(schemaResult).toEqual({
      resolutionMetadata: {},
      schemaMetadata: {},
      schema: {
        attrNames: ['one', 'two'],
        issuerId: '7Cd2Yj9yEZNcmNoH54tq9i',
        name: 'Test Schema',
        version: '1.0.0',
      },
      schemaId: '7Cd2Yj9yEZNcmNoH54tq9i:2:Test Schema:1.0.0',
    })
  })

  test('register a credential definition', async () => {
    // Create key
    await agent.wallet.createKey({
      privateKey: TypedArrayEncoder.fromString('00000000000000000000000000000My1'),
      keyType: KeyType.Ed25519,
    })

    const issuerId = 'did:indy:pool:localhost:VsKV7grR1BUE29mG2Fm2kX'

    const credentialDefinitionResult = await agent.modules.anoncreds.registerCredentialDefinition({
      credentialDefinition: {
        issuerId,
        schemaId: '7Cd2Yj9yEZNcmNoH54tq9i:2:Test Schema:1.0.0',
        tag: 'TAG',
      },
      options: {
        supportRevocation: false,
      },
    })

    expect(credentialDefinitionResult).toEqual({
      registrationMetadata: {},
      credentialDefinitionMetadata: {},
      credentialDefinitionState: {
        state: 'finished',
        credentialDefinition: {
          issuerId: 'did:indy:pool:localhost:VsKV7grR1BUE29mG2Fm2kX',
          tag: 'TAG',
          schemaId: '7Cd2Yj9yEZNcmNoH54tq9i:2:Test Schema:1.0.0',
          type: 'CL',
          value: {
            primary: {
              n: expect.any(String),
              s: expect.any(String),
              r: {
                one: expect.any(String),
                master_secret: expect.any(String),
                two: expect.any(String),
              },
              rctxt: expect.any(String),
              z: expect.any(String),
            },
          },
        },
        credentialDefinitionId: 'did:indy:pool:localhost:VsKV7grR1BUE29mG2Fm2kX/anoncreds/v0/CLAIM_DEF/75206/TAG',
      },
    })

    const [credentialDefinitionRecord] = await agent.modules.anoncreds.getCreatedCredentialDefinitions({
      credentialDefinitionId: 'did:indy:pool:localhost:VsKV7grR1BUE29mG2Fm2kX/anoncreds/v0/CLAIM_DEF/75206/TAG',
    })
    expect(credentialDefinitionRecord).toMatchObject({
      credentialDefinitionId: 'did:indy:pool:localhost:VsKV7grR1BUE29mG2Fm2kX/anoncreds/v0/CLAIM_DEF/75206/TAG',
      methodName: 'inMemory',
      credentialDefinition: {
        issuerId: 'did:indy:pool:localhost:VsKV7grR1BUE29mG2Fm2kX',
        tag: 'TAG',
        schemaId: '7Cd2Yj9yEZNcmNoH54tq9i:2:Test Schema:1.0.0',
        type: 'CL',
        value: {
          primary: {
            n: expect.any(String),
            s: expect.any(String),
            r: {
              one: expect.any(String),
              master_secret: expect.any(String),
              two: expect.any(String),
            },
            rctxt: expect.any(String),
            z: expect.any(String),
          },
        },
      },
    })

    expect(credentialDefinitionRecord.getTags()).toEqual({
      methodName: 'inMemory',
      credentialDefinitionId: 'did:indy:pool:localhost:VsKV7grR1BUE29mG2Fm2kX/anoncreds/v0/CLAIM_DEF/75206/TAG',
      schemaId: '7Cd2Yj9yEZNcmNoH54tq9i:2:Test Schema:1.0.0',
      issuerId: 'did:indy:pool:localhost:VsKV7grR1BUE29mG2Fm2kX',
      tag: 'TAG',
      unqualifiedCredentialDefinitionId: 'VsKV7grR1BUE29mG2Fm2kX:3:CL:75206:TAG',
    })
  })

  test('resolve a credential definition', async () => {
    const credentialDefinitionResult = await agent.modules.anoncreds.getCredentialDefinition(
      'VsKV7grR1BUE29mG2Fm2kX:3:CL:75206:TAG'
    )

    expect(credentialDefinitionResult).toEqual({
      resolutionMetadata: {},
      credentialDefinitionMetadata: {
        didIndyNamespace: 'pool:localhost',
      },
      credentialDefinition: existingCredentialDefinitions['VsKV7grR1BUE29mG2Fm2kX:3:CL:75206:TAG'],
      credentialDefinitionId: 'VsKV7grR1BUE29mG2Fm2kX:3:CL:75206:TAG',
    })
  })

  test('resolve a revocation regsitry definition', async () => {
    const revocationRegistryDefinition = await agent.modules.anoncreds.getRevocationRegistryDefinition(
      'VsKV7grR1BUE29mG2Fm2kX:4:VsKV7grR1BUE29mG2Fm2kX:3:CL:75206:TAG:CL_ACCUM:TAG'
    )

    expect(revocationRegistryDefinition).toEqual({
      revocationRegistryDefinitionId: 'VsKV7grR1BUE29mG2Fm2kX:4:VsKV7grR1BUE29mG2Fm2kX:3:CL:75206:TAG:CL_ACCUM:TAG',
      revocationRegistryDefinition:
        existingRevocationRegistryDefinitions[
          'VsKV7grR1BUE29mG2Fm2kX:4:VsKV7grR1BUE29mG2Fm2kX:3:CL:75206:TAG:CL_ACCUM:TAG'
        ],
      resolutionMetadata: {},
      revocationRegistryDefinitionMetadata: {},
    })
  })

  test('resolve a revocation status list', async () => {
    const revocationStatusList = await agent.modules.anoncreds.getRevocationStatusList(
      'VsKV7grR1BUE29mG2Fm2kX:4:VsKV7grR1BUE29mG2Fm2kX:3:CL:75206:TAG:CL_ACCUM:TAG',
      10123
    )

    expect(revocationStatusList).toEqual({
      revocationStatusList:
        existingRevocationStatusLists[
          'VsKV7grR1BUE29mG2Fm2kX:4:VsKV7grR1BUE29mG2Fm2kX:3:CL:75206:TAG:CL_ACCUM:TAG'
        ][10123],
      resolutionMetadata: {},
      revocationStatusListMetadata: {},
    })
  })
})
