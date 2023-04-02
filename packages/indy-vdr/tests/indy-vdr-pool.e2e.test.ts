import type { Key } from '@aries-framework/core'

import { TypedArrayEncoder, KeyType, SigningProviderRegistry } from '@aries-framework/core'
import { GetNymRequest, NymRequest, SchemaRequest, CredentialDefinitionRequest } from '@hyperledger/indy-vdr-shared'

import { genesisTransactions, getAgentConfig, getAgentContext } from '../../core/tests/helpers'
import testLogger from '../../core/tests/logger'
import { IndySdkWallet } from '../../indy-sdk/src'
import { indySdk } from '../../indy-sdk/tests/setupIndySdkModule'
import { IndyVdrPool } from '../src/pool'
import { IndyVdrPoolService } from '../src/pool/IndyVdrPoolService'
import { indyDidFromPublicKeyBase58 } from '../src/utils/did'

import { indyVdrModuleConfig } from './helpers'

const indyVdrPoolService = new IndyVdrPoolService(testLogger, indyVdrModuleConfig)
const wallet = new IndySdkWallet(indySdk, testLogger, new SigningProviderRegistry([]))
const agentConfig = getAgentConfig('IndyVdrPoolService')
const agentContext = getAgentContext({ wallet, agentConfig })

const config = {
  isProduction: false,
  genesisTransactions,
  indyNamespace: `pool:localtest`,
  transactionAuthorAgreement: { version: '1', acceptanceMechanism: 'accept' },
} as const

let signerKey: Key

describe('IndyVdrPoolService', () => {
  beforeAll(async () => {
    await wallet.createAndOpen(agentConfig.walletConfig)

    signerKey = await wallet.createKey({
      privateKey: TypedArrayEncoder.fromString('000000000000000000000000Trustee9'),
      keyType: KeyType.Ed25519,
    })
  })

  afterAll(async () => {
    for (const pool of indyVdrPoolService.pools) {
      pool.close()
    }

    await wallet.delete()
  })

  describe('DIDs', () => {
    test('can get a pool based on the namespace', async () => {
      const pool = indyVdrPoolService.getPoolForNamespace('pool:localtest')
      expect(pool).toBeInstanceOf(IndyVdrPool)
      expect(pool.config).toEqual(config)
    })

    test('can resolve a did using the pool', async () => {
      const pool = indyVdrPoolService.getPoolForNamespace('pool:localtest')

      const request = new GetNymRequest({
        dest: 'TL1EaPFCZ8Si5aUrqScBDt',
      })

      const response = await pool.submitReadRequest(request)

      expect(response).toMatchObject({
        op: 'REPLY',
        result: {
          dest: 'TL1EaPFCZ8Si5aUrqScBDt',
          type: '105',
          data: expect.any(String),
          identifier: 'LibindyDid111111111111',
          reqId: expect.any(Number),
          seqNo: expect.any(Number),
          txnTime: expect.any(Number),
          state_proof: expect.any(Object),
        },
      })

      expect(JSON.parse(response.result.data as string)).toMatchObject({
        dest: 'TL1EaPFCZ8Si5aUrqScBDt',
        identifier: 'V4SGRU86Z58d6TV7PBUe6f',
        role: '101',
        seqNo: expect.any(Number),
        txnTime: expect.any(Number),
        verkey: '~43X4NhAFqREffK7eWdKgFH',
      })
    })

    test('can write a did using the pool', async () => {
      const pool = indyVdrPoolService.getPoolForNamespace('pool:localtest')

      // prepare the DID we are going to write to the ledger
      const key = await wallet.createKey({ keyType: KeyType.Ed25519 })
      const did = indyDidFromPublicKeyBase58(key.publicKeyBase58)

      const request = new NymRequest({
        dest: did,
        submitterDid: 'TL1EaPFCZ8Si5aUrqScBDt',
        verkey: key.publicKeyBase58,
      })

      const response = await pool.createAndSubmitWriteRequest(agentContext, request, signerKey)

      expect(response).toMatchObject({
        op: 'REPLY',
        result: {
          txn: {
            protocolVersion: 2,
            metadata: expect.any(Object),
            data: expect.any(Object),
            type: '1',
          },
          ver: '1',
          rootHash: expect.any(String),
          txnMetadata: expect.any(Object),
        },
      })
    })
  })

  test('can write a schema and credential definition using the pool', async () => {
    const pool = indyVdrPoolService.getPoolForNamespace('pool:localtest')

    const dynamicVersion = `1.${Math.random() * 100}`

    const schemaRequest = new SchemaRequest({
      submitterDid: 'TL1EaPFCZ8Si5aUrqScBDt',
      schema: {
        id: 'test-schema-id',
        name: 'test-schema',
        ver: '1.0',
        version: dynamicVersion,
        attrNames: ['first_name', 'last_name', 'age'],
      },
    })

    const schemaResponse = await pool.createAndSubmitWriteRequest(agentContext, schemaRequest, signerKey)

    expect(schemaResponse).toMatchObject({
      op: 'REPLY',
      result: {
        ver: '1',
        txn: {
          metadata: expect.any(Object),
          type: '101',
          data: {
            data: {
              attr_names: expect.arrayContaining(['age', 'last_name', 'first_name']),
              name: 'test-schema',
              version: dynamicVersion,
            },
          },
        },
      },
    })

    const credentialDefinitionRequest = new CredentialDefinitionRequest({
      submitterDid: 'TL1EaPFCZ8Si5aUrqScBDt',
      credentialDefinition: {
        ver: '1.0',
        id: `TL1EaPFCZ8Si5aUrqScBDt:3:CL:${schemaResponse.result.txnMetadata.seqNo}:TAG`,
        // must be string version of the schema seqNo
        schemaId: `${schemaResponse.result.txnMetadata.seqNo}`,
        type: 'CL',
        tag: 'TAG',
        value: {
          primary: {
            n: '95671911213029889766246243339609567053285242961853979532076192834533577534909796042025401129640348836502648821408485216223269830089771714177855160978214805993386076928594836829216646288195127289421136294309746871614765411402917891972999085287429566166932354413679994469616357622976775651506242447852304853465380257226445481515631782793575184420720296120464167257703633829902427169144462981949944348928086406211627174233811365419264314148304536534528344413738913277713548403058098093453580992173145127632199215550027527631259565822872315784889212327945030315062879193999012349220118290071491899498795367403447663354833',
            s: '1573939820553851804028472930351082111827449763317396231059458630252708273163050576299697385049087601314071156646675105028237105229428440185022593174121924731226634356276616495327358864865629675802738680754755949997611920669823449540027707876555408118172529688443208301403297680159171306000341239398135896274940688268460793682007115152428685521865921925309154307574955324973580144009271977076586453011938089159885164705002797196738438392179082905738155386545935208094240038135576042886730802817809757582039362798495805441520744154270346780731494125065136433163757697326955962282840631850597919384092584727207908978907',
            r: {
              master_secret:
                '51468326064458249697956272807708948542001661888325200180968238787091473418947480867518174106588127385097619219536294589148765074804124925845579871788369264160902401097166484002617399484700234182426993061977152961670486891123188739266793651668791365808983166555735631354925174224786218771453042042304773095663181121735652667614424198057134974727791329623974680096491276337756445057223988781749506082654194307092164895251308088903000573135447235553684949564809677864522417041639512933806794232354223826262154508950271949764583849083972967642587778197779127063591201123312548182885603427440981731822883101260509710567731',
              last_name:
                '35864556460959997092903171610228165251001245539613587319116151716453114432309327039517115215674024166920383445379522674504803469517283236033110568676156285676664363558333716898161685255450536856645604857714925836474250821415182026707218622134953915013803750771185050002646661004119778318524426368842019753903741998256374803456282688037624993010626333853831264356355867746685055670790915539230702546586615988121383960277550317876816983602795121749533628953449405383896799464872758725899520173321672584180060465965090049734285011738428381648013150818429882628144544132356242262467090140003979917439514443707537952643217',
              first_name:
                '26405366527417391838431479783966663952336302347775179063968690502492620867161212873635806190080000833725932174641667734138216137047349915190546601368424742647800764149890590518336588437317392528514313749533980651547425554257026971104775208127915118918084350210726664749850578299247705298976657301433446491575776774836993110356033664644761593799921221474617858131678955318702706530853801195330271860527250931569815553226145458665481867408279941785848264018364216087471931232367137301987457054918438087686484522112532447779498424748261678616461026788516567300969886029412198319909977473167405879110243445062391837349387',
              age: '19865805272519696320755573045337531955436490760876870776207490804137339344112305203631892390827288264857621916650098902064979838987400911652887344763586495880167030031364467726355103327059673023946234460960685398768709062405377107912774045508870580108596597470880834205563197111550140867466625683117333370595295321833757429488192170551320637065066368716366317421169802474954914904380304190861641082310805418122837214965865969459724848071006870574514215255412289237027267424055400593307112849859757094597401668252862525566316402695830217450073667487951799749275437192883439584518905943435472478496028380016245355151988',
            },
            rctxt:
              '17146114573198643698878017247599007910707723139165264508694101989891626297408755744139587708989465136799243292477223763665064840330721616213638280284119891715514951989022398510785960099708705561761504012512387129498731093386014964896897751536856287377064154297370092339714578039195258061017640952790913108285519632654466006255438773382930416822756630391947263044087385305540191237328903426888518439803354213792647775798033294505898635058814132665832000734168261793545453678083703704122695006541391598116359796491845268631009298069826949515604008666680160398698425061157356267086946953480945396595351944425658076127674',
            z: '57056568014385132434061065334124327103768023932445648883765905576432733866307137325457775876741578717650388638737098805750938053855430851133826479968450532729423746605371536096355616166421996729493639634413002114547787617999178137950004782677177313856876420539744625174205603354705595789330008560775613287118432593300023801651460885523314713996258581986238928077688246511704050386525431448517516821261983193275502089060128363906909778842476516981025598807378338053788433033754999771876361716562378445777250912525673660842724168260417083076824975992327559199634032439358787956784395443246565622469187082767614421691234',
          },
        },
      },
    })

    const response = await pool.createAndSubmitWriteRequest(agentContext, credentialDefinitionRequest, signerKey)

    expect(response).toMatchObject({
      op: 'REPLY',
      result: {
        ver: '1',
        txn: {
          metadata: expect.any(Object),
          type: '102',
          data: {
            data: {
              primary: {
                r: {
                  last_name:
                    '35864556460959997092903171610228165251001245539613587319116151716453114432309327039517115215674024166920383445379522674504803469517283236033110568676156285676664363558333716898161685255450536856645604857714925836474250821415182026707218622134953915013803750771185050002646661004119778318524426368842019753903741998256374803456282688037624993010626333853831264356355867746685055670790915539230702546586615988121383960277550317876816983602795121749533628953449405383896799464872758725899520173321672584180060465965090049734285011738428381648013150818429882628144544132356242262467090140003979917439514443707537952643217',
                  first_name:
                    '26405366527417391838431479783966663952336302347775179063968690502492620867161212873635806190080000833725932174641667734138216137047349915190546601368424742647800764149890590518336588437317392528514313749533980651547425554257026971104775208127915118918084350210726664749850578299247705298976657301433446491575776774836993110356033664644761593799921221474617858131678955318702706530853801195330271860527250931569815553226145458665481867408279941785848264018364216087471931232367137301987457054918438087686484522112532447779498424748261678616461026788516567300969886029412198319909977473167405879110243445062391837349387',
                  age: '19865805272519696320755573045337531955436490760876870776207490804137339344112305203631892390827288264857621916650098902064979838987400911652887344763586495880167030031364467726355103327059673023946234460960685398768709062405377107912774045508870580108596597470880834205563197111550140867466625683117333370595295321833757429488192170551320637065066368716366317421169802474954914904380304190861641082310805418122837214965865969459724848071006870574514215255412289237027267424055400593307112849859757094597401668252862525566316402695830217450073667487951799749275437192883439584518905943435472478496028380016245355151988',
                  master_secret:
                    '51468326064458249697956272807708948542001661888325200180968238787091473418947480867518174106588127385097619219536294589148765074804124925845579871788369264160902401097166484002617399484700234182426993061977152961670486891123188739266793651668791365808983166555735631354925174224786218771453042042304773095663181121735652667614424198057134974727791329623974680096491276337756445057223988781749506082654194307092164895251308088903000573135447235553684949564809677864522417041639512933806794232354223826262154508950271949764583849083972967642587778197779127063591201123312548182885603427440981731822883101260509710567731',
                },
                z: '57056568014385132434061065334124327103768023932445648883765905576432733866307137325457775876741578717650388638737098805750938053855430851133826479968450532729423746605371536096355616166421996729493639634413002114547787617999178137950004782677177313856876420539744625174205603354705595789330008560775613287118432593300023801651460885523314713996258581986238928077688246511704050386525431448517516821261983193275502089060128363906909778842476516981025598807378338053788433033754999771876361716562378445777250912525673660842724168260417083076824975992327559199634032439358787956784395443246565622469187082767614421691234',
                rctxt:
                  '17146114573198643698878017247599007910707723139165264508694101989891626297408755744139587708989465136799243292477223763665064840330721616213638280284119891715514951989022398510785960099708705561761504012512387129498731093386014964896897751536856287377064154297370092339714578039195258061017640952790913108285519632654466006255438773382930416822756630391947263044087385305540191237328903426888518439803354213792647775798033294505898635058814132665832000734168261793545453678083703704122695006541391598116359796491845268631009298069826949515604008666680160398698425061157356267086946953480945396595351944425658076127674',
                n: '95671911213029889766246243339609567053285242961853979532076192834533577534909796042025401129640348836502648821408485216223269830089771714177855160978214805993386076928594836829216646288195127289421136294309746871614765411402917891972999085287429566166932354413679994469616357622976775651506242447852304853465380257226445481515631782793575184420720296120464167257703633829902427169144462981949944348928086406211627174233811365419264314148304536534528344413738913277713548403058098093453580992173145127632199215550027527631259565822872315784889212327945030315062879193999012349220118290071491899498795367403447663354833',
                s: '1573939820553851804028472930351082111827449763317396231059458630252708273163050576299697385049087601314071156646675105028237105229428440185022593174121924731226634356276616495327358864865629675802738680754755949997611920669823449540027707876555408118172529688443208301403297680159171306000341239398135896274940688268460793682007115152428685521865921925309154307574955324973580144009271977076586453011938089159885164705002797196738438392179082905738155386545935208094240038135576042886730802817809757582039362798495805441520744154270346780731494125065136433163757697326955962282840631850597919384092584727207908978907',
              },
            },
            signature_type: 'CL',
            ref: schemaResponse.result.txnMetadata.seqNo,
            tag: 'TAG',
          },
        },
      },
    })
  })
})
