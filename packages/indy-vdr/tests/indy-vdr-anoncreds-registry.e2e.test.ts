import { Agent, DidsModule, Key, KeyType } from '@aries-framework/core'
import { RevocationRegistryDefinitionRequest, RevocationRegistryEntryRequest } from '@hyperledger/indy-vdr-shared'

import { agentDependencies, getAgentConfig } from '../../core/tests/helpers'
import { IndySdkModule } from '../../indy-sdk/src'
import { indySdk } from '../../indy-sdk/tests/setupIndySdkModule'
import { IndyVdrSovDidResolver } from '../src'
import { IndyVdrAnonCredsRegistry } from '../src/anoncreds/IndyVdrAnonCredsRegistry'
import { IndyVdrPoolService } from '../src/pool'

import { indyVdrModuleConfig } from './helpers'

const agentConfig = getAgentConfig('IndyVdrAnonCredsRegistry')

// TODO: update to module once available
const indyVdrPoolService = new IndyVdrPoolService(agentConfig.logger, indyVdrModuleConfig)
const pool = indyVdrPoolService.getPoolForNamespace('pool:localtest')

// Verkey for the publicDidSeed
const signingKey = Key.fromPublicKeyBase58('FMGcFuU3QwAQLywxvmEnSorQT3NwU9wgDMMTaDFtvswm', KeyType.Ed25519)
const indyVdrAnonCredsRegistry = new IndyVdrAnonCredsRegistry()

const agent = new Agent({
  config: agentConfig,
  dependencies: agentDependencies,
  modules: {
    indySdk: new IndySdkModule({
      indySdk,
    }),
    dids: new DidsModule({
      resolvers: [new IndyVdrSovDidResolver()],
    }),
  },
})

agent.dependencyManager.registerInstance(IndyVdrPoolService, indyVdrPoolService)

describe('IndyVdrAnonCredsRegistry', () => {
  beforeAll(async () => {
    await agent.initialize()
  })

  afterAll(async () => {
    for (const pool of indyVdrPoolService.pools) {
      pool.close()
    }

    await agent.shutdown()
    await agent.wallet.delete()
  })

  // One test as the credential definition depends on the schema
  test('register and resolve a schema and credential definition', async () => {
    const dynamicVersion = `1.${Math.random() * 100}`

    const schemaResult = await indyVdrAnonCredsRegistry.registerSchema(agent.context, {
      options: {
        didIndyNamespace: 'pool:localtest',
      },
      schema: {
        attrNames: ['age'],
        issuerId: 'TL1EaPFCZ8Si5aUrqScBDt',
        name: 'test',
        version: dynamicVersion,
      },
    })

    expect(schemaResult).toMatchObject({
      schemaState: {
        state: 'finished',
        schema: {
          attrNames: ['age'],
          issuerId: 'TL1EaPFCZ8Si5aUrqScBDt',
          name: 'test',
          version: dynamicVersion,
        },
        schemaId: `TL1EaPFCZ8Si5aUrqScBDt:2:test:${dynamicVersion}`,
      },
      registrationMetadata: {},
      schemaMetadata: {
        indyLedgerSeqNo: expect.any(Number),
        didIndyNamespace: 'pool:localtest',
      },
    })

    const schemaResponse = await indyVdrAnonCredsRegistry.getSchema(
      agent.context,
      schemaResult.schemaState.schemaId as string
    )
    expect(schemaResponse).toMatchObject({
      schema: {
        attrNames: ['age'],
        name: 'test',
        version: dynamicVersion,
        issuerId: 'TL1EaPFCZ8Si5aUrqScBDt',
      },
      schemaId: `TL1EaPFCZ8Si5aUrqScBDt:2:test:${dynamicVersion}`,
      resolutionMetadata: {},
      schemaMetadata: {
        didIndyNamespace: 'pool:localtest',
        indyLedgerSeqNo: expect.any(Number),
      },
    })

    const credentialDefinitionResult = await indyVdrAnonCredsRegistry.registerCredentialDefinition(agent.context, {
      credentialDefinition: {
        issuerId: 'TL1EaPFCZ8Si5aUrqScBDt',
        tag: 'TAG',
        schemaId: `TL1EaPFCZ8Si5aUrqScBDt:2:test:${dynamicVersion}`,
        type: 'CL',
        value: {
          primary: {
            n: '96517142458750088826087901549537285521906361834839650465292394026155791790248920518228426560592477800345470631128393537910767968076647428853737338120375137978526133371095345886547568849980095910835456337942570110635942227498396677781945046904040000347997661394155645138402989185582727368743644878567330299129483548946710969360956979880962101169330048328620192831242584775824654760726417810662811409929761424969870024291961980782988854217354212087291593903213167261779548063894662259300608395552269380441482047725811646638173390809967510159302372018819245039226007682154490256871635806558216146474297742733244470144481',
            s: '20992997088800769394205042281221010730843336204635587269131066142238627416871294692123680065003125450990475247419429111144686875080339959479648984195457400282722471552678361441816569115316390063503704185107464429408708889920969284364549487320740759452356010336698287092961864738455949515401889999320804333605635972368885179914619910494573144273759358510644118555354521660927445864167887629319425342133470781407706668100509422240127902573158722086763638357241708157836231326104213948080124231104027985997092193458353052131052627451830345602820935886233072722689872803371231173593216542422645374438328309647440653637339',
            r: {
              master_secret:
                '96243300745227716230048295249700256382424379142767068560156597061550615821183969840133023439359733351013932957841392861447122785423145599004240865527901625751619237368187131360686977600247815596986496835118582544022443932674638843143227258367859921648385998241629365673854479167826898057354386557912400420925145402535066400276579674049751639901555837852972622061540154688641944145082381483273814616102862399655638465723909813901943343059991047747289931252070264205125933226649905593045675877143065756794349492159868513288280364195700788501708587588090219665708038121636837649207584981238653023213330207384929738192210',
              age: '73301750658973501389860306433954162777688414647250690792688553201037736559940890441467927863421690990807820789906540409252803697381653459639864945429958798104818241892796218340966964349674689564019059435289373607451125919476002261041343187491848656595845611576458601110066647002078334660251906541846222115184239401618625285703919125402959929850028352261117167621349930047514115676870868726855651130262227714591240534532398809967792128535084773798290351459391475237061458901325844643172504167457543287673202618731404966555015061917662865397763636445953946274068384614117513804834235388565249331682010365807270858083546',
            },
            rctxt:
              '37788128721284563440858950515231840450431543928224096081933216180465915572829884228780081835462293611329848268384962871736884632087015070623933628853658097637604059748079512999518737243304794110313829761155878287344472916564970806851294430356498883927870926898737394894892797927804721407643833828162246495645836390303263072281761384240973982733122383052566872688887552226083782030670443318152427129452272570595367287061688769394567289624972332234661767648489253220495098949161964171486245324730862072203259801377135500275012560207100571502032523912388082460843991502336467718632746396226650194750972544436894286230063',
            z: '43785356695890052462955676926428400928903479009358861113206349419200366390858322895540291303484939601128045362682307382393826375825484851021601464391509750565285197155653613669680662395620338416776539485377195826876505126073018100680273457526216247879013350460071029101583221000647494610122617904515744711339846577920055655093367012508192004131719432915903924789974568341538556528133188398290594619318653419602058489178526243446782729272985727332736198326183868783570550373552407121582843992983431205917273352230155794805507408743590383242904107596623095433284330566906935063373759426916339149701872288610119965287995',
          },
          revocation: {
            g: '1 0A84C28144BC8B677839038FFFA824AB5ADE517F8DD4A89F092FAF9A3560C62D 1 00FD708E112EEA5D89AF9D0559795E6DBCF56D3B8CDF79EFF34A72EB741F896F 2 095E45DDF417D05FB10933FFC63D474548B7FFFF7888802F07FFFFFF7D07A8A8',
            g_dash:
              '1 201F3E23CC7E9284F3EFCF9500F1E2537C398EAB2E94D2EB801AECC7FBFBDC01 1 08132C7723CF9861D4CC24B56555EF1CBD9AE746C97B3ADFA36C669F2DCE09B6 1 1B2397FB2A1ADE704E2A1E4C242612F4677F9F1BD09E6B14C2E77E25EDA4C62E 1 00CDC2CF5F278D699D52223577AB032C150A3CB4C8E8AB07AB9D592772910E95 2 095E45DDF417D05FB10933FFC63D474548B7FFFF7888802F07FFFFFF7D07A8A8 1 0000000000000000000000000000000000000000000000000000000000000000',
            h: '1 072E0A505004F2F32B4210E72FA18A2ADF17F31479BD2059B7A8C0BA58F2ACB3 1 05C70F039E60317003C41C319753ECACC629791FDB06D6ADC5B06DD94501B973 2 095E45DDF417D05FB10933FFC63D474548B7FFFF7888802F07FFFFFF7D07A8A8',
            h0: '1 03CBE26D18118E9770D4A0B3E8607B3B3A8D3D3CA81FF8D41862430CC583156E 1 004A2A57E0A826AEFF007EDDAF89B02F054050843689167B10127FE9EDEEEDA9 2 095E45DDF417D05FB10933FFC63D474548B7FFFF7888802F07FFFFFF7D07A8A8',
            h1: '1 10C9F9DE537994E4FEF2625AFA78342C8A096238A875F6899DD500230E6022E5 1 0C0A88F53D020557377B4ED9C3826E9B8F918DD03E23B0F8ECD922F8333359D3 2 095E45DDF417D05FB10933FFC63D474548B7FFFF7888802F07FFFFFF7D07A8A8',
            h2: '1 017F748AEEC1DDE4E4C3FBAE771C041F0A6FAEAF34FD02AF773AC4B75025147B 1 1298DBD9A4BEE6AD54E060A57BCE932735B7738C30A9ADAEFE2F38E1858A0183 2 095E45DDF417D05FB10933FFC63D474548B7FFFF7888802F07FFFFFF7D07A8A8',
            htilde:
              '1 0C471F0451D6AC352E28B6ECDE8D7233B75530AE59276DF0F4B9A8B0C5C7E5DB 1 24CE4461910AA5D60C09C24EE0FE51E1B1600D8BA6E483E9050EF897CA3E3C8A 2 095E45DDF417D05FB10933FFC63D474548B7FFFF7888802F07FFFFFF7D07A8A8',
            h_cap:
              '1 225B2106DEBD353AABDFC4C7F7E8660D308FB514EA9DAE0533DDEB65CF796159 1 1F6093622F439FC22C64F157F4F35F7C592EC0169C6F0026BC44CD3E375974A7 1 142126FAC3657AD846D394E1F72FD01ECC15E84416713CD133980E324B24F4BC 1 0357995DBDCD4385E59E607761AB30AE8D9DDE005A777EE846EF51AE2816CD33 2 095E45DDF417D05FB10933FFC63D474548B7FFFF7888802F07FFFFFF7D07A8A8 1 0000000000000000000000000000000000000000000000000000000000000000',
            u: '1 00D8DDC2EB6536CA320EE035D099937E59B11678162C1BFEB30C58FCA9F84650 1 1557A5B05A1A30D63322E187D323C9CA431BC5E811E68D4703933D9DDA26D299 1 10E8AB93AA87839B757521742EBA23C3B257C91F61A93D37AEC4C0A011B5F073 1 1DA65E40406A7875DA8CFCE9FD7F283145C166382A937B72819BDC335FE9A734 2 095E45DDF417D05FB10933FFC63D474548B7FFFF7888802F07FFFFFF7D07A8A8 1 0000000000000000000000000000000000000000000000000000000000000000',
            pk: '1 1A7EBBE3E7F8ED50959851364B20997944FA8AE5E3FC0A2BB531BAA17179D320 1 02C55FE6F64A2A4FF49B37C513C39E56ECD565CFAD6CA46DC6D8095179351863 2 095E45DDF417D05FB10933FFC63D474548B7FFFF7888802F07FFFFFF7D07A8A8',
            y: '1 1BF97F07270EC21A89E43BCA645D86A755F846B547238F1DA379E088CDD9B40D 1 146BB00F56FFC0DEF6541CEB484C718559B398DB1547B52850E46B23144161F1 1 079A1BEF8DFFA4E6352F701D476664340E7FBE5D3F46B897412BD2B5F10E33D7 1 02FDC508AEF90FB11961AF332BE4037973C76B954FFA48848F7E0588E93FCA8C 2 095E45DDF417D05FB10933FFC63D474548B7FFFF7888802F07FFFFFF7D07A8A8 1 0000000000000000000000000000000000000000000000000000000000000000',
          },
        },
      },
      options: {
        didIndyNamespace: 'pool:localtest',
      },
    })

    expect(credentialDefinitionResult).toMatchObject({
      credentialDefinitionMetadata: {
        didIndyNamespace: 'pool:localtest',
      },
      credentialDefinitionState: {
        credentialDefinition: {
          issuerId: 'TL1EaPFCZ8Si5aUrqScBDt',
          tag: 'TAG',
          schemaId: `TL1EaPFCZ8Si5aUrqScBDt:2:test:${dynamicVersion}`,
          type: 'CL',
          value: {
            primary: {
              n: '96517142458750088826087901549537285521906361834839650465292394026155791790248920518228426560592477800345470631128393537910767968076647428853737338120375137978526133371095345886547568849980095910835456337942570110635942227498396677781945046904040000347997661394155645138402989185582727368743644878567330299129483548946710969360956979880962101169330048328620192831242584775824654760726417810662811409929761424969870024291961980782988854217354212087291593903213167261779548063894662259300608395552269380441482047725811646638173390809967510159302372018819245039226007682154490256871635806558216146474297742733244470144481',
              s: '20992997088800769394205042281221010730843336204635587269131066142238627416871294692123680065003125450990475247419429111144686875080339959479648984195457400282722471552678361441816569115316390063503704185107464429408708889920969284364549487320740759452356010336698287092961864738455949515401889999320804333605635972368885179914619910494573144273759358510644118555354521660927445864167887629319425342133470781407706668100509422240127902573158722086763638357241708157836231326104213948080124231104027985997092193458353052131052627451830345602820935886233072722689872803371231173593216542422645374438328309647440653637339',
              r: {
                master_secret:
                  '96243300745227716230048295249700256382424379142767068560156597061550615821183969840133023439359733351013932957841392861447122785423145599004240865527901625751619237368187131360686977600247815596986496835118582544022443932674638843143227258367859921648385998241629365673854479167826898057354386557912400420925145402535066400276579674049751639901555837852972622061540154688641944145082381483273814616102862399655638465723909813901943343059991047747289931252070264205125933226649905593045675877143065756794349492159868513288280364195700788501708587588090219665708038121636837649207584981238653023213330207384929738192210',
                age: '73301750658973501389860306433954162777688414647250690792688553201037736559940890441467927863421690990807820789906540409252803697381653459639864945429958798104818241892796218340966964349674689564019059435289373607451125919476002261041343187491848656595845611576458601110066647002078334660251906541846222115184239401618625285703919125402959929850028352261117167621349930047514115676870868726855651130262227714591240534532398809967792128535084773798290351459391475237061458901325844643172504167457543287673202618731404966555015061917662865397763636445953946274068384614117513804834235388565249331682010365807270858083546',
              },
              rctxt:
                '37788128721284563440858950515231840450431543928224096081933216180465915572829884228780081835462293611329848268384962871736884632087015070623933628853658097637604059748079512999518737243304794110313829761155878287344472916564970806851294430356498883927870926898737394894892797927804721407643833828162246495645836390303263072281761384240973982733122383052566872688887552226083782030670443318152427129452272570595367287061688769394567289624972332234661767648489253220495098949161964171486245324730862072203259801377135500275012560207100571502032523912388082460843991502336467718632746396226650194750972544436894286230063',
              z: '43785356695890052462955676926428400928903479009358861113206349419200366390858322895540291303484939601128045362682307382393826375825484851021601464391509750565285197155653613669680662395620338416776539485377195826876505126073018100680273457526216247879013350460071029101583221000647494610122617904515744711339846577920055655093367012508192004131719432915903924789974568341538556528133188398290594619318653419602058489178526243446782729272985727332736198326183868783570550373552407121582843992983431205917273352230155794805507408743590383242904107596623095433284330566906935063373759426916339149701872288610119965287995',
            },
            revocation: {
              g: '1 0A84C28144BC8B677839038FFFA824AB5ADE517F8DD4A89F092FAF9A3560C62D 1 00FD708E112EEA5D89AF9D0559795E6DBCF56D3B8CDF79EFF34A72EB741F896F 2 095E45DDF417D05FB10933FFC63D474548B7FFFF7888802F07FFFFFF7D07A8A8',
              g_dash:
                '1 201F3E23CC7E9284F3EFCF9500F1E2537C398EAB2E94D2EB801AECC7FBFBDC01 1 08132C7723CF9861D4CC24B56555EF1CBD9AE746C97B3ADFA36C669F2DCE09B6 1 1B2397FB2A1ADE704E2A1E4C242612F4677F9F1BD09E6B14C2E77E25EDA4C62E 1 00CDC2CF5F278D699D52223577AB032C150A3CB4C8E8AB07AB9D592772910E95 2 095E45DDF417D05FB10933FFC63D474548B7FFFF7888802F07FFFFFF7D07A8A8 1 0000000000000000000000000000000000000000000000000000000000000000',
              h: '1 072E0A505004F2F32B4210E72FA18A2ADF17F31479BD2059B7A8C0BA58F2ACB3 1 05C70F039E60317003C41C319753ECACC629791FDB06D6ADC5B06DD94501B973 2 095E45DDF417D05FB10933FFC63D474548B7FFFF7888802F07FFFFFF7D07A8A8',
              h0: '1 03CBE26D18118E9770D4A0B3E8607B3B3A8D3D3CA81FF8D41862430CC583156E 1 004A2A57E0A826AEFF007EDDAF89B02F054050843689167B10127FE9EDEEEDA9 2 095E45DDF417D05FB10933FFC63D474548B7FFFF7888802F07FFFFFF7D07A8A8',
              h1: '1 10C9F9DE537994E4FEF2625AFA78342C8A096238A875F6899DD500230E6022E5 1 0C0A88F53D020557377B4ED9C3826E9B8F918DD03E23B0F8ECD922F8333359D3 2 095E45DDF417D05FB10933FFC63D474548B7FFFF7888802F07FFFFFF7D07A8A8',
              h2: '1 017F748AEEC1DDE4E4C3FBAE771C041F0A6FAEAF34FD02AF773AC4B75025147B 1 1298DBD9A4BEE6AD54E060A57BCE932735B7738C30A9ADAEFE2F38E1858A0183 2 095E45DDF417D05FB10933FFC63D474548B7FFFF7888802F07FFFFFF7D07A8A8',
              htilde:
                '1 0C471F0451D6AC352E28B6ECDE8D7233B75530AE59276DF0F4B9A8B0C5C7E5DB 1 24CE4461910AA5D60C09C24EE0FE51E1B1600D8BA6E483E9050EF897CA3E3C8A 2 095E45DDF417D05FB10933FFC63D474548B7FFFF7888802F07FFFFFF7D07A8A8',
              h_cap:
                '1 225B2106DEBD353AABDFC4C7F7E8660D308FB514EA9DAE0533DDEB65CF796159 1 1F6093622F439FC22C64F157F4F35F7C592EC0169C6F0026BC44CD3E375974A7 1 142126FAC3657AD846D394E1F72FD01ECC15E84416713CD133980E324B24F4BC 1 0357995DBDCD4385E59E607761AB30AE8D9DDE005A777EE846EF51AE2816CD33 2 095E45DDF417D05FB10933FFC63D474548B7FFFF7888802F07FFFFFF7D07A8A8 1 0000000000000000000000000000000000000000000000000000000000000000',
              u: '1 00D8DDC2EB6536CA320EE035D099937E59B11678162C1BFEB30C58FCA9F84650 1 1557A5B05A1A30D63322E187D323C9CA431BC5E811E68D4703933D9DDA26D299 1 10E8AB93AA87839B757521742EBA23C3B257C91F61A93D37AEC4C0A011B5F073 1 1DA65E40406A7875DA8CFCE9FD7F283145C166382A937B72819BDC335FE9A734 2 095E45DDF417D05FB10933FFC63D474548B7FFFF7888802F07FFFFFF7D07A8A8 1 0000000000000000000000000000000000000000000000000000000000000000',
              pk: '1 1A7EBBE3E7F8ED50959851364B20997944FA8AE5E3FC0A2BB531BAA17179D320 1 02C55FE6F64A2A4FF49B37C513C39E56ECD565CFAD6CA46DC6D8095179351863 2 095E45DDF417D05FB10933FFC63D474548B7FFFF7888802F07FFFFFF7D07A8A8',
              y: '1 1BF97F07270EC21A89E43BCA645D86A755F846B547238F1DA379E088CDD9B40D 1 146BB00F56FFC0DEF6541CEB484C718559B398DB1547B52850E46B23144161F1 1 079A1BEF8DFFA4E6352F701D476664340E7FBE5D3F46B897412BD2B5F10E33D7 1 02FDC508AEF90FB11961AF332BE4037973C76B954FFA48848F7E0588E93FCA8C 2 095E45DDF417D05FB10933FFC63D474548B7FFFF7888802F07FFFFFF7D07A8A8 1 0000000000000000000000000000000000000000000000000000000000000000',
            },
          },
        },
        credentialDefinitionId: `TL1EaPFCZ8Si5aUrqScBDt:3:CL:${schemaResponse.schemaMetadata.indyLedgerSeqNo}:TAG`,
        state: 'finished',
      },
      registrationMetadata: {},
    })

    const credentialDefinitionResponse = await indyVdrAnonCredsRegistry.getCredentialDefinition(
      agent.context,
      credentialDefinitionResult.credentialDefinitionState.credentialDefinitionId as string
    )

    expect(credentialDefinitionResponse).toMatchObject({
      credentialDefinitionId: `TL1EaPFCZ8Si5aUrqScBDt:3:CL:${schemaResponse.schemaMetadata.indyLedgerSeqNo}:TAG`,
      credentialDefinition: {
        issuerId: 'TL1EaPFCZ8Si5aUrqScBDt',
        schemaId: `TL1EaPFCZ8Si5aUrqScBDt:2:test:${dynamicVersion}`,
        tag: 'TAG',
        type: 'CL',
        value: {
          primary: {
            n: '96517142458750088826087901549537285521906361834839650465292394026155791790248920518228426560592477800345470631128393537910767968076647428853737338120375137978526133371095345886547568849980095910835456337942570110635942227498396677781945046904040000347997661394155645138402989185582727368743644878567330299129483548946710969360956979880962101169330048328620192831242584775824654760726417810662811409929761424969870024291961980782988854217354212087291593903213167261779548063894662259300608395552269380441482047725811646638173390809967510159302372018819245039226007682154490256871635806558216146474297742733244470144481',
            s: '20992997088800769394205042281221010730843336204635587269131066142238627416871294692123680065003125450990475247419429111144686875080339959479648984195457400282722471552678361441816569115316390063503704185107464429408708889920969284364549487320740759452356010336698287092961864738455949515401889999320804333605635972368885179914619910494573144273759358510644118555354521660927445864167887629319425342133470781407706668100509422240127902573158722086763638357241708157836231326104213948080124231104027985997092193458353052131052627451830345602820935886233072722689872803371231173593216542422645374438328309647440653637339',
            r: {
              master_secret:
                '96243300745227716230048295249700256382424379142767068560156597061550615821183969840133023439359733351013932957841392861447122785423145599004240865527901625751619237368187131360686977600247815596986496835118582544022443932674638843143227258367859921648385998241629365673854479167826898057354386557912400420925145402535066400276579674049751639901555837852972622061540154688641944145082381483273814616102862399655638465723909813901943343059991047747289931252070264205125933226649905593045675877143065756794349492159868513288280364195700788501708587588090219665708038121636837649207584981238653023213330207384929738192210',
              age: '73301750658973501389860306433954162777688414647250690792688553201037736559940890441467927863421690990807820789906540409252803697381653459639864945429958798104818241892796218340966964349674689564019059435289373607451125919476002261041343187491848656595845611576458601110066647002078334660251906541846222115184239401618625285703919125402959929850028352261117167621349930047514115676870868726855651130262227714591240534532398809967792128535084773798290351459391475237061458901325844643172504167457543287673202618731404966555015061917662865397763636445953946274068384614117513804834235388565249331682010365807270858083546',
            },
            rctxt:
              '37788128721284563440858950515231840450431543928224096081933216180465915572829884228780081835462293611329848268384962871736884632087015070623933628853658097637604059748079512999518737243304794110313829761155878287344472916564970806851294430356498883927870926898737394894892797927804721407643833828162246495645836390303263072281761384240973982733122383052566872688887552226083782030670443318152427129452272570595367287061688769394567289624972332234661767648489253220495098949161964171486245324730862072203259801377135500275012560207100571502032523912388082460843991502336467718632746396226650194750972544436894286230063',
            z: '43785356695890052462955676926428400928903479009358861113206349419200366390858322895540291303484939601128045362682307382393826375825484851021601464391509750565285197155653613669680662395620338416776539485377195826876505126073018100680273457526216247879013350460071029101583221000647494610122617904515744711339846577920055655093367012508192004131719432915903924789974568341538556528133188398290594619318653419602058489178526243446782729272985727332736198326183868783570550373552407121582843992983431205917273352230155794805507408743590383242904107596623095433284330566906935063373759426916339149701872288610119965287995',
          },
          revocation: {
            g: '1 0A84C28144BC8B677839038FFFA824AB5ADE517F8DD4A89F092FAF9A3560C62D 1 00FD708E112EEA5D89AF9D0559795E6DBCF56D3B8CDF79EFF34A72EB741F896F 2 095E45DDF417D05FB10933FFC63D474548B7FFFF7888802F07FFFFFF7D07A8A8',
            g_dash:
              '1 201F3E23CC7E9284F3EFCF9500F1E2537C398EAB2E94D2EB801AECC7FBFBDC01 1 08132C7723CF9861D4CC24B56555EF1CBD9AE746C97B3ADFA36C669F2DCE09B6 1 1B2397FB2A1ADE704E2A1E4C242612F4677F9F1BD09E6B14C2E77E25EDA4C62E 1 00CDC2CF5F278D699D52223577AB032C150A3CB4C8E8AB07AB9D592772910E95 2 095E45DDF417D05FB10933FFC63D474548B7FFFF7888802F07FFFFFF7D07A8A8 1 0000000000000000000000000000000000000000000000000000000000000000',
            h: '1 072E0A505004F2F32B4210E72FA18A2ADF17F31479BD2059B7A8C0BA58F2ACB3 1 05C70F039E60317003C41C319753ECACC629791FDB06D6ADC5B06DD94501B973 2 095E45DDF417D05FB10933FFC63D474548B7FFFF7888802F07FFFFFF7D07A8A8',
            h0: '1 03CBE26D18118E9770D4A0B3E8607B3B3A8D3D3CA81FF8D41862430CC583156E 1 004A2A57E0A826AEFF007EDDAF89B02F054050843689167B10127FE9EDEEEDA9 2 095E45DDF417D05FB10933FFC63D474548B7FFFF7888802F07FFFFFF7D07A8A8',
            h1: '1 10C9F9DE537994E4FEF2625AFA78342C8A096238A875F6899DD500230E6022E5 1 0C0A88F53D020557377B4ED9C3826E9B8F918DD03E23B0F8ECD922F8333359D3 2 095E45DDF417D05FB10933FFC63D474548B7FFFF7888802F07FFFFFF7D07A8A8',
            h2: '1 017F748AEEC1DDE4E4C3FBAE771C041F0A6FAEAF34FD02AF773AC4B75025147B 1 1298DBD9A4BEE6AD54E060A57BCE932735B7738C30A9ADAEFE2F38E1858A0183 2 095E45DDF417D05FB10933FFC63D474548B7FFFF7888802F07FFFFFF7D07A8A8',
            htilde:
              '1 0C471F0451D6AC352E28B6ECDE8D7233B75530AE59276DF0F4B9A8B0C5C7E5DB 1 24CE4461910AA5D60C09C24EE0FE51E1B1600D8BA6E483E9050EF897CA3E3C8A 2 095E45DDF417D05FB10933FFC63D474548B7FFFF7888802F07FFFFFF7D07A8A8',
            h_cap:
              '1 225B2106DEBD353AABDFC4C7F7E8660D308FB514EA9DAE0533DDEB65CF796159 1 1F6093622F439FC22C64F157F4F35F7C592EC0169C6F0026BC44CD3E375974A7 1 142126FAC3657AD846D394E1F72FD01ECC15E84416713CD133980E324B24F4BC 1 0357995DBDCD4385E59E607761AB30AE8D9DDE005A777EE846EF51AE2816CD33 2 095E45DDF417D05FB10933FFC63D474548B7FFFF7888802F07FFFFFF7D07A8A8 1 0000000000000000000000000000000000000000000000000000000000000000',
            u: '1 00D8DDC2EB6536CA320EE035D099937E59B11678162C1BFEB30C58FCA9F84650 1 1557A5B05A1A30D63322E187D323C9CA431BC5E811E68D4703933D9DDA26D299 1 10E8AB93AA87839B757521742EBA23C3B257C91F61A93D37AEC4C0A011B5F073 1 1DA65E40406A7875DA8CFCE9FD7F283145C166382A937B72819BDC335FE9A734 2 095E45DDF417D05FB10933FFC63D474548B7FFFF7888802F07FFFFFF7D07A8A8 1 0000000000000000000000000000000000000000000000000000000000000000',
            pk: '1 1A7EBBE3E7F8ED50959851364B20997944FA8AE5E3FC0A2BB531BAA17179D320 1 02C55FE6F64A2A4FF49B37C513C39E56ECD565CFAD6CA46DC6D8095179351863 2 095E45DDF417D05FB10933FFC63D474548B7FFFF7888802F07FFFFFF7D07A8A8',
            y: '1 1BF97F07270EC21A89E43BCA645D86A755F846B547238F1DA379E088CDD9B40D 1 146BB00F56FFC0DEF6541CEB484C718559B398DB1547B52850E46B23144161F1 1 079A1BEF8DFFA4E6352F701D476664340E7FBE5D3F46B897412BD2B5F10E33D7 1 02FDC508AEF90FB11961AF332BE4037973C76B954FFA48848F7E0588E93FCA8C 2 095E45DDF417D05FB10933FFC63D474548B7FFFF7888802F07FFFFFF7D07A8A8 1 0000000000000000000000000000000000000000000000000000000000000000',
          },
        },
      },
      credentialDefinitionMetadata: {
        didIndyNamespace: 'pool:localtest',
      },
      resolutionMetadata: {},
    })

    // We don't support creating a revocation registry using AFJ yet, so we directly use indy-vdr to create the revocation registry
    const revocationRegistryDefinitionId = `TL1EaPFCZ8Si5aUrqScBDt:4:TL1EaPFCZ8Si5aUrqScBDt:3:CL:${schemaResponse.schemaMetadata.indyLedgerSeqNo}:TAG:CL_ACCUM:tag`
    const revocationRegistryRequest = new RevocationRegistryDefinitionRequest({
      submitterDid: 'TL1EaPFCZ8Si5aUrqScBDt',
      revocationRegistryDefinitionV1: {
        credDefId: credentialDefinitionResponse.credentialDefinitionId,
        id: revocationRegistryDefinitionId,
        revocDefType: 'CL_ACCUM',
        tag: 'tag',
        value: {
          issuanceType: 'ISSUANCE_BY_DEFAULT',
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
        ver: '1.0',
      },
    })

    // After this call, the revocation registry should now be resolvable
    await pool.submitWriteRequest(agent.context, revocationRegistryRequest, signingKey)

    // Also create a revocation registry entry
    const revocationEntryRequest = new RevocationRegistryEntryRequest({
      revocationRegistryDefinitionId,
      revocationRegistryDefinitionType: 'CL_ACCUM',
      revocationRegistryEntry: {
        ver: '1.0',
        value: {
          accum: '1',
        },
      },
      submitterDid: 'TL1EaPFCZ8Si5aUrqScBDt',
    })

    // After this call we can query the revocation registry entries (using timestamp now)
    const response = await pool.submitWriteRequest(agent.context, revocationEntryRequest, signingKey)

    const revocationRegistryDefintion = await indyVdrAnonCredsRegistry.getRevocationRegistryDefinition(
      agent.context,
      revocationRegistryDefinitionId
    )

    expect(revocationRegistryDefintion).toMatchObject({
      revocationRegistryDefinitionId: `TL1EaPFCZ8Si5aUrqScBDt:4:TL1EaPFCZ8Si5aUrqScBDt:3:CL:${schemaResponse.schemaMetadata.indyLedgerSeqNo}:TAG:CL_ACCUM:tag`,
      revocationRegistryDefinition: {
        issuerId: 'TL1EaPFCZ8Si5aUrqScBDt',
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
        tag: 'tag',
        credDefId: `TL1EaPFCZ8Si5aUrqScBDt:3:CL:${schemaResponse.schemaMetadata.indyLedgerSeqNo}:TAG`,
      },
      revocationRegistryDefinitionMetadata: {
        issuanceType: 'ISSUANCE_BY_DEFAULT',
        didIndyNamespace: 'pool:localtest',
      },
      resolutionMetadata: {},
    })

    const revocationStatusList = await indyVdrAnonCredsRegistry.getRevocationStatusList(
      agent.context,
      revocationRegistryDefinitionId,
      response.result.txnMetadata.txnTime
    )

    expect(revocationStatusList).toMatchObject({
      resolutionMetadata: {},
      revocationStatusList: {
        issuerId: 'TL1EaPFCZ8Si5aUrqScBDt',
        currentAccumulator: '1',
        revRegId: `TL1EaPFCZ8Si5aUrqScBDt:4:TL1EaPFCZ8Si5aUrqScBDt:3:CL:${schemaResponse.schemaMetadata.indyLedgerSeqNo}:TAG:CL_ACCUM:tag`,
        revocationList: [
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ],
        timestamp: response.result.txnMetadata.txnTime,
      },
      revocationStatusListMetadata: { didIndyNamespace: 'pool:localtest' },
    })
  })
})
