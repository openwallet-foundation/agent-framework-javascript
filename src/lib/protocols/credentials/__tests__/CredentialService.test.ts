/* eslint-disable no-console */
import { Wallet } from '../../../wallet/Wallet';
import { Repository } from '../../../storage/Repository';
import { CredentialService, EventType } from '../CredentialService';
import { CredentialRecord } from '../../../storage/CredentialRecord';
import { InboundMessageContext } from '../../../agent/models/InboundMessageContext';
import { CredentialState } from '../CredentialState';
import { StubWallet } from './StubWallet';
import {
  CredentialOfferMessage,
  CredentialPreview,
  CredentialPreviewAttribute,
} from '../messages/CredentialOfferMessage';
import { ConnectionRecord } from '../../../storage/ConnectionRecord';
import { JsonEncoder } from '../JsonEncoder';
import { Attachment } from '../messages/Attachment';
import { CredentialRequestMessage } from '../messages/CredentialRequestMessage';
import { CredentialResponseMessage } from '../messages/CredentialResponseMessage';

jest.mock('./../../../storage/Repository');

const CredentialRepository = <jest.Mock<Repository<CredentialRecord>>>(<unknown>Repository);

const preview = new CredentialPreview({
  attributes: [
    new CredentialPreviewAttribute({
      name: 'name',
      mimeType: 'text/plain',
      value: 'John',
    }),
    new CredentialPreviewAttribute({
      name: 'age',
      mimeType: 'text/plain',
      value: '99',
    }),
  ],
});

const attachment = new Attachment({
  id: '6526420d-8d1c-4f70-89de-54c9f3fa9f5c',
  mimeType: '',
  data: {
    base64:
      'eyJzY2hlbWFfaWQiOiJhYWEiLCJjcmVkX2RlZl9pZCI6IlRoN01wVGFSWlZSWW5QaWFiZHM4MVk6MzpDTDoxNzpUQUciLCJub25jZSI6Im5vbmNlIiwia2V5X2NvcnJlY3RuZXNzX3Byb29mIjp7fX0',
  },
});

// A record is deserialized to JSON when it's stored into the storage. We want to simulate this behaviour for `offer`
// object to test our service would behave correctly. We use type assertion for `offer` attribute to `any`.
const mockCredentialRecord = ({
  state,
  request,
  requestMetadata,
  tags,
}: {
  state: CredentialState;
  request?: CredReq;
  requestMetadata?: CredReqMetadata;
  tags?: Record<string, unknown>;
}) =>
  new CredentialRecord({
    offer: new CredentialOfferMessage({
      comment: 'some comment',
      credentialPreview: preview,
      attachments: [attachment],
    }).toJSON(),
    request: request,
    requestMetadata: requestMetadata,
    state: state || CredentialState.OfferSent,
    tags: tags || {},
    connectionId: '123',
  } as any);

const connection = { id: '123' } as ConnectionRecord;

const credDef = {
  ver: '1.0',
  id: 'TL1EaPFCZ8Si5aUrqScBDt:3:CL:16:TAG',
  schemaId: '16',
  type: 'CL',
  tag: 'TAG',
  value: {
    primary: {
      n:
        '92498022445845202032348897620554299694896009176315493627722439892023558526259875239808280186111059586069456394012963552956574651629517633396592827947162983189649269173220440607665417484696688946624963596710652063849006738050417440697782608643095591808084344059908523401576738321329706597491345875134180790935098782801918369980296355919072827164363500681884641551147645504164254206270541724042784184712124576190438261715948768681331862924634233043594086219221089373455065715714369325926959533971768008691000560918594972006312159600845441063618991760512232714992293187779673708252226326233136573974603552763615191259713',
      s:
        '10526250116244590830801226936689232818708299684432892622156345407187391699799320507237066062806731083222465421809988887959680863378202697458984451550048737847231343182195679453915452156726746705017249911605739136361885518044604626564286545453132948801604882107628140153824106426249153436206037648809856342458324897885659120708767794055147846459394129610878181859361616754832462886951623882371283575513182530118220334228417923423365966593298195040550255217053655606887026300020680355874881473255854564974899509540795154002250551880061649183753819902391970912501350100175974791776321455551753882483918632271326727061054',
      r: [Object],
      rctxt:
        '46370806529776888197599056685386177334629311939451963919411093310852010284763705864375085256873240323432329015015526097014834809926159013231804170844321552080493355339505872140068998254185756917091385820365193200970156007391350745837300010513687490459142965515562285631984769068796922482977754955668569724352923519618227464510753980134744424528043503232724934196990461197793822566137436901258663918660818511283047475389958180983391173176526879694302021471636017119966755980327241734084462963412467297412455580500138233383229217300797768907396564522366006433982511590491966618857814545264741708965590546773466047139517',
      z:
        '84153935869396527029518633753040092509512111365149323230260584738724940130382637900926220255597132853379358675015222072417404334537543844616589463419189203852221375511010886284448841979468767444910003114007224993233448170299654815710399828255375084265247114471334540928216537567325499206413940771681156686116516158907421215752364889506967984343660576422672840921988126699885304325384925457260272972771547695861942114712679509318179363715259460727275178310181122162544785290813713205047589943947592273130618286905125194410421355167030389500160371886870735704712739886223342214864760968555566496288314800410716250791012',
    },
  },
};

const credOffer = {
  schema_id: 'TL1EaPFCZ8Si5aUrqScBDt:2:test-schema-1599055118161:1.0',
  cred_def_id: 'TL1EaPFCZ8Si5aUrqScBDt:3:CL:49:TAG',
  key_correctness_proof: {
    c: '50047550092211803100898435599448498249230644214602846259465380105187911562981',
    xz_cap:
      '903377919969858361861015636539761203188657065139923565169527138921408162179186528356880386741834936511828233627399006489728775544195659624738894378139967421189010372215352983118513580084886680005590351907106638703178655817619548698392274394080197104513101326422946899502782963819178061725651195158952405559244837834363357514238035344644245428381747318500206935512140018411279271654056625228252895211750431161165113594675112781707690650346028518711572046490157895995321932792559036799731075010805676081761818738662133557673397343395090042309895292970880031625026873886199268438633391631171327618951514526941153292890331525143330509967786605076984412387036942171388655140446222693051734534012842',
    xr_cap: [[], [], []],
  },
  nonce: '947121108704767252195123',
};

const credReq = {
  prover_did: 'did:sov:Y8iyDrCHfUpBY2jkd7Utfx',
  cred_def_id: 'TL1EaPFCZ8Si5aUrqScBDt:3:CL:51:TAG',
  blinded_ms: {
    u:
      '110610123432332476473375007487247709218419524765032439076208019871743569018252586850427838771931221771227203551775289761586009084292284314207436640231052129266015503401118322009304919643287710408379757802540667358968471419257863330969561198349637578063688118910240720917456714103872180385172499545967921817473077820161374967377407759331556210823439440478684915287345759439215952485377081630435110911287494666818169608863639467996786227107447757434904894305851282532340335379056077475867151483520074334113239997171746478579695337411744772387197598863836759115206573022265599781958164663366458791934494773405738216913411',
    ur: null,
    hidden_attributes: ['master_secret'],
    committed_attributes: {},
  },
  blinded_ms_correctness_proof: {
    c: '74166567145664716669042749172899862913175746842119925863709522367997555162535',
    v_dash_cap:
      '1891661791592401364793544973569850112519453874155294114300886230795255714579603892516573573155105241417827172655027285062713792077137917614458690245067502490043126222829248919183676387904671567784621260696991226361605344734978904242726352512061421137336169348863177667958333777571812458318894495425085637370715152338807798447174855274779220884193480392221426666786386198680359381546692118689959879385498358879593493608080913336396532253364578927496868954362997951935977034507467171417802640352406191044080192001188762610962085274270807255753335099171457405366335155255038768918649029766176047384127483587155470131765852176320591348954350985301805080951657475246349277435569952922829946940821962356900415616036024524136',
    m_caps: {
      master_secret:
        '32296179824587808657350024608644011637567680645343910724911461554002267640642014452361757388185386803499726200537448417105380225841945137943648126052207146380258164316458003146028',
    },
    r_caps: {},
  },
  nonce: '784158051402761459123237',
};

const requestAttachment = new Attachment({
  id: '6526420d-8d1c-4f70-89de-54c9f3fa9f5c',
  mimeType: '',
  data: {
    base64: JsonEncoder.encode(credReq),
  },
});

describe('CredentialService', () => {
  let wallet: Wallet;
  let credentialRepository: Repository<CredentialRecord>;
  let credentialService: CredentialService;

  beforeAll(async () => {
    wallet = new StubWallet();
    await wallet.init();
  });

  afterAll(async () => {
    await wallet.close();
    await wallet.delete();
  });

  describe('createCredentialOffer', () => {
    beforeEach(() => {
      credentialRepository = new CredentialRepository();
      credentialService = new CredentialService(wallet, credentialRepository);
    });

    test('creates credential in OFFER_SENT state', async () => {
      const repositorySaveSpy = jest.spyOn(credentialRepository, 'save');

      const credentialOffer = await credentialService.createCredentialOffer(connection, {
        credDefId: 'Th7MpTaRZVRYnPiabds81Y:3:CL:17:TAG',
        comment: 'some comment',
        preview,
      });

      const [[createdCredentialRecord]] = repositorySaveSpy.mock.calls;
      expect(createdCredentialRecord).toMatchObject({
        createdAt: expect.any(Number),
        id: expect.any(String),
        offer: credentialOffer,
        tags: { threadId: createdCredentialRecord.offer.id },
        type: CredentialRecord.name,
        state: 'OFFER_SENT',
      });
    });

    test(`emits stateChange event with a new credential in OFFER_SENT state`, async () => {
      const eventListenerMock = jest.fn();
      credentialService.on(EventType.StateChanged, eventListenerMock);

      await credentialService.createCredentialOffer(connection, {
        credDefId: 'Th7MpTaRZVRYnPiabds81Y:3:CL:17:TAG',
        comment: 'some comment',
        preview,
      });

      expect(eventListenerMock).toHaveBeenCalledTimes(1);

      const [[event]] = eventListenerMock.mock.calls;
      expect(event).toMatchObject({
        credential: {
          state: 'OFFER_SENT',
        },
        prevState: null,
      });
    });

    test('returns credential offer message', async () => {
      const credentialOffer = await credentialService.createCredentialOffer(connection, {
        credDefId: 'Th7MpTaRZVRYnPiabds81Y:3:CL:17:TAG',
        comment: 'some comment',
        preview,
      });

      expect(credentialOffer.toJSON()).toMatchObject({
        '@id': expect.any(String),
        '@type': 'did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/issue-credential/1.0/offer-credential',
        comment: 'some comment',
        credential_preview: {
          '@type': 'did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/issue-credential/1.0/credential-preview',
          attributes: [
            {
              name: 'name',
              'mime-type': 'text/plain',
              value: 'John',
            },
            {
              name: 'age',
              'mime-type': 'text/plain',
              value: '99',
            },
          ],
        },
        'offers~attach': [
          {
            '@id': expect.any(String),
            'mime-type': 'application/json',
            data: {
              base64: expect.any(String),
            },
          },
        ],
      });
    });
  });

  describe('processCredentialOffer', () => {
    beforeEach(() => {
      credentialRepository = new CredentialRepository();
      credentialService = new CredentialService(wallet, credentialRepository);
    });

    test('creates credential in OFFER_RECEIVED state based on credential offer message', async () => {
      const repositorySaveSpy = jest.spyOn(credentialRepository, 'save');

      const credentialOfferMessage = new CredentialOfferMessage({
        comment: 'some comment',
        credentialPreview: preview,
        attachments: [attachment],
      });

      const messageContext = new InboundMessageContext(credentialOfferMessage);
      messageContext.connection = connection;

      await credentialService.processCredentialOffer(messageContext);

      const [[createdCredentialRecord]] = repositorySaveSpy.mock.calls;
      expect(createdCredentialRecord).toMatchObject({
        createdAt: expect.any(Number),
        id: expect.any(String),
        offer: credentialOfferMessage,
        tags: { threadId: credentialOfferMessage.id },
        type: CredentialRecord.name,
        state: 'OFFER_RECEIVED',
      });
    });

    test(`emits stateChange event with OFFER_RECEIVED`, async () => {
      const eventListenerMock = jest.fn();
      credentialService.on(EventType.StateChanged, eventListenerMock);

      const credentialOfferMessage = new CredentialOfferMessage({
        comment: 'some comment',
        credentialPreview: preview,
        attachments: [attachment],
      });

      const messageContext = new InboundMessageContext(credentialOfferMessage);
      messageContext.connection = connection;

      await credentialService.processCredentialOffer(messageContext);

      expect(eventListenerMock).toHaveBeenCalledTimes(1);

      const [[event]] = eventListenerMock.mock.calls;
      expect(event).toMatchObject({
        credential: {
          state: 'OFFER_RECEIVED',
        },
        prevState: null,
      });
    });
  });

  describe('createCredentialRequest', () => {
    beforeEach(() => {
      credentialRepository = new CredentialRepository();
      credentialService = new CredentialService(wallet, credentialRepository);
    });

    test('updates credential to REQUEST_SENT state', async () => {
      const repositoryUpdateSpy = jest.spyOn(credentialRepository, 'update');
      const credential = mockCredentialRecord({ state: CredentialState.OfferReceived });
      await credentialService.createCredentialRequest(connection, credential, credDef);

      expect(repositoryUpdateSpy).toHaveBeenCalledTimes(1);

      const [[updatedCredentialRecord]] = repositoryUpdateSpy.mock.calls;
      expect(updatedCredentialRecord).toMatchObject({
        requestMetadata: { cred_req: 'meta-data' },
        type: CredentialRecord.name,
        state: 'REQUEST_SENT',
      });
    });

    test(`emits stateChange event with REQUEST_SENT`, async () => {
      const eventListenerMock = jest.fn();
      credentialService.on(EventType.StateChanged, eventListenerMock);

      const credential = mockCredentialRecord({ state: CredentialState.OfferReceived });
      await credentialService.createCredentialRequest(connection, credential, credDef);

      expect(eventListenerMock).toHaveBeenCalledTimes(1);

      const [[event]] = eventListenerMock.mock.calls;
      expect(event).toMatchObject({
        credential: {
          state: 'REQUEST_SENT',
        },
        prevState: 'OFFER_RECEIVED',
      });
    });

    test('returns credential request message base on existing credential offer message', async () => {
      const credential = mockCredentialRecord({
        state: CredentialState.OfferReceived,
        tags: { threadId: 'fd9c5ddb-ec11-4acd-bc32-540736249746' },
      });
      const credentialRequest = await credentialService.createCredentialRequest(connection, credential, credDef);

      expect(credentialRequest.toJSON()).toMatchObject({
        '@id': expect.any(String),
        '@type': 'did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/issue-credential/1.0/request-credential',
        '~thread': {
          // @ts-ignore
          thid: 'fd9c5ddb-ec11-4acd-bc32-540736249746',
        },
        comment: 'some credential request comment',
        'requests~attach': [
          {
            '@id': expect.any(String),
            'mime-type': 'application/json',
            data: {
              base64: expect.any(String),
            },
          },
        ],
      });
    });
  });

  describe('processCredentialRequest', () => {
    let repositoryFindMock: jest.Mock<Promise<CredentialRecord[]>, [WalletQuery]>;

    beforeEach(() => {
      credentialRepository = new CredentialRepository();
      credentialService = new CredentialService(wallet, credentialRepository);
      // make separate mockFind variable to get the correct jest mock typing
      repositoryFindMock = credentialRepository.findByQuery as jest.Mock<Promise<CredentialRecord[]>, [WalletQuery]>;
    });

    test('updates credential to REQUEST_RECEIVED state', async () => {
      const repositoryUpdateSpy = jest.spyOn(credentialRepository, 'update');
      repositoryFindMock.mockReturnValue(Promise.resolve([mockCredentialRecord({ state: CredentialState.OfferSent })]));

      const credentialRequest = new CredentialRequestMessage({ comment: 'abcd', attachments: [requestAttachment] });
      credentialRequest.setThread({ threadId: 'somethreadid' });
      const messageContext = new InboundMessageContext(credentialRequest);

      await credentialService.processCredentialRequest(messageContext);

      const [[findByQueryArg]] = repositoryFindMock.mock.calls;
      expect(findByQueryArg).toEqual({ threadId: 'somethreadid' });

      const [[updatedCredentialRecord]] = repositoryUpdateSpy.mock.calls;
      expect(updatedCredentialRecord).toMatchObject({
        state: 'REQUEST_RECEIVED',
        request: credReq,
      });
    });

    test(`emits stateChange event from OFFER_SENT to REQUEST_RECEIVED`, async () => {
      const eventListenerMock = jest.fn();
      credentialService.on(EventType.StateChanged, eventListenerMock);
      repositoryFindMock.mockReturnValue(Promise.resolve([mockCredentialRecord({ state: CredentialState.OfferSent })]));

      const credentialRequest = new CredentialRequestMessage({ comment: 'abcd', attachments: [requestAttachment] });
      credentialRequest.setThread({ threadId: 'somethreadid' });
      const messageContext = new InboundMessageContext(credentialRequest);

      await credentialService.processCredentialRequest(messageContext);

      expect(eventListenerMock).toHaveBeenCalledTimes(1);

      const [[event]] = eventListenerMock.mock.calls;
      expect(event).toMatchObject({
        credential: {
          state: 'REQUEST_RECEIVED',
        },
        prevState: 'OFFER_SENT',
      });
    });
  });

  describe('createCredentialResponse', () => {
    let repositoryFindMock: jest.Mock<Promise<CredentialRecord>, [string]>;

    beforeEach(() => {
      credentialRepository = new CredentialRepository();
      credentialService = new CredentialService(wallet, credentialRepository);
      // make separate mockFind variable to get the correct jest mock typing
      repositoryFindMock = credentialRepository.find as jest.Mock<Promise<CredentialRecord>, [string]>;
    });

    test('updates credential to CREDENTIAL_ISSUED state', async () => {
      const repositoryUpdateSpy = jest.spyOn(credentialRepository, 'update');
      const credential = mockCredentialRecord({ state: CredentialState.RequestReceived, request: credReq });
      repositoryFindMock.mockReturnValue(Promise.resolve(credential));

      const comment = 'credential response comment';
      await credentialService.createCredentialResponse(credential.id, { comment });

      const [[updatedCredentialRecord]] = repositoryUpdateSpy.mock.calls;
      expect(updatedCredentialRecord).toMatchObject({
        state: 'CREDENTIAL_ISSUED',
      });
    });

    test(`emits stateChange event from REQUEST_RECEIVED to CREDENTIAL_ISSUED`, async () => {
      const eventListenerMock = jest.fn();
      credentialService.on(EventType.StateChanged, eventListenerMock);
      const credential = mockCredentialRecord({ state: CredentialState.RequestReceived, request: credReq });
      repositoryFindMock.mockReturnValue(Promise.resolve(credential));

      const comment = 'credential response comment';
      await credentialService.createCredentialResponse(credential.id, { comment });
      expect(eventListenerMock).toHaveBeenCalledTimes(1);

      const [[event]] = eventListenerMock.mock.calls;
      expect(event).toMatchObject({
        credential: {
          state: 'CREDENTIAL_ISSUED',
        },
        prevState: 'REQUEST_RECEIVED',
      });
    });

    test('returns credential response message base on credential request message', async () => {
      const credential = mockCredentialRecord({
        state: CredentialState.RequestReceived,
        request: credReq,
        tags: { threadId: 'fd9c5ddb-ec11-4acd-bc32-540736249746' },
      });
      repositoryFindMock.mockReturnValue(Promise.resolve(credential));

      const comment = 'credential response comment';
      const credentialResponse = await credentialService.createCredentialResponse(credential.id, { comment });

      expect(credentialResponse.toJSON()).toMatchObject({
        '@id': expect.any(String),
        '@type': 'did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/issue-credential/1.0/issue-credential',
        '~thread': {
          // @ts-ignore
          thid: 'fd9c5ddb-ec11-4acd-bc32-540736249746',
        },
        comment,
        'credentials~attach': [
          {
            '@id': expect.any(String),
            'mime-type': 'application/json',
            data: {
              base64: expect.any(String),
            },
          },
        ],
      });

      // We're using instance of `StubWallet`. Value of `cred` should be as same as in the credential response message.
      const [cred] = await wallet.createCredential(credOffer, credReq, {});
      const [responseAttachment] = credentialResponse.attachments;
      expect(JsonEncoder.decode(responseAttachment.data.base64)).toEqual(cred);
    });
  });

  describe('processCredentialResponse', () => {
    let repositoryFindMock: jest.Mock<Promise<CredentialRecord[]>, [WalletQuery]>;

    beforeEach(() => {
      credentialRepository = new CredentialRepository();
      credentialService = new CredentialService(wallet, credentialRepository);
      // make separate mockFind variable to get the correct jest mock typing
      repositoryFindMock = credentialRepository.findByQuery as jest.Mock<Promise<CredentialRecord[]>, [WalletQuery]>;
    });

    test('stores credential from incoming credential response message into given credential record', async () => {
      const repositoryUpdateSpy = jest.spyOn(credentialRepository, 'update');
      const walletSaveSpy = jest.spyOn(wallet, 'storeCredential');
      repositoryFindMock.mockReturnValue(
        Promise.resolve([
          mockCredentialRecord({ state: CredentialState.RequestSent, requestMetadata: { cred_req: 'meta-data' } }),
        ])
      );

      const credentialResponse = new CredentialResponseMessage({ comment: 'abcd', attachments: [attachment] });
      credentialResponse.setThread({ threadId: 'somethreadid' });
      const messageContext = new InboundMessageContext(credentialResponse);

      await credentialService.processCredentialResponse(messageContext, credDef);

      const [[findByQueryArg]] = repositoryFindMock.mock.calls;
      expect(findByQueryArg).toEqual({ threadId: 'somethreadid' });

      console.log(walletSaveSpy.mock.calls);

      const [[updatedCredentialRecord]] = repositoryUpdateSpy.mock.calls;
      expect(updatedCredentialRecord).toMatchObject({
        id: expect.any(String),
        credentialId: expect.any(String),
        type: CredentialRecord.name,
        state: CredentialState.CredentialReceived,
      });
    });
  });
});
