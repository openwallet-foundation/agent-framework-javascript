import type {
  Cred,
  CredDef,
  CredDefConfig,
  CredDefId,
  CredentialDefs,
  CredentialId,
  CredOffer,
  CredReq,
  CredReqMetadata,
  CredRevocId,
  CredValues,
  Did,
  DidConfig,
  IndyProofRequest,
  IndyRequestedCredentials,
  LedgerRequest,
  ProofCred,
  RevocRegDelta,
  RevStates,
  Schema,
  Schemas,
  Verkey,
  WalletConfig,
  WalletCredentials,
  WalletQuery,
  WalletRecord,
  WalletRecordOptions,
  WalletSearchOptions,
} from 'indy-sdk';
import type Indy from 'indy-sdk';

import logger from '../logger';
import { UnpackedMessageContext } from '../types';
import { isIndyError } from '../utils/indyError';
import { Wallet, DidInfo } from './Wallet';
import { JsonEncoder } from '../utils/JsonEncoder';

export class IndyWallet implements Wallet {
  private _walletHandle?: number;
  private _masterSecretId?: string;
  private walletConfig: WalletConfig;
  private walletCredentials: WalletCredentials;
  private publicDidInfo: DidInfo | undefined;
  private indy: typeof Indy;

  public constructor(walletConfig: WalletConfig, walletCredentials: WalletCredentials, indy: typeof Indy) {
    this.walletConfig = walletConfig;
    this.walletCredentials = walletCredentials;
    this.indy = indy;
  }

  public get publicDid() {
    return this.publicDidInfo;
  }

  private get walletHandle() {
    if (!this._walletHandle) {
      throw new Error('Wallet has not been initialized yet');
    }

    return this._walletHandle;
  }

  private get masterSecretId() {
    // In theory this is not possible if the wallet handle is available
    if (!this._masterSecretId) {
      throw new Error('Master secret has not been initialized yet');
    }

    return this._masterSecretId;
  }

  public async init() {
    try {
      await this.indy.createWallet(this.walletConfig, this.walletCredentials);
    } catch (error) {
      logger.log('error', error);
      if (isIndyError(error, 'WalletAlreadyExistsError')) {
        logger.log(error.indyName);
      } else {
        throw error;
      }
    }

    this._walletHandle = await this.indy.openWallet(this.walletConfig, this.walletCredentials);

    try {
      logger.log(`Creating master secret...`);
      this._masterSecretId = await this.indy.proverCreateMasterSecret(this.walletHandle, this.walletConfig.id);
    } catch (error) {
      logger.log('error', error);
      if (isIndyError(error, 'AnoncredsMasterSecretDuplicateNameError')) {
        // master secret id is the same as the master secret id passed in the create function
        // so if it already exists we can just assign it.
        this._masterSecretId = this.walletConfig.id;
        logger.log(`master secret with id ${this.masterSecretId} already exists`, error.indyName);
      } else {
        throw error;
      }
    }

    logger.log(`Wallet opened with handle: ${this.walletHandle}`);
  }

  public async initPublicDid(didConfig: DidConfig) {
    const [did, verkey] = await this.createDid(didConfig);
    this.publicDidInfo = {
      did,
      verkey,
    };
  }

  public async createDid(didConfig?: DidConfig): Promise<[Did, Verkey]> {
    return this.indy.createAndStoreMyDid(this.walletHandle, didConfig || {});
  }

  public async createCredentialDefinition(
    issuerDid: string,
    schema: Schema,
    tag: string,
    signatureType: string,
    config?: CredDefConfig
  ): Promise<[CredDefId, CredDef]> {
    return this.indy.issuerCreateAndStoreCredentialDef(
      this.walletHandle,
      issuerDid,
      schema,
      tag,
      signatureType,
      config
    );
  }

  public searchCredentialsForProofRequest(proofRequest: IndyProofRequest): Promise<number> {
    return this.indy.proverSearchCredentialsForProofReq(this.walletHandle, proofRequest, {} as any);
  }

  public async createCredentialOffer(credDefId: CredDefId) {
    return this.indy.issuerCreateCredentialOffer(this.walletHandle, credDefId);
  }

  public async getCredentialsForProofRequest(proof: IndyProofRequest): Promise<ProofCred> {
    return await this.indy.proverGetCredentialsForProofReq(this.walletHandle, proof);
  }

  public async createCredentialRequest(
    proverDid: string,
    offer: CredOffer,
    credDef: CredDef
  ): Promise<[CredReq, CredReqMetadata]> {
    return this.indy.proverCreateCredentialReq(this.walletHandle, proverDid, offer, credDef, this.masterSecretId);
  }

  public async createCredential(
    credOffer: CredOffer,
    credReq: CredReq,
    credValues: CredValues
  ): Promise<[Cred, CredRevocId, RevocRegDelta]> {
    // TODO This is just dummy tails writer config to get dummy blob reader handle because revocations feature
    // is not part of the credential issuance task. It needs to be implemented properly together with revocations
    // feature implementation.
    const tailsWriterConfig = {
      base_dir: '',
      uri_pattern: '',
    };
    const blobReaderHandle = await this.indy.openBlobStorageReader('default', tailsWriterConfig);

    return this.indy.issuerCreateCredential(this.walletHandle, credOffer, credReq, credValues, null, blobReaderHandle);
  }

  public async storeCredential(
    credentialId: CredentialId,
    credReqMetadata: CredReqMetadata,
    cred: Cred,
    credDef: CredDef
  ) {
    return this.indy.proverStoreCredential(this.walletHandle, credentialId, credReqMetadata, cred, credDef, null);
  }

  public async getCredential(credentialId: CredentialId) {
    return this.indy.proverGetCredential(this.walletHandle, credentialId);
  }

  public async createProof(
    proofRequest: IndyProofRequest,
    requestedCredentials: IndyRequestedCredentials,
    schemas: Schemas,
    credentialDefs: CredentialDefs,
    revStates: RevStates
  ) {
    return this.indy.proverCreateProof(
      this.walletHandle,
      proofRequest,
      requestedCredentials,
      this.masterSecretId,
      schemas,
      credentialDefs,
      revStates
    );
  }

  public async pack(payload: Record<string, unknown>, recipientKeys: Verkey[], senderVk: Verkey): Promise<JsonWebKey> {
    const messageRaw = JsonEncoder.toBuffer(payload);
    const packedMessage = await this.indy.packMessage(this.walletHandle, messageRaw, recipientKeys, senderVk);
    return JsonEncoder.fromBuffer(packedMessage);
  }

  public async unpack(messagePackage: JsonWebKey): Promise<UnpackedMessageContext> {
    const unpackedMessageBuffer = await this.indy.unpackMessage(
      this.walletHandle,
      JsonEncoder.toBuffer(messagePackage)
    );
    const unpackedMessage = JsonEncoder.fromBuffer(unpackedMessageBuffer);
    return {
      ...unpackedMessage,
      message: JsonEncoder.fromString(unpackedMessage.message),
    };
  }

  public async sign(data: Buffer, verkey: Verkey): Promise<Buffer> {
    const signatureBuffer = await this.indy.cryptoSign(this.walletHandle, verkey, data);

    return signatureBuffer;
  }

  public async verify(signerVerkey: Verkey, data: Buffer, signature: Buffer): Promise<boolean> {
    // check signature
    const isValid = await this.indy.cryptoVerify(signerVerkey, data, signature);

    return isValid;
  }

  public async close() {
    return this.indy.closeWallet(this.walletHandle);
  }

  public async delete() {
    return this.indy.deleteWallet(this.walletConfig, this.walletCredentials);
  }

  public async addWalletRecord(type: string, id: string, value: string, tags: Record<string, string>) {
    return this.indy.addWalletRecord(this.walletHandle, type, id, value, tags);
  }

  public async updateWalletRecordValue(type: string, id: string, value: string) {
    return this.indy.updateWalletRecordValue(this.walletHandle, type, id, value);
  }

  public async updateWalletRecordTags(type: string, id: string, tags: Record<string, string>) {
    return this.indy.addWalletRecordTags(this.walletHandle, type, id, tags);
  }

  public async deleteWalletRecord(type: string, id: string) {
    return this.indy.deleteWalletRecord(this.walletHandle, type, id);
  }

  public async search(type: string, query: WalletQuery, options: WalletSearchOptions) {
    const sh: number = await this.indy.openWalletSearch(this.walletHandle, type, query, options);
    const generator = async function* (indy: typeof Indy, wh: number) {
      try {
        while (true) {
          // count should probably be exported as a config?
          const recordSearch = await indy.fetchWalletSearchNextRecords(wh, sh, 10);
          for (const record of recordSearch.records) {
            yield record;
          }
        }
      } catch (error) {
        // pass
      } finally {
        await indy.closeWalletSearch(sh);
        return;
      }
    };

    return generator(this.indy, this.walletHandle);
  }

  public getWalletRecord(type: string, id: string, options: WalletRecordOptions): Promise<WalletRecord> {
    return this.indy.getWalletRecord(this.walletHandle, type, id, options);
  }

  public signRequest(myDid: Did, request: LedgerRequest) {
    return this.indy.signRequest(this.walletHandle, myDid, request);
  }

  public async generateNonce() {
    return this.indy.generateNonce();
  }
}
