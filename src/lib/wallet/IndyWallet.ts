/* eslint-disable @typescript-eslint/ban-types */

import logger from '../logger';
import { UnpackedMessage } from '../types';
import { Wallet, WalletConfig, WalletCredentials, DidInfo, DidConfig } from './Wallet';

export class IndyWallet implements Wallet {
  wh?: number;
  walletConfig: WalletConfig;
  walletCredentials: WalletCredentials;
  agentDidInfo: DidInfo | {} = {};
  publicDidInfo: DidInfo | Record<string, undefined> = {};
  indy: Indy;

  constructor(walletConfig: WalletConfig, walletCredentials: WalletCredentials, indy: Indy) {
    this.walletConfig = walletConfig;
    this.walletCredentials = walletCredentials;
    this.indy = indy;
  }

  async init() {
    try {
      await this.indy.createWallet(this.walletConfig, this.walletCredentials);
    } catch (error) {
      logger.log('error', error);
      if (error.indyName && error.indyName === 'WalletAlreadyExistsError') {
        logger.log(error.indyName);
      } else {
        throw error;
      }
    }

    this.wh = await this.indy.openWallet(this.walletConfig, this.walletCredentials);
    logger.log(`Wallet opened with handle: ${this.wh}`);
  }

  async initPublicDid(didConfig: DidConfig) {
    const [did, verkey] = await this.createDid(didConfig);
    this.publicDidInfo = {
      did,
      verkey,
    };
  }

  getPublicDid(): DidInfo | {} {
    return this.publicDidInfo;
  }

  async createDid(didConfig?: DidConfig): Promise<[Did, Verkey]> {
    if (!this.wh) {
      throw Error('Wallet has not been initialized yet');
    }

    return this.indy.createAndStoreMyDid(this.wh, didConfig || {});
  }

  async createCredDef(
    issuerDid: string,
    schema: Schema,
    tag: string,
    signatureType: string,
    config: {}
  ): Promise<[string, CredDef]> {
    if (!this.wh) {
      throw Error('Wallet has not been initialized yet');
    }

    return this.indy.issuerCreateAndStoreCredentialDef(this.wh, issuerDid, schema, tag, signatureType, config);
  }

  async pack(payload: {}, recipientKeys: Verkey[], senderVk: Verkey): Promise<JsonWebKey> {
    if (!this.wh) {
      throw Error('Wallet has not been initialized yet');
    }

    const messageRaw = Buffer.from(JSON.stringify(payload), 'utf-8');
    const packedMessage = await this.indy.packMessage(this.wh, messageRaw, recipientKeys, senderVk);
    return JSON.parse(packedMessage.toString('utf-8'));
  }

  async unpack(messagePackage: JsonWebKey): Promise<UnpackedMessage> {
    if (!this.wh) {
      throw Error('Wallet has not been initialized yet');
    }

    const unpackedMessageBuffer = await this.indy.unpackMessage(
      this.wh,
      Buffer.from(JSON.stringify(messagePackage), 'utf-8')
    );
    const unpackedMessage = JSON.parse(unpackedMessageBuffer.toString('utf-8'));
    return {
      ...unpackedMessage,
      message: JSON.parse(unpackedMessage.message),
    };
  }

  async sign(data: Buffer, verkey: Verkey): Promise<Buffer> {
    if (!this.wh) {
      throw Error('Wallet has not been initialized yet');
    }

    const signatureBuffer = await this.indy.cryptoSign(this.wh, verkey, data);

    return signatureBuffer;
  }

  async verify(signerVerkey: Verkey, data: Buffer, signature: Buffer): Promise<boolean> {
    // check signature
    const isValid = await this.indy.cryptoVerify(signerVerkey, data, signature);

    return isValid;
  }

  async close() {
    if (!this.wh) {
      throw Error('Wallet has not been initialized yet');
    }

    return this.indy.closeWallet(this.wh);
  }

  async delete() {
    if (!this.wh) {
      throw Error('Wallet has not been initialized yet');
    }

    return this.indy.deleteWallet(this.walletConfig, this.walletCredentials);
  }

  async addWalletRecord(type: string, id: string, value: string, tags: {}) {
    if (!this.wh) {
      throw new Error(`Wallet has not been initialized yet`);
    }
    return this.indy.addWalletRecord(this.wh, type, id, value, tags);
  }

  async updateWalletRecordValue(type: string, id: string, value: string) {
    if (!this.wh) {
      throw new Error(`Wallet has not been initialized yet`);
    }
    return this.indy.updateWalletRecordValue(this.wh, type, id, value);
  }

  async updateWalletRecordTags(type: string, id: string, tags: {}) {
    if (!this.wh) {
      throw new Error(`Wallet has not been initialized yet`);
    }
    return this.indy.addWalletRecordTags(this.wh, type, id, tags);
  }

  async deleteWalletRecord(type: string, id: string) {
    if (!this.wh) {
      throw new Error(`Wallet has not been initialized yet`);
    }
    return this.indy.deleteWalletRecord(this.wh, type, id);
  }

  async search(type: string, query: {}, options: {}) {
    if (!this.wh) {
      throw new Error(`Wallet has not been initialized yet`);
    }
    const sh: number = await this.indy.openWalletSearch(this.wh, type, query, options);
    const generator = async function* (indy: Indy, wh: number) {
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

    return generator(this.indy, this.wh);
  }

  getWalletRecord(type: string, id: string, options: {}): Promise<WalletRecord> {
    if (!this.wh) {
      throw new Error(`Wallet has not been initialized yet`);
    }
    return this.indy.getWalletRecord(this.wh, type, id, options);
  }

  signRequest(myDid: Did, request: LedgerRequest) {
    if (!this.wh) {
      throw new Error(`Wallet has not been initialized yet`);
    }
    return this.indy.signRequest(this.wh, myDid, request);
  }

  private keyForLocalDid(did: Did) {
    if (!this.wh) {
      throw Error('Wallet has not been initialized yet');
    }

    return this.indy.keyForLocalDid(this.wh, did);
  }
}
