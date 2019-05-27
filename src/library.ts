import { Vault, OPItem, OPDetail, OPOverview } from "./interface";
import {
  randomBytes,
  pbkdf2Sync,
  createHash,
  createHmac,
  createCipheriv,
  createDecipheriv
} from "crypto";

export default class OPVault implements Vault {
  items: any;
  profileJson: any;
  itemIndex: any;
  masterKeys: any;
  overviewKeys: any;
  derivedKeys: any;
  type: string;

  constructor(profile: any, items: any, type: string = "json") {
    this.profileJson = profile;
    this.items = items;
    this.type = type;
  }

  getItems = () => {
    return this.itemIndex;
  };

  unlock = (masterPassword: string) => {
    const salt =
      this.type === "json"
        ? Buffer.from(this.profileJson.salt, "base64")
        : Buffer.from(this.profileJson.salt);
    const { iterations } = this.profileJson;

    const keys = pbkdf2Sync(
      Buffer.from(masterPassword),
      salt,
      iterations,
      64,
      "sha512"
    );
    this.derivedKeys = {
      encryptionKey: keys.slice(0, 32),
      macKey: keys.slice(32)
    };
    this.getMasterKeys();
    this.getOverviewKeys();
    return true;
  };

  lock = () => {
    this.masterKeys = null;
    this.overviewKeys = null;

    return true;
  };

  isUnlocked = (): boolean => {
    return Boolean(this.masterKeys && this.overviewKeys);
  };

  createEntry = ({ detail, overview }: any) => {
    const itemKeys = this.generateKeyPair();
    const k = this.encryptItemKeys(itemKeys);
    const o = this.encryptOpData(
      Buffer.from(JSON.stringify(overview)),
      this.overviewKeys
    );
    const d = this.encryptOpData(Buffer.from(JSON.stringify(detail)), itemKeys);
    const date = Math.floor(Date.now() / 1000);
    const returnData = {
      category: "001",
      created: date,
      d,
      k,
      o,
      tx: date,
      updated: date,
      uuid: overview.uuid
    };
    const hmac = this.generateHMAC(returnData);
    return { ...returnData, hmac };
  };

  loadItems = (excludeTrashed = false) => {
    this.itemIndex = {};
    for (let uuid in this.items) {
      const item = this.items[uuid];
      const overview = this.itemOverview(item);
      if (overview.url) {
        if (!excludeTrashed || !item.trashed) {
          try {
            const url = new URL(overview.url).hostname;
            this.itemIndex[url] = uuid;
          } catch (e) {
            overview.title ? (this.itemIndex[overview.title] = uuid) : null;
          }
        }
      }
    }

    return this.itemIndex;
  };

  getItem = (fqdn: string): OPItem => {
    if (this.itemIndex.hasOwnProperty(fqdn)) {
      const uuid = this.itemIndex[fqdn];
      const item = this.items[uuid];
      return {
        overview: this.itemOverview(item),
        detail: this.itemDetail(item)
      };
    } else {
      throw new Error("No item found.");
    }
  };

  private getMasterKeys = () => {
    const encrypted =
      this.type === "json"
        ? Buffer.from(this.profileJson.masterKey, "base64")
        : Buffer.from(this.profileJson.masterKey);
    this.masterKeys = this.decryptKeys(encrypted, this.derivedKeys);
  };

  private getOverviewKeys = () => {
    const encrypted =
      this.type === "json"
        ? Buffer.from(this.profileJson.overviewKey, "base64")
        : Buffer.from(this.profileJson.overviewKey);
    this.overviewKeys = this.decryptKeys(encrypted, this.derivedKeys);
  };

  private decryptKeys = (encryptedKey: Buffer, encryptionKeys: any) => {
    const keyBase = this.decryptOpdata(encryptedKey, encryptionKeys);
    const digest = createHash("sha512")
      .update(keyBase)
      .digest();
    return {
      encryptionKey: digest.slice(0, 32),
      macKey: digest.slice(32)
    };
  };

  private decryptOpdata = (cipherText: Buffer, cipherKeys: any) => {
    const keyData = cipherText.slice(0, -32);
    const macData = cipherText.slice(-32);
    this.checkHmac(keyData, cipherKeys.macKey, macData);

    const plaintext = this.decryptData(
      cipherKeys.encryptionKey,
      keyData.slice(16, 32),
      keyData.slice(32)
    );
    //keyData.slice(8,24).readUInt32LE(0).;
    const dv = new DataView(keyData.buffer, 8, 16);
    // TODO: should be unsigned 64-bit int, but that's not a DataView method.
    const plaintextSize = dv.getUint32(0, true /* littleEndian */);
    return plaintext.slice(-plaintextSize);
  };

  private checkHmac = (data: Buffer, hmacKey: Buffer, desiredHmac: Buffer) => {
    const generatedHMAC = createHmac("sha256", hmacKey)
      .update(data)
      .digest();
    const isValid = generatedHMAC.equals(desiredHmac);
    if (!isValid) {
      throw new Error("Invalid Credentials.");
    }

    return true;
  };

  private itemKeys = (item: any) => {
    //a = encrypt(itemkey)
    //b = encrypt(mackey);
    //c = hmac(iv+a+b)
    // k = iv + a + b + c;
    //iv = 128 bits = 16 bytes
    //itemKey = 256bits = 32bytes
    //mackey = 256bits = 32bytes
    // c = mac data = 256bits = 32 bytes
    // total = 16+32+32+32 = 112bytes
    const itemKey =
      this.type === "json"
        ? Buffer.from(item.k, "base64")
        : Buffer.from(item.k);
    const keyData = itemKey.slice(0, -32);
    const macData = itemKey.slice(-32);

    this.checkHmac(keyData, this.masterKeys.macKey, macData);

    const plaintext = this.decryptData(
      this.masterKeys.encryptionKey,
      keyData.slice(0, 16),
      keyData.slice(16)
    );

    return {
      encryptionKey: plaintext.slice(0, 32),
      macKey: plaintext.slice(32)
    };
  };

  private itemOverview = (item: any): OPOverview => {
    const overviewData =
      this.type === "json"
        ? Buffer.from(item.o, "base64")
        : Buffer.from(item.o);
    const overview = this.decryptOpdata(overviewData, this.overviewKeys);
    const itemData = JSON.parse(overview.toString());
    itemData.uuid = item.uuid;
    return itemData;
  };

  private itemDetail = (item: any): OPDetail => {
    const data =
      this.type === "json"
        ? Buffer.from(item.d, "base64")
        : Buffer.from(item.d);
    const itemKeys = this.itemKeys(item);
    const detail = this.decryptOpdata(data, itemKeys);
    return JSON.parse(detail.toString());
  };

  decryptData = (key: Buffer, iv: Buffer, data: Buffer) => {
    const padding = Buffer.from(
      new Uint8Array([
        16,
        16,
        16,
        16,
        16,
        16,
        16,
        16,
        16,
        16,
        16,
        16,
        16,
        16,
        16,
        16
      ])
    );
    const paddingCipher = createCipheriv("aes-256-cbc", key, data.slice(-16));
    paddingCipher.setAutoPadding(false);
    const suffix = Buffer.concat([
      paddingCipher.update(padding),
      paddingCipher.final()
    ]);

    const paddedData = Buffer.concat([data, suffix]);
    const plainText = createDecipheriv("aes-256-cbc", key, iv);
    return Buffer.concat([plainText.update(paddedData), plainText.final()]);
  };
  //itemkey encrypted using master key.
  //a = encrypt(itemkey)
  //b = encrypt(mackey);
  //c = hmac(iv+a+b)
  // k = iv + a + b + c;
  //iv = 128 bits = 16 bytes
  //itemKey = 256bits = 32bytes
  //mackey = 256bits = 32bytes
  // c = mac data = 256bits = 32 bytes
  // total = 16+32+32+32 = 112bytes

  private encryptItemKeys = (itemKeys: any) => {
    const iv = this.generateIV();
    const combinedKey = Buffer.concat([
      itemKeys.encryptionKey,
      itemKeys.macKey
    ]);
    const cipher = createCipheriv(
      "aes-256-cbc",
      this.masterKeys.encryptionKey,
      iv
    );
    cipher.setAutoPadding(false);
    const ek = Buffer.concat([cipher.update(combinedKey), cipher.final()]);
    const encryptedKeyWithIV = Buffer.concat([iv, ek]);
    const hash = createHmac("sha256", this.masterKeys.macKey)
      .update(encryptedKeyWithIV)
      .digest();
    const encrypted = Buffer.concat([encryptedKeyWithIV, hash]);
    return this.type === "json"
      ? encrypted.toString("base64")
      : encrypted.toString();
  };

  private encryptOpData = (data: Buffer, { encryptionKey, macKey }: any) => {
    const iv = this.generateIV();
    const opData01 = Buffer.from([111, 112, 100, 97, 116, 97, 48, 49]);
    const length = Buffer.from(this.splitToByte(data.byteLength));
    const remainder = data.byteLength % 16;
    const extraData = randomBytes(remainder === 0 ? 16 : 16 - remainder);
    const paddedData = Buffer.concat([extraData, data]);
    const header = Buffer.concat([opData01, length, iv]);
    const cipher = createCipheriv("aes-256-cbc", encryptionKey, iv);
    cipher.setAutoPadding(false);
    const encryptedData = Buffer.concat([
      cipher.update(paddedData),
      cipher.final()
    ]);
    const combinedData = Buffer.concat([header, encryptedData]);
    const hash = createHmac("sha256", macKey)
      .update(combinedData)
      .digest();
    const encrypted = Buffer.concat([combinedData, hash]);
    return this.type === "json"
      ? encrypted.toString("base64")
      : encrypted.toString();
  };

  private generateKeyPair = () => {
    const encryptionKey = randomBytes(32);
    const macKey = randomBytes(32);
    return { encryptionKey, macKey };
  };

  private generateIV = () => {
    return randomBytes(16);
  };

  private splitToByte = (number: number) => {
    const splitArray = new Uint8Array([0, 0, 0, 0, 0, 0, 0, 0]);
    for (let i = 0; i < 4; i++) {
      splitArray[i] = number >> (i * 8);
    }
    return splitArray;
  };

  private generateHMAC = (data: any) => {
    const { macKey } = this.overviewKeys;
    const dataArray: Array<Uint8Array> = [];
    Object.keys(data).map(key => {
      dataArray.push(Buffer.from(key));
      dataArray.push(
        data[key].hasOwnProperty("byteLength")
          ? data[key]
          : Buffer.from(String(data[key]))
      );
    });
    const mergedData = Buffer.concat(dataArray);
    return createHmac("sha256", macKey)
      .update(mergedData)
      .digest("base64");
  };
}
