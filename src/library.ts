/**
 * Extended from: https://github.com/keanulee/opvault-viewer/
 * Class structure inspired by https://github.com/OblivionCloudControl/opvault/blob/master/opvault/onepass.py
 * Crypto functions from https://github.com/diafygi/webcrypto-examples#hmac-verify
 * OPVault design https://support.1password.com/opvault-design/
 */

export interface Vault {
  unlock: (masterPassword: string) => Promise<true>;
  isUnlocked(): boolean;
  lock(): boolean;
  loadItems(): Promise<Object>;
  getItem: (title: string) => Promise<OPItem>;
  createEntry: (data: any) => any;
}

export interface OPItem {
  overview: OPOverview;
  detail: OPDetail;
}

export interface OPDetail {
  fields: [
    {
      type: string;
      value: string;
      designation: string;
      name: string;
    }
  ];
  sections?: [
    { title: string; name: string; fields?: [{ k: string; v: string }] }
  ];
  htmlForm?: { htmlAction: string; htmlName: string; htmlMethod: string };
}

export interface OPOverview {
  title: string;
  url: string;
  tags: Array<any>;
  uuid: string;
  URLs: Array<any>;
}

export default class OPVault implements Vault {
  _items: any;
  _profileJson: any;
  _itemIndex: any;
  _masterKeys: any;
  _overviewKeys: any;
  _type: string;

  constructor(profile: any, items: any, _type: string = "json") {
    this._profileJson = profile;
    this._items = items;
    this._type = _type;
  }

  getItems() {
    return this._itemIndex;
  }

  async unlock(masterPassword: any): Promise<true> {
    const salt =
      this._type === "json"
        ? this._base64DecodeString(this._profileJson.salt)
        : this._profileJson.salt;
    const iterations = this._profileJson.iterations;

    const derivedKeys = await this._deriveKeys(
      masterPassword,
      salt,
      iterations
    );

    this._masterKeys = await this.masterKeys(derivedKeys);
    this._overviewKeys = await this.overviewKeys(derivedKeys);

    return true;
  }

  lock() {
    this._masterKeys = null;
    this._overviewKeys = null;

    return true;
  }

  isUnlocked(): boolean {
    return Boolean(this._masterKeys && this._overviewKeys);
  }

  async _deriveKeys(masterPassword: any, salt: any, iterations: number) {
    const masterPasswordKey = await window.crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(masterPassword),
      //@ts-ignore
      { name: "PBKDF2" },
      false /* extractable */,
      ["deriveBits"]
    );
    const bits = await window.crypto.subtle.deriveBits(
      {
        name: "PBKDF2",
        salt: salt,
        iterations: iterations,
        hash: { name: "SHA-512" }
      },
      masterPasswordKey,
      512
    );
    return {
      encryptionKey: bits.slice(0, 32),
      macKey: bits.slice(32)
    };
  }

  async masterKeys(derivedKeys: any) {
    const encrypted =
      this._type === "json"
        ? this._base64DecodeString(this._profileJson.masterKey)
        : this._profileJson.masterKey;
    return this.decryptKeys(encrypted, derivedKeys);
  }

  async overviewKeys(derivedKeys: any) {
    const encrypted =
      this._type === "json"
        ? this._base64DecodeString(this._profileJson.overviewKey)
        : this._profileJson.overviewKey;
    return this.decryptKeys(encrypted, derivedKeys);
  }

  async decryptKeys(encryptedKey: any, derivedKeys: any) {
    const keyBase = await this.decryptOpdata(encryptedKey, derivedKeys);
    const digest = await window.crypto.subtle.digest(
      { name: "SHA-512" },
      keyBase
    );
    return {
      encryptionKey: digest.slice(0, 32),
      macKey: digest.slice(32)
    };
  }

  async decryptOpdata(cipherText: any, cipherKeys: any) {
    const keyData = cipherText.slice(0, -32);
    const macData = cipherText.slice(-32);

    await this.checkHmac(keyData, cipherKeys.macKey, macData);

    const plaintext = await this.decryptData(
      cipherKeys.encryptionKey,
      keyData.slice(16, 32),
      keyData.slice(32)
    );
    const dv = new DataView(keyData.buffer, 8, 16);
    // TODO: should be unsigned 64-bit int, but that's not a DataView method.
    const plaintextSize = dv.getUint32(0, true /* littleEndian */);

    return plaintext.slice(-plaintextSize);
  }

  async checkHmac(data: any, hmacKey: any, desiredHmac: any) {
    const key = await window.crypto.subtle.importKey(
      "raw",
      hmacKey,
      {
        name: "HMAC",
        hash: { name: "SHA-256" }
      },
      false /* extractable */,
      ["verify"]
    );

    const isValid = await window.crypto.subtle.verify(
      //@ts-ignore
      { name: "HMAC" },
      key,
      desiredHmac,
      data
    );
    if (!isValid) {
      throw new Error("Invalid Credentials.");
    }

    return true;
  }

  async loadItems(excludeTrashed = false) {
    this._itemIndex = {};
    for (let uuid in this._items) {
      const item = this._items[uuid];
      const overview = await this.itemOverview(item);
      if (overview.url) {
        if (!excludeTrashed || !item.trashed) {
          try {
            const url = new URL(overview.url).hostname;
            this._itemIndex[url] = uuid;
          } catch (e) {
            overview.title ? (this._itemIndex[overview.title] = uuid) : null;
          }
        }
      }
    }

    return this._itemIndex;
  }

  async itemKeys(item: any) {
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
      this._type === "json" ? this._base64DecodeString(item.k) : item.k;
    const keyData = itemKey.slice(0, -32);
    const macData = itemKey.slice(-32);

    await this.checkHmac(keyData, this._masterKeys.macKey, macData);

    const plaintext = await this.decryptData(
      this._masterKeys.encryptionKey,
      keyData.slice(0, 16),
      keyData.slice(16)
    );

    return {
      encryptionKey: plaintext.slice(0, 32),
      macKey: plaintext.slice(32)
    };
  }

  async itemOverview(item: any): Promise<OPOverview> {
    const overviewData =
      this._type === "json" ? this._base64DecodeString(item.o) : item.o;
    const overview = await this.decryptOpdata(overviewData, this._overviewKeys);
    const itemData = JSON.parse(new TextDecoder().decode(overview));
    itemData.uuid = item.uuid;
    return itemData;
  }

  async itemDetail(item: any): Promise<OPDetail> {
    const data =
      this._type === "json" ? this._base64DecodeString(item.d) : item.d;
    const itemKeys = await this.itemKeys(item);
    const detail = await this.decryptOpdata(data, itemKeys);
    return JSON.parse(new TextDecoder().decode(detail));
  }

  async getItem(fqdn: string): Promise<OPItem> {
    if (this._itemIndex.hasOwnProperty(fqdn)) {
      const uuid = this._itemIndex[fqdn];
      const item = this._items[uuid];
      return {
        overview: await this.itemOverview(item),
        detail: await this.itemDetail(item)
      };
    } else {
      throw new Error("No item found.");
    }
  }

  async decryptData(key: any, iv: any, data: any) {
    // NOTE(keanulee): OPVault uses a custom padding scheme for AES-CBC
    // (https://support.1password.com/opvault-design/#opdata01), but Web Cryptography API
    // requires PKCS#7 (https://www.w3.org/TR/WebCryptoAPI/#aes-cbc-description).
    // Since the data is already padded and a multiple of 16 bytes, we can calculate the
    // last block by encrypting the plaintext PKCS#7 padding (16 bytes of 16 in Uint8)
    // using the same key and the last 16 bytes of the data as the initialization vector.
    // We append the first block (16 bytes) of the result to the data before decrypting.

    //@ts-ignore
    const cryptoKey = await window.crypto.subtle.importKey(
      "raw",
      key,
      //@ts-ignore
      { name: "AES-CBC" },
      false /* extractable */,
      ["encrypt", "decrypt"]
    );

    const suffixBuffer = await window.crypto.subtle.encrypt(
      {
        name: "AES-CBC",
        iv: data.slice(-16) //data.slice(-16) = encrypted item key
      },
      cryptoKey,
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
    const suffix = new Uint8Array(suffixBuffer, 0, 16);

    const paddedData = this._mergeArrayBuffers([data, suffix]);

    return window.crypto.subtle.decrypt(
      {
        name: "AES-CBC",
        iv: iv
      },
      cryptoKey,
      paddedData
    );
  }

  async createEntry({ detail, overview }: any) {
    const encoder = new TextEncoder();
    const itemKeys = await this._generateKeyPair();
    const k = await this._encryptItemKeys(itemKeys);
    const overviewKeys = await this._getCryptoKeys(this._overviewKeys);
    const o = await this._encryptOpData(
      encoder.encode(JSON.stringify(overview)),
      overviewKeys
    );
    const d = await this._encryptOpData(
      encoder.encode(JSON.stringify(detail)),
      await this._getCryptoKeys(itemKeys)
    );
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
    const hmac = await this._generateHMAC(returnData);
    return { ...returnData, hmac };
  }

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

  private async _encryptItemKeys(itemKeys: any) {
    const iv = this._generateIV();
    const masterKeys = await this._getCryptoKeys(this._masterKeys);
    const combinedKey = this._mergeArrayBuffers([
      new Uint8Array(itemKeys.encryptionKey),
      new Uint8Array(itemKeys.macKey)
    ]);
    //Removing the default pkcs#7 padding (16 bits) as opvault
    //implements it's own custom padding.
    const ek = new Uint8Array(
      await window.crypto.subtle.encrypt(
        { name: "AES-CBC", iv: iv },
        masterKeys.encryptionKey,
        combinedKey
      )
    ).slice(0, -16);
    const encryptedKeyWithIV = this._mergeArrayBuffers([iv, ek]);
    const hash = new Uint8Array(
      await window.crypto.subtle.sign(
        { name: "HMAC", hash: "SHA-256", length: 256 },
        masterKeys.macKey,
        encryptedKeyWithIV
      )
    );
    const encrypted = this._mergeArrayBuffers([encryptedKeyWithIV, hash]);
    return this._type === "json"
      ? this._base64EncodeBinary(encrypted)
      : encrypted;
  }

  private async _encryptOpData(data: any, { encryptionKey, macKey }: any) {
    const iv = this._generateIV();
    const opData01 = new Uint8Array([111, 112, 100, 97, 116, 97, 48, 49]);
    const length = this._splitToByte(data.byteLength);
    const remainder = data.byteLength % 16;
    const extraData = window.crypto.getRandomValues(
      new Uint8Array(remainder === 0 ? 16 : 16 - remainder)
    );
    const paddedData = this._mergeArrayBuffers([extraData, data]);
    const header = this._mergeArrayBuffers([opData01, length, iv]);
    //Removing the default pkcs#7 padding (16 bits) as opvault
    //implements it's own custom padding.
    const encryptedData = new Uint8Array(
      await window.crypto.subtle.encrypt(
        {
          name: "AES-CBC",
          iv
        },
        encryptionKey,
        paddedData
      )
    ).slice(0, -16);
    const combinedData = this._mergeArrayBuffers([header, encryptedData]);
    const hash = new Uint8Array(
      await window.crypto.subtle.sign(
        { name: "HMAC", hash: "SHA-256", length: 256 },
        macKey,
        combinedData
      )
    );
    const encrypted = this._mergeArrayBuffers([combinedData, hash]);
    return this._type === "json"
      ? this._base64EncodeBinary(encrypted)
      : encrypted;
  }

  private _mergeArrayBuffers(keys: Array<Uint8Array>): Uint8Array {
    let mergedArray: Array<number> = [];
    let length = 0;
    keys.map((key: any) => {
      for (let i = 0; i < key.byteLength; i++) {
        mergedArray[length + i] = key[i];
      }
      length += key.byteLength;
    });
    return new Uint8Array(mergedArray);
  }

  private async _generateKeyPair() {
    const encryptionKeyCrypto = await window.crypto.subtle.generateKey(
      { name: "AES-CBC", length: 256 },
      true,
      ["encrypt", "decrypt"]
    );

    const macKeyCrypto = await window.crypto.subtle.generateKey(
      { name: "HMAC", hash: "SHA-256", length: 256 },
      true,
      ["sign"]
    );
    const encryptionKey = await window.crypto.subtle.exportKey(
      "raw",
      encryptionKeyCrypto
    );
    const macKey = await window.crypto.subtle.exportKey("raw", macKeyCrypto);
    return { encryptionKey, macKey };
  }

  _generateIV() {
    return window.crypto.getRandomValues(new Uint8Array(16));
  }

  private async _getCryptoKeys(key: any) {
    const cryptoKey = await window.crypto.subtle.importKey(
      "raw",
      key.encryptionKey,
      //@ts-ignore
      { name: "AES-CBC" },
      false /* extractable */,
      ["encrypt", "decrypt"]
    );

    const cryptoKeyMac = await window.crypto.subtle.importKey(
      "raw",
      key.macKey,
      //@ts-ignore
      { name: "HMAC", hash: "SHA-256" },
      false /* extractable */,
      ["sign"]
    );
    return { encryptionKey: cryptoKey, macKey: cryptoKeyMac };
  }

  // https://stackoverflow.com/questions/21797299/convert-base64-string-to-arraybuffer
  private _base64DecodeString(base64: any) {
    const b = window.atob(base64),
      n = b.length,
      a = new Uint8Array(n);
    for (let i = 0; i < n; i++) {
      a[i] = b.charCodeAt(i);
    }
    return a;
  }

  private _base64EncodeBinary(binary: Uint8Array) {
    let text = "";
    for (let i = 0; i < binary.byteLength; i++) {
      text += String.fromCharCode(binary[i]);
    }
    return window.btoa(text);
  }

  //Javascript does not support 64bit unsigned integers. Using 32bit instead.
  private _splitToByte(number: number) {
    const splitArray = new Uint8Array([0, 0, 0, 0, 0, 0, 0, 0]);
    for (let i = 0; i < 4; i++) {
      splitArray[i] = number >> (i * 8);
    }
    return splitArray;
  }

  private _generateHMAC = async (data: any) => {
    const { macKey } = await this._getCryptoKeys(this._overviewKeys);
    const dataArray: Array<Uint8Array> = [];
    Object.keys(data).map(key => {
      dataArray.push(new TextEncoder().encode(key));
      dataArray.push(
        data[key].hasOwnProperty("byteLength")
          ? data[key]
          : new TextEncoder().encode(data[key])
      );
    });
    const mergedData = this._mergeArrayBuffers(dataArray);
    return this._base64EncodeBinary(
      new Uint8Array(
        await window.crypto.subtle.sign("HMAC", macKey, mergedData)
      )
    );
  };
}
