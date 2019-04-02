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
  htmlForm: { htmlAction: string; htmlName: string; htmlMethod: string };
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

  constructor(profile: any, items: any) {
    this._profileJson = profile;
    this._items = items;
  }

  getItems() {
    return this._itemIndex;
  }

  async unlock(masterPassword: any): Promise<true> {
    const salt = this._base64DecodeString(this._profileJson.salt);
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
    const encrypted = this._base64DecodeString(this._profileJson.masterKey);
    return this.decryptKeys(encrypted, derivedKeys);
  }

  async overviewKeys(derivedKeys: any) {
    const encrypted = this._base64DecodeString(this._profileJson.overviewKey);
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
    const itemKey = this._base64DecodeString(item.k);
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
    const overviewData = this._base64DecodeString(item.o);
    const overview = await this.decryptOpdata(overviewData, this._overviewKeys);
    const itemData = JSON.parse(new TextDecoder().decode(overview));
    itemData.uuid = item.uuid;
    return itemData;
  }

  async itemDetail(item: any): Promise<OPDetail> {
    const data = this._base64DecodeString(item.d);
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
        iv: data.slice(-16)
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

    const paddedData = new Uint8Array(data.length + 16);
    for (let i = 0; i < data.length; ++i) {
      paddedData[i] = data[i];
    }
    for (let i = 0; i < suffix.length; ++i) {
      paddedData[data.length + i] = suffix[i];
    }

    return window.crypto.subtle.decrypt(
      {
        name: "AES-CBC",
        iv: iv
      },
      cryptoKey,
      paddedData
    );
  }

  // https://stackoverflow.com/questions/21797299/convert-base64-string-to-arraybuffer
  _base64DecodeString(base64: any) {
    const b = window.atob(base64),
      n = b.length,
      a = new Uint8Array(n);
    for (let i = 0; i < n; i++) {
      a[i] = b.charCodeAt(i);
    }
    return a;
  }
}
