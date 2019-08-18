"use strict";
var __assign = (this && this.__assign) || function () {
    __assign = Object.assign || function(t) {
        for (var s, i = 1, n = arguments.length; i < n; i++) {
            s = arguments[i];
            for (var p in s) if (Object.prototype.hasOwnProperty.call(s, p))
                t[p] = s[p];
        }
        return t;
    };
    return __assign.apply(this, arguments);
};
Object.defineProperty(exports, "__esModule", { value: true });
var crypto_1 = require("crypto");
var OPVault = /** @class */ (function () {
    function OPVault(profile, items, type) {
        var _this = this;
        if (type === void 0) { type = "json"; }
        this.getItems = function () {
            return _this.itemIndex;
        };
        this.unlock = function (masterPassword) {
            var salt = _this.type === "json"
                ? Buffer.from(_this.profileJson.salt, "base64")
                : Buffer.from(_this.profileJson.salt);
            var iterations = _this.profileJson.iterations;
            var keys = crypto_1.pbkdf2Sync(Buffer.from(masterPassword), salt, iterations, 64, "sha512");
            _this.derivedKeys = {
                encryptionKey: keys.slice(0, 32),
                macKey: keys.slice(32)
            };
            _this.getMasterKeys();
            _this.getOverviewKeys();
            return true;
        };
        this.lock = function () {
            _this.masterKeys = null;
            _this.overviewKeys = null;
            return true;
        };
        this.isUnlocked = function () {
            return Boolean(_this.masterKeys && _this.overviewKeys);
        };
        this.createEntry = function (_a) {
            var detail = _a.detail, overview = _a.overview;
            var itemKeys = _this.generateKeyPair();
            var k = _this.encryptItemKeys(itemKeys);
            var o = _this.encryptOpData(Buffer.from(JSON.stringify(overview)), _this.overviewKeys);
            var d = _this.encryptOpData(Buffer.from(JSON.stringify(detail)), itemKeys);
            var date = Math.floor(Date.now() / 1000);
            var returnData = {
                category: "001",
                created: date,
                d: d,
                k: k,
                o: o,
                tx: date,
                updated: date,
                uuid: overview.uuid
            };
            var hmac = _this.generateHMAC(returnData);
            return __assign({}, returnData, { hmac: hmac });
        };
        this.loadItems = function (excludeTrashed) {
            if (excludeTrashed === void 0) { excludeTrashed = false; }
            _this.itemIndex = {};
            for (var uuid in _this.items) {
                var item = _this.items[uuid];
                var overview = _this.itemOverview(item);
                if (overview.url) {
                    if (!excludeTrashed || !item.trashed) {
                        try {
                            var url = new URL(overview.url).hostname;
                            _this.itemIndex[url] = uuid;
                        }
                        catch (e) {
                            overview.title ? (_this.itemIndex[overview.title] = uuid) : null;
                        }
                    }
                }
            }
            return _this.itemIndex;
        };
        this.getItem = function (keyword) {
            var keys = Object.keys(_this.itemIndex);
            var index = keys
                .map(function (url) { return url.search(new RegExp(keyword)) > -1; })
                .indexOf(true);
            if (index > -1) {
                var uuid = _this.itemIndex[keys[index]];
                var item = _this.items[uuid];
                return {
                    overview: _this.itemOverview(item),
                    detail: _this.itemDetail(item)
                };
            }
            else {
                throw new Error("No item found.");
            }
        };
        this.getMasterKeys = function () {
            var encrypted = _this.type === "json"
                ? Buffer.from(_this.profileJson.masterKey, "base64")
                : Buffer.from(_this.profileJson.masterKey);
            _this.masterKeys = _this.decryptKeys(encrypted, _this.derivedKeys);
        };
        this.getOverviewKeys = function () {
            var encrypted = _this.type === "json"
                ? Buffer.from(_this.profileJson.overviewKey, "base64")
                : Buffer.from(_this.profileJson.overviewKey);
            _this.overviewKeys = _this.decryptKeys(encrypted, _this.derivedKeys);
        };
        this.decryptKeys = function (encryptedKey, encryptionKeys) {
            var keyBase = _this.decryptOpdata(encryptedKey, encryptionKeys);
            var digest = crypto_1.createHash("sha512")
                .update(keyBase)
                .digest();
            return {
                encryptionKey: digest.slice(0, 32),
                macKey: digest.slice(32)
            };
        };
        this.decryptOpdata = function (cipherText, cipherKeys) {
            var keyData = cipherText.slice(0, -32);
            var macData = cipherText.slice(-32);
            _this.checkHmac(keyData, cipherKeys.macKey, macData);
            var plaintext = _this.decryptData(cipherKeys.encryptionKey, keyData.slice(16, 32), keyData.slice(32));
            var plaintextSize = keyData.slice(8, 24).readUInt32LE(0);
            return plaintext.slice(-plaintextSize);
        };
        this.checkHmac = function (data, hmacKey, desiredHmac) {
            var generatedHMAC = crypto_1.createHmac("sha256", hmacKey)
                .update(data)
                .digest();
            var isValid = generatedHMAC.equals(desiredHmac);
            if (!isValid) {
                throw new Error("Invalid Credentials.");
            }
            return true;
        };
        this.itemKeys = function (item) {
            //a = encrypt(itemkey)
            //b = encrypt(mackey);
            //c = hmac(iv+a+b)
            // k = iv + a + b + c;
            //iv = 128 bits = 16 bytes
            //itemKey = 256bits = 32bytes
            //mackey = 256bits = 32bytes
            // c = mac data = 256bits = 32 bytes
            // total = 16+32+32+32 = 112bytes
            var itemKey = _this.type === "json"
                ? Buffer.from(item.k, "base64")
                : Buffer.from(item.k);
            var keyData = itemKey.slice(0, -32);
            var macData = itemKey.slice(-32);
            _this.checkHmac(keyData, _this.masterKeys.macKey, macData);
            var plaintext = _this.decryptData(_this.masterKeys.encryptionKey, keyData.slice(0, 16), keyData.slice(16));
            return {
                encryptionKey: plaintext.slice(0, 32),
                macKey: plaintext.slice(32)
            };
        };
        this.itemOverview = function (item) {
            var overviewData = _this.type === "json"
                ? Buffer.from(item.o, "base64")
                : Buffer.from(item.o);
            var overview = _this.decryptOpdata(overviewData, _this.overviewKeys);
            var itemData = JSON.parse(overview.toString());
            itemData.uuid = item.uuid;
            return itemData;
        };
        this.itemDetail = function (item) {
            var data = _this.type === "json"
                ? Buffer.from(item.d, "base64")
                : Buffer.from(item.d);
            var itemKeys = _this.itemKeys(item);
            var detail = _this.decryptOpdata(data, itemKeys);
            return JSON.parse(detail.toString());
        };
        this.decryptData = function (key, iv, data) {
            var padding = Buffer.from(new Uint8Array([
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
            ]));
            var paddingCipher = crypto_1.createCipheriv("aes-256-cbc", key, data.slice(-16));
            paddingCipher.setAutoPadding(false);
            var suffix = Buffer.concat([
                paddingCipher.update(padding),
                paddingCipher.final()
            ]);
            var paddedData = Buffer.concat([data, suffix]);
            var plainText = crypto_1.createDecipheriv("aes-256-cbc", key, iv);
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
        this.encryptItemKeys = function (itemKeys) {
            var iv = _this.generateIV();
            var combinedKey = Buffer.concat([
                itemKeys.encryptionKey,
                itemKeys.macKey
            ]);
            var cipher = crypto_1.createCipheriv("aes-256-cbc", _this.masterKeys.encryptionKey, iv);
            cipher.setAutoPadding(false);
            var ek = Buffer.concat([cipher.update(combinedKey), cipher.final()]);
            var encryptedKeyWithIV = Buffer.concat([iv, ek]);
            var hash = crypto_1.createHmac("sha256", _this.masterKeys.macKey)
                .update(encryptedKeyWithIV)
                .digest();
            var encrypted = Buffer.concat([encryptedKeyWithIV, hash]);
            return _this.type === "json"
                ? encrypted.toString("base64")
                : encrypted.toString();
        };
        this.encryptOpData = function (data, _a) {
            var encryptionKey = _a.encryptionKey, macKey = _a.macKey;
            var iv = _this.generateIV();
            var opData01 = Buffer.from([111, 112, 100, 97, 116, 97, 48, 49]);
            var length = Buffer.from(_this.splitToByte(data.byteLength));
            var remainder = data.byteLength % 16;
            var extraData = crypto_1.randomBytes(remainder === 0 ? 16 : 16 - remainder);
            var paddedData = Buffer.concat([extraData, data]);
            var header = Buffer.concat([opData01, length, iv]);
            var cipher = crypto_1.createCipheriv("aes-256-cbc", encryptionKey, iv);
            cipher.setAutoPadding(false);
            var encryptedData = Buffer.concat([
                cipher.update(paddedData),
                cipher.final()
            ]);
            var combinedData = Buffer.concat([header, encryptedData]);
            var hash = crypto_1.createHmac("sha256", macKey)
                .update(combinedData)
                .digest();
            var encrypted = Buffer.concat([combinedData, hash]);
            return _this.type === "json"
                ? encrypted.toString("base64")
                : encrypted.toString();
        };
        this.generateKeyPair = function () {
            var encryptionKey = crypto_1.randomBytes(32);
            var macKey = crypto_1.randomBytes(32);
            return { encryptionKey: encryptionKey, macKey: macKey };
        };
        this.generateIV = function () {
            return crypto_1.randomBytes(16);
        };
        this.splitToByte = function (number) {
            var splitArray = new Uint8Array([0, 0, 0, 0, 0, 0, 0, 0]);
            for (var i = 0; i < 4; i++) {
                splitArray[i] = number >> (i * 8);
            }
            return splitArray;
        };
        this.generateHMAC = function (data) {
            var macKey = _this.overviewKeys.macKey;
            var dataArray = [];
            Object.keys(data).map(function (key) {
                dataArray.push(Buffer.from(key));
                dataArray.push(data[key].hasOwnProperty("byteLength")
                    ? data[key]
                    : Buffer.from(String(data[key])));
            });
            var mergedData = Buffer.concat(dataArray);
            return crypto_1.createHmac("sha256", macKey)
                .update(mergedData)
                .digest("base64");
        };
        this.profileJson = profile;
        this.items = items;
        this.type = type;
    }
    return OPVault;
}());
exports.default = OPVault;
