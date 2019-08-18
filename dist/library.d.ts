/// <reference types="node" />
export default class OPVault {
    items: any;
    profileJson: any;
    itemIndex: any;
    masterKeys: any;
    overviewKeys: any;
    derivedKeys: any;
    type: string;
    constructor(profile: any, items: any, type?: string);
    getItems: () => any;
    unlock: (masterPassword: string) => boolean;
    lock: () => boolean;
    isUnlocked: () => boolean;
    createEntry: ({ detail, overview }: any) => {
        hmac: string;
        category: string;
        created: number;
        d: string;
        k: string;
        o: string;
        tx: number;
        updated: number;
        uuid: any;
    };
    loadItems: (excludeTrashed?: boolean) => any;
    getItem: (keyword: string) => {
        overview: any;
        detail: any;
    };
    private getMasterKeys;
    private getOverviewKeys;
    private decryptKeys;
    private decryptOpdata;
    private checkHmac;
    private itemKeys;
    private itemOverview;
    private itemDetail;
    decryptData: (key: Buffer, iv: Buffer, data: Buffer) => Buffer;
    private encryptItemKeys;
    private encryptOpData;
    private generateKeyPair;
    private generateIV;
    private splitToByte;
    private generateHMAC;
}
