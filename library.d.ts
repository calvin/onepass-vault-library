export declare class OPVault {
  constructor(profile: Object, items: Object);
  unlock(masterPassword: string): Promise<true>;
  isUnlocked(): boolean;
  lock(): boolean;
  loadItems(): Promise<Object>;
  getItem(
    title: string
  ): Promise<{
    overview: {
      title: string;
      url: string;
      tags: Array;
      uuid: string;
      URLs: Array;
    };
    detail: {
      fields: [
        {
          type: string;
          value: string;
          designation: string;
          name: string;
        }
      ];
      htmlForm: {
        htmlAction: string;
        htmlName: string;
        htmlMethod: string;
      };
    };
  }>;
}
