export declare class OPVault {
  constructor(profile: JSON, items: Object);
  unlock(masterPassword: String): Promise<true>;
  isUnlocked(): Boolean;
  lock(): Boolean;
  loadItems(): Promise<Object>;
  getItem(
    title: String
  ): Promise<{
    overview: {
      title: String;
      url: String;
      tags: Array;
      uuid: String;
      URLs: Array;
    };
    detail: {
      fields: [
        {
          type: String;
          value: String;
          designation: String;
          name: String;
        }
      ];
      htmlForm: {
        htmlAction: String;
        htmlName: String;
        htmlMethod: String;
      };
    };
  }>;
}
