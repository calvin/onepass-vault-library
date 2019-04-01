export declare class OPVault {
  constructor(profile: Object, items: Object);
  unlock(masterPassword: string): Promise<true>;
  isUnlocked(): boolean;
  lock(): boolean;
  loadItems(): Promise<Object>;
  getItem(title: string): Promise<OPItem>;
}

export type OPField = {
  type: string;
  value: string;
  designation: string;
  name: string;
};

export type OPHtmlForm = {
  htmlAction: string;
  htmlName: string;
  htmlMethod: string;
};

export type OPItem = {
  overview: {
    title: string;
    url: string;
    tags: Array;
    uuid: string;
    URLs: Array;
  };
  detail: {
    fields: [OPField];
    htmlForm: OPHtmlForm;
  };
};
