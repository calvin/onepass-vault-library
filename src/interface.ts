export interface Vault {
  unlock: (masterPassword: string) => boolean;
  isUnlocked(): boolean;
  lock(): boolean;
  loadItems(): Object;
  getItem: (title: string) => OPItem;
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
