import { TestBed } from '@angular/core/testing';

import { IndexedDbCredentiaStorageTsService } from './indexed-db-credentia-storage.ts.service';

describe('IndexedDbCredentiaStorageTsService', () => {
  let service: IndexedDbCredentiaStorageTsService;

  beforeEach(() => {
    TestBed.configureTestingModule({});
    service = TestBed.inject(IndexedDbCredentiaStorageTsService);
  });

  it('should be created', () => {
    expect(service).toBeTruthy();
  });
});
