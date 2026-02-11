import { TestBed } from '@angular/core/testing';

import { CredentialStorageProviderTsService } from './credential-storage.provider.ts.service';

describe('CredentialStorageProviderTsService', () => {
  let service: CredentialStorageProviderTsService;

  beforeEach(() => {
    TestBed.configureTestingModule({});
    service = TestBed.inject(CredentialStorageProviderTsService);
  });

  it('should be created', () => {
    expect(service).toBeTruthy();
  });
});
