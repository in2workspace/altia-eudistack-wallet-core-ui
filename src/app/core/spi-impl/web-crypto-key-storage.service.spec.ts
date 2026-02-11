import { TestBed } from '@angular/core/testing';

import { WebCryptoKeyStorageService } from '../spi/web-crypto-key-storage.service';

describe('WebCryptoKeyStorageService', () => {
  let service: WebCryptoKeyStorageService;

  beforeEach(() => {
    TestBed.configureTestingModule({});
    service = TestBed.inject(WebCryptoKeyStorageService);
  });

  it('should be created', () => {
    expect(service).toBeTruthy();
  });
});
