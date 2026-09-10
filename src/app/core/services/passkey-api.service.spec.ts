import { TestBed } from '@angular/core/testing';
import { HttpClientTestingModule, HttpTestingController } from '@angular/common/http/testing';
import { PasskeyApiService } from './passkey-api.service';
import { UrlResolverService } from './url-resolver.service';

describe('PasskeyApiService', () => {
  let service: PasskeyApiService;
  let httpMock: HttpTestingController;
  const AUTH_BASE = 'https://tenant.test/api/v1/auth';

  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [HttpClientTestingModule],
      providers: [
        PasskeyApiService,
        { provide: UrlResolverService, useValue: { serverUrl: () => 'https://tenant.test' } },
      ],
    });
    service = TestBed.inject(PasskeyApiService);
    httpMock = TestBed.inject(HttpTestingController);
  });

  afterEach(() => httpMock.verify());

  it('confirmSession POSTs the refresh token to the passkey confirm-session endpoint', () => {
    service.confirmSession('p1', 'refresh-abc').subscribe();

    const req = httpMock.expectOne(`${AUTH_BASE}/passkeys/p1/confirm-session`);
    expect(req.request.method).toBe('POST');
    expect(req.request.body).toEqual({ refreshToken: 'refresh-abc' });
    req.flush(null);
  });

  it('registerPasskey forwards the optional refreshToken in the request body', () => {
    service.registerPasskey({ credentialId: 'c1', displayName: 'Laptop', refreshToken: 'r1' }).subscribe();

    const req = httpMock.expectOne(`${AUTH_BASE}/passkeys`);
    expect(req.request.method).toBe('POST');
    expect(req.request.body).toEqual({ credentialId: 'c1', displayName: 'Laptop', refreshToken: 'r1' });
    req.flush({});
  });

  it('registerPasskey works without a refreshToken', () => {
    service.registerPasskey({ credentialId: 'c1', displayName: 'Laptop' }).subscribe();

    const req = httpMock.expectOne(`${AUTH_BASE}/passkeys`);
    expect(req.request.body).toEqual({ credentialId: 'c1', displayName: 'Laptop' });
    req.flush({});
  });

  it('listPasskeys GETs the passkeys endpoint', () => {
    service.listPasskeys().subscribe();

    const req = httpMock.expectOne(`${AUTH_BASE}/passkeys`);
    expect(req.request.method).toBe('GET');
    req.flush([]);
  });

  it('renamePasskey PATCHes the display name', () => {
    service.renamePasskey('p1', 'New name').subscribe();

    const req = httpMock.expectOne(`${AUTH_BASE}/passkeys/p1`);
    expect(req.request.method).toBe('PATCH');
    expect(req.request.body).toEqual({ displayName: 'New name' });
    req.flush({});
  });

  it('deletePasskey DELETEs the passkey', () => {
    service.deletePasskey('p1').subscribe();

    const req = httpMock.expectOne(`${AUTH_BASE}/passkeys/p1`);
    expect(req.request.method).toBe('DELETE');
    req.flush(null);
  });

  it('revokeSessions POSTs to the revoke-sessions endpoint', () => {
    service.revokeSessions('p1').subscribe();

    const req = httpMock.expectOne(`${AUTH_BASE}/passkeys/p1/revoke-sessions`);
    expect(req.request.method).toBe('POST');
    req.flush(null);
  });
});
