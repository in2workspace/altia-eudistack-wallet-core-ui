import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { PasskeyApiService, PasskeyInfo } from './passkey-api.service';
import { UrlResolverService } from './url-resolver.service';

const SERVER_BASE = 'https://tenant.example.com';
const PASSKEYS_URL = `${SERVER_BASE}/api/v1/auth/passkeys`;

function setup(): { service: PasskeyApiService; httpMock: HttpTestingController } {
  TestBed.configureTestingModule({
    providers: [
      provideHttpClient(),
      provideHttpClientTesting(),
      PasskeyApiService,
      { provide: UrlResolverService, useValue: { serverUrl: () => SERVER_BASE } },
    ],
  });
  return {
    service: TestBed.inject(PasskeyApiService),
    httpMock: TestBed.inject(HttpTestingController),
  };
}

const samplePasskey: PasskeyInfo = {
  id: 'p1',
  credentialId: 'cred-1',
  displayName: 'My Laptop',
  createdAt: '2026-01-01T00:00:00.000Z',
  lastUsedAt: null,
  activeSessions: 1,
};

describe('PasskeyApiService', () => {
  afterEach(() => TestBed.inject(HttpTestingController).verify());

  describe('registerPasskey', () => {
    it('POSTs to /passkeys with the given payload, including an optional refreshToken', (done) => {
      const { service, httpMock } = setup();

      service.registerPasskey({
        credentialId: 'cred-1',
        displayName: 'My Laptop',
        userAgent: 'test-agent',
        refreshToken: 'refresh-abc',
      }).subscribe((res) => {
        expect(res).toEqual(samplePasskey);
        done();
      });

      const req = httpMock.expectOne(PASSKEYS_URL);
      expect(req.request.method).toBe('POST');
      expect(req.request.body).toEqual({
        credentialId: 'cred-1',
        displayName: 'My Laptop',
        userAgent: 'test-agent',
        refreshToken: 'refresh-abc',
      });
      req.flush(samplePasskey);
    });

    it('works without a refreshToken (optional field)', (done) => {
      const { service, httpMock } = setup();

      service.registerPasskey({ credentialId: 'cred-1', displayName: 'My Laptop' }).subscribe(() => done());

      const req = httpMock.expectOne(PASSKEYS_URL);
      expect(req.request.body.refreshToken).toBeUndefined();
      req.flush(samplePasskey);
    });
  });

  describe('listPasskeys', () => {
    it('GETs /passkeys and returns the list', (done) => {
      const { service, httpMock } = setup();

      service.listPasskeys().subscribe((res) => {
        expect(res).toEqual([samplePasskey]);
        done();
      });

      const req = httpMock.expectOne(PASSKEYS_URL);
      expect(req.request.method).toBe('GET');
      req.flush([samplePasskey]);
    });
  });

  describe('renamePasskey', () => {
    it('PATCHes /passkeys/{id} with the new displayName', (done) => {
      const { service, httpMock } = setup();

      service.renamePasskey('p1', 'New Name').subscribe((res) => {
        expect(res.displayName).toBe('New Name');
        done();
      });

      const req = httpMock.expectOne(`${PASSKEYS_URL}/p1`);
      expect(req.request.method).toBe('PATCH');
      expect(req.request.body).toEqual({ displayName: 'New Name' });
      req.flush({ ...samplePasskey, displayName: 'New Name' });
    });
  });

  describe('deletePasskey', () => {
    it('DELETEs /passkeys/{id}', (done) => {
      const { service, httpMock } = setup();

      service.deletePasskey('p1').subscribe(() => done());

      const req = httpMock.expectOne(`${PASSKEYS_URL}/p1`);
      expect(req.request.method).toBe('DELETE');
      req.flush(null);
    });
  });

  describe('revokeSessions', () => {
    it('POSTs to /passkeys/{id}/revoke-sessions with an empty body', (done) => {
      const { service, httpMock } = setup();

      service.revokeSessions('p1').subscribe(() => done());

      const req = httpMock.expectOne(`${PASSKEYS_URL}/p1/revoke-sessions`);
      expect(req.request.method).toBe('POST');
      expect(req.request.body).toEqual({});
      req.flush(null);
    });
  });

  describe('confirmSession', () => {
    it('POSTs to /passkeys/{id}/confirm-session with the refreshToken', (done) => {
      const { service, httpMock } = setup();

      service.confirmSession('p1', 'refresh-abc').subscribe(() => done());

      const req = httpMock.expectOne(`${PASSKEYS_URL}/p1/confirm-session`);
      expect(req.request.method).toBe('POST');
      expect(req.request.body).toEqual({ refreshToken: 'refresh-abc' });
      req.flush(null);
    });
  });
});
