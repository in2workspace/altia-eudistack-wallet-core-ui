// The real module is ESM-only and unused by createPasskey(); stub it so the
// spec never loads it.
jest.mock('@noble/curves/nist.js', () => ({ p256: { getPublicKey: jest.fn() } }));

import { TestBed } from '@angular/core/testing';
import { PasskeyPrfService } from './passkey-prf.service';
import { PasskeyStoreService } from './passkey-store.service';
import { base64UrlDecode } from '../utils/base64url';

describe('PasskeyPrfService — createPasskey WebAuthn user handle', () => {
  let service: PasskeyPrfService;
  let store: {
    getWebAuthnUserId: jest.Mock;
    setWebAuthnUserId: jest.Mock;
    setCredentialId: jest.Mock;
    getCredentialId: jest.Mock;
  };
  let createMock: jest.Mock;

  beforeEach(() => {
    store = {
      getWebAuthnUserId: jest.fn().mockReturnValue(null),
      setWebAuthnUserId: jest.fn().mockResolvedValue(undefined),
      setCredentialId: jest.fn().mockResolvedValue(undefined),
      getCredentialId: jest.fn().mockReturnValue(null),
    };

    TestBed.configureTestingModule({
      providers: [
        PasskeyPrfService,
        { provide: PasskeyStoreService, useValue: store },
      ],
    });
    service = TestBed.inject(PasskeyPrfService);

    Object.defineProperty(globalThis, 'crypto', {
      value: { getRandomValues: (buf: Uint8Array) => { buf.fill(7); return buf; } },
      configurable: true,
      writable: true,
    });

    createMock = jest.fn().mockResolvedValue({ rawId: new Uint8Array([1, 2, 3, 4]).buffer });
    Object.defineProperty(globalThis.navigator, 'credentials', {
      value: { create: createMock },
      configurable: true,
      writable: true,
    });
  });

  it('generates and persists a stable handle keyed by the account the first time', async () => {
    await service.createPasskey('Alice', 'alice@example.com');

    expect(store.getWebAuthnUserId).toHaveBeenCalledWith('alice@example.com');
    expect(store.setWebAuthnUserId).toHaveBeenCalledTimes(1);
    const [accountKey, persisted] = store.setWebAuthnUserId.mock.calls[0];
    expect(accountKey).toBe('alice@example.com');
    expect(typeof persisted).toBe('string');
    expect(persisted.length).toBeGreaterThan(0);
  });

  it('defaults the account key to the display name when none is passed', async () => {
    await service.createPasskey('Alice');

    expect(store.getWebAuthnUserId).toHaveBeenCalledWith('Alice');
  });

  it('reuses the stored handle for the same account instead of generating a new one', async () => {
    // 16 zero bytes, base64url
    const storedHandle = 'AAAAAAAAAAAAAAAAAAAAAA';
    store.getWebAuthnUserId.mockReturnValue(storedHandle);

    await service.createPasskey('Alice', 'alice@example.com');

    expect(store.setWebAuthnUserId).not.toHaveBeenCalled();
    const passedUserId = createMock.mock.calls[0][0].publicKey.user.id as Uint8Array;
    expect(Array.from(passedUserId)).toEqual(Array.from(base64UrlDecode(storedHandle)));
  });

  it('mints a fresh handle for a second account (no handle stored for it yet)', async () => {
    // The store returns null for bob's key because only alice's was set.
    store.getWebAuthnUserId.mockImplementation((key: string) =>
      key === 'alice@example.com' ? 'AAAAAAAAAAAAAAAAAAAAAA' : null);

    await service.createPasskey('Bob', 'bob@example.com');

    expect(store.setWebAuthnUserId).toHaveBeenCalledWith('bob@example.com', expect.any(String));
    const persisted = store.setWebAuthnUserId.mock.calls[0][1];
    expect(persisted).not.toBe('AAAAAAAAAAAAAAAAAAAAAA');
  });

  it('stores the created credential id and returns it', async () => {
    const credentialId = await service.createPasskey('Alice', 'alice@example.com');

    expect(store.setCredentialId).toHaveBeenCalledWith(credentialId);
    expect(credentialId).toBeTruthy();
  });
});
