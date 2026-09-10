import { TestBed } from '@angular/core/testing';
import { PasskeyStoreService } from './passkey-store.service';

describe('PasskeyStoreService', () => {
  let service: PasskeyStoreService;
  let deletedKeys: string[];

  beforeEach(() => {
    TestBed.configureTestingModule({ providers: [PasskeyStoreService] });
    service = TestBed.inject(PasskeyStoreService);

    deletedKeys = [];
    // Stub the IndexedDB layer so tests exercise the cache + key-scoping logic
    // without a real database.
    jest.spyOn(service as unknown as { put: () => Promise<void> }, 'put').mockResolvedValue(undefined);
    jest.spyOn(service as unknown as { putAll: () => Promise<void> }, 'putAll').mockResolvedValue(undefined);
    jest.spyOn(service as unknown as { awaitTx: () => Promise<void> }, 'awaitTx').mockResolvedValue(undefined);
    jest.spyOn(service as unknown as { openDatabase: () => Promise<unknown> }, 'openDatabase').mockResolvedValue({
      transaction: () => ({
        objectStore: () => ({ delete: (key: string) => deletedKeys.push(key) }),
      }),
      close: () => undefined,
    });
  });

  describe('WebAuthn user handle', () => {
    it('returns null when nothing is stored', () => {
      expect(service.getWebAuthnUserId()).toBeNull();
    });

    it('persists the handle and reads it back synchronously from cache', async () => {
      await service.setWebAuthnUserId('handle-123');

      expect(service.getWebAuthnUserId()).toBe('handle-123');
      expect((service as unknown as { put: jest.Mock }).put).toHaveBeenCalledWith({
        key: 'webauthn_user_id',
        value: 'handle-123',
      });
    });
  });

  describe('clear() key scoping', () => {
    it('drops the credential but keeps the WebAuthn user handle', async () => {
      await service.setWebAuthnUserId('handle-123');
      await service.setCredentialId('cred-1');

      await service.clear();

      expect(service.getCredentialId()).toBeNull();
      expect(service.hasPasskey()).toBe(false);
      expect(service.getWebAuthnUserId()).toBe('handle-123');
      expect(deletedKeys).toEqual(['credential_id', 'has_passkey']);
      expect(deletedKeys).not.toContain('webauthn_user_id');
    });

    it('clearCredentialId() delegates to clear() and keeps the handle', async () => {
      await service.setWebAuthnUserId('handle-123');
      await service.setCredentialId('cred-1');

      await service.clearCredentialId();

      expect(service.getCredentialId()).toBeNull();
      expect(service.getWebAuthnUserId()).toBe('handle-123');
    });
  });
});
