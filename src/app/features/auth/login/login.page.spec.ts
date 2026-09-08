import { ComponentFixture, TestBed } from '@angular/core/testing';
import { Router } from '@angular/router';
import { TranslateModule } from '@ngx-translate/core';
import { NEVER, Observable, of, throwError } from 'rxjs';
import { LoginPage } from './login.page';
import { AuthService } from 'src/app/core/services/auth.service';
import { PasskeyPrfService } from 'src/app/core/services/passkey-prf.service';
import { PasskeyStoreService } from 'src/app/core/services/passkey-store.service';
import { PasskeyApiService } from 'src/app/core/services/passkey-api.service';
import { ThemeService } from 'src/app/core/services/theme.service';
import { PwaInstallService } from 'src/app/shared/services/pwa-install.service';
import { WalletService } from 'src/app/core/services/wallet.service';
import { ActivityService } from 'src/app/core/services/activity.service';
import { CredentialCacheService } from 'src/app/shared/services/credential-cache.service';
import { PENDING_DEEP_LINK_KEY } from 'src/app/core/constants/deep-link.constants';

describe('LoginPage (server mode)', () => {
  let component: LoginPage;
  let fixture: ComponentFixture<LoginPage>;

  let mockAuthService: {
    register: jest.Mock;
    verifyEmail: jest.Mock;
    refreshAccessToken: jest.Mock;
  };
  let mockPrfService: {
    hasPasskey: jest.Mock;
    createPasskey: jest.Mock;
    getCredentialId: jest.Mock;
  };
  let mockPasskeyStore: { getCredentialId: jest.Mock; hasPasskey: jest.Mock };
  let mockPasskeyApi: { registerPasskey: jest.Mock; listPasskeys: jest.Mock };
  let mockRouter: { navigateByUrl: jest.Mock };
  let mockWalletService: { syncCredentials: jest.Mock };
  let mockActivityService: { syncFromServer: jest.Mock };
  let mockCredentialCache: { setLoading: jest.Mock; setError: jest.Mock };
  let baseProviders: { provide: unknown; useValue: unknown }[];

  beforeEach(async () => {
    localStorage.clear();
    sessionStorage.clear();

    Object.defineProperty(globalThis, 'crypto', {
      value: {
        subtle: {},
        getRandomValues: (buf: Uint8Array) => { buf.fill(0x42); return buf; },
      },
      configurable: true,
      writable: true,
    });

    mockAuthService = {
      register: jest.fn().mockReturnValue(of({ message: 'If the email is valid, you will receive a verification code.' })),
      verifyEmail: jest.fn().mockReturnValue(of({ accessToken: 'access-1', refreshToken: 'refresh-1', expiresIn: 900 })),
      refreshAccessToken: jest.fn().mockReturnValue(of({ accessToken: 'access-2', refreshToken: 'refresh-2', expiresIn: 900 })),
    };
    mockPrfService = {
      hasPasskey: jest.fn().mockReturnValue(false),
      createPasskey: jest.fn().mockResolvedValue('cred-local-1'),
      getCredentialId: jest.fn().mockReturnValue('cred-local-1'),
    };
    mockPasskeyStore = {
      getCredentialId: jest.fn().mockReturnValue('cred-local-1'),
      hasPasskey: jest.fn().mockReturnValue(true),
    };
    mockPasskeyApi = {
      registerPasskey: jest.fn().mockReturnValue(of({ id: 'p1', credentialId: 'cred-local-1', displayName: 'device' })),
      listPasskeys: jest.fn().mockReturnValue(of([])),
    };
    mockRouter = { navigateByUrl: jest.fn() };
    mockWalletService = { syncCredentials: jest.fn().mockReturnValue(of(undefined)) };
    mockActivityService = { syncFromServer: jest.fn().mockResolvedValue(undefined) };
    mockCredentialCache = { setLoading: jest.fn(), setError: jest.fn() };

    baseProviders = [
      { provide: AuthService, useValue: mockAuthService },
      { provide: PasskeyPrfService, useValue: mockPrfService },
      { provide: PasskeyStoreService, useValue: mockPasskeyStore },
      { provide: PasskeyApiService, useValue: mockPasskeyApi },
      { provide: Router, useValue: mockRouter },
      {
        provide: ThemeService,
        useValue: {
          getLogoUrl: jest.fn().mockReturnValue('logo.png'),
          // brandName() now derives from this stream instead of reading `snapshot`.
          getTheme: jest.fn().mockReturnValue(of(null)),
        },
      },
      {
        provide: PwaInstallService,
        useValue: { installDecision$: of(false), isStandalone: false, promptInstall: jest.fn() }
      },
      { provide: WalletService, useValue: mockWalletService },
      { provide: ActivityService, useValue: mockActivityService },
      { provide: CredentialCacheService, useValue: mockCredentialCache },
    ];

    await TestBed.configureTestingModule({
      imports: [LoginPage, TranslateModule.forRoot()],
      providers: baseProviders,
    }).compileComponents();

    fixture = TestBed.createComponent(LoginPage);
    component = fixture.componentInstance;
  });

  async function rebuildWithInstallDecision(decision: boolean, isStandalone = false): Promise<void> {
    TestBed.resetTestingModule();
    await TestBed.configureTestingModule({
      imports: [LoginPage, TranslateModule.forRoot()],
      providers: baseProviders.map(provider => provider.provide === PwaInstallService
        ? {
            provide: PwaInstallService,
            useValue: { installDecision$: of(decision), isStandalone, promptInstall: jest.fn() },
          }
        : provider),
    }).compileComponents();

    fixture = TestBed.createComponent(LoginPage);
    component = fixture.componentInstance;
  }

  it('should create in server mode', () => {
    expect(component.isBrowserMode).toBe(false);
  });

  describe('AC-05: edited device name is sent to registerPasskey', () => {
    it('sends the edited displayName when confirming passkey registration', async () => {
      component.step.set('passkey');
      component.needsPasskeySetup = true;
      component.deviceName = 'My Custom Laptop';

      await component.createPasskeyForDevice();

      expect(mockPasskeyApi.registerPasskey).toHaveBeenCalledWith(
        expect.objectContaining({ displayName: 'My Custom Laptop', credentialId: 'cred-local-1' })
      );
    });
  });

  describe('EC-04: device name defaults when the user does not edit it', () => {
    it('prefills deviceName after verifyCode() and registers with that default', async () => {
      component.email = 'user@example.com';
      component.otpValue = '123456';

      component.verifyCode();

      expect(component.step()).toBe('passkey');
      expect(component.needsPasskeySetup).toBe(true);
      expect(component.deviceName).toBeTruthy();

      const prefilledName = component.deviceName;
      await component.createPasskeyForDevice();

      expect(mockPasskeyApi.registerPasskey).toHaveBeenCalledWith(
        expect.objectContaining({ displayName: prefilledName })
      );
    });
  });

  describe('EC-05: resuming with a refresh token but no local passkey', () => {
    it('routes straight to the passkey step, skipping email/OTP', () => {
      localStorage.setItem('wallet_refresh_token', 'stored-refresh-token');
      mockPrfService.hasPasskey.mockReturnValue(false);

      component.ionViewWillEnter();

      expect(component.step()).toBe('passkey');
      expect(component.needsPasskeySetup).toBe(true);
      expect(component.deviceName).toBeTruthy();
      expect(mockAuthService.register).not.toHaveBeenCalled();
      expect(mockAuthService.verifyEmail).not.toHaveBeenCalled();
    });

    it('goes to the email step when there is no refresh token', () => {
      component.ionViewWillEnter();

      expect(component.step()).toBe('email');
      expect(component.needsPasskeySetup).toBe(false);
    });
  });

  describe('TECH-DEBT #1046140: needsPasskeySetup must not trust a stale local flag from another account', () => {
    it('forces device registration when the account has no server-side passkeys, even if the browser has a local one', () => {
      mockPrfService.hasPasskey.mockReturnValue(true);
      mockPasskeyApi.listPasskeys.mockReturnValue(of([]));
      component.email = 'new-account@example.com';
      component.otpValue = '123456';

      component.verifyCode();

      expect(mockPasskeyApi.listPasskeys).toHaveBeenCalled();
      expect(component.needsPasskeySetup).toBe(true);
      expect(component.step()).toBe('passkey');
      expect(component.deviceName).toBeTruthy();
    });

    it('does not force setup when this device\'s local credentialId matches one of the account\'s server-side passkeys', () => {
      mockPasskeyApi.listPasskeys.mockReturnValue(of([
        { id: 'p1', credentialId: 'cred-local-1', displayName: 'This Laptop', createdAt: '', lastUsedAt: null, activeSessions: 1 }
      ]));
      component.email = 'existing-account@example.com';
      component.otpValue = '123456';

      component.verifyCode();

      expect(component.needsPasskeySetup).toBe(false);
      expect(component.step()).toBe('passkey');
    });

    it('forces setup when the account has other passkeys but none match this device\'s local credentialId', () => {
      mockPasskeyApi.listPasskeys.mockReturnValue(of([
        { id: 'p1', credentialId: 'cred-on-phone', displayName: 'Phone', createdAt: '', lastUsedAt: null, activeSessions: 1 }
      ]));
      component.email = 'existing-account@example.com';
      component.otpValue = '123456';

      component.verifyCode();

      expect(component.needsPasskeySetup).toBe(true);
      expect(component.step()).toBe('passkey');
      expect(component.deviceName).toBeTruthy();
    });

    it('forces setup when this device has no local credentialId at all, even if the account has server-side passkeys', () => {
      mockPrfService.getCredentialId.mockReturnValue(null);
      mockPasskeyApi.listPasskeys.mockReturnValue(of([
        { id: 'p1', credentialId: 'cred-on-phone', displayName: 'Phone', createdAt: '', lastUsedAt: null, activeSessions: 1 }
      ]));
      component.email = 'existing-account@example.com';
      component.otpValue = '123456';

      component.verifyCode();

      expect(component.needsPasskeySetup).toBe(true);
      expect(component.step()).toBe('passkey');
    });

    it('fails safe to needsPasskeySetup=true when listPasskeys() errors', () => {
      mockPasskeyApi.listPasskeys.mockReturnValue(throwError(() => ({ status: 500 })));
      component.email = 'user@example.com';
      component.otpValue = '123456';

      component.verifyCode();

      expect(component.needsPasskeySetup).toBe(true);
      expect(component.step()).toBe('passkey');
      expect(component.loading).toBe(false);
    });
  });

  describe('ES-04: recoverable error on register()/verifyEmail() failure', () => {
    it('shows an error and stays on the email step when register() fails', () => {
      mockAuthService.register.mockReturnValue(throwError(() => ({ status: 500, error: {} })));
      component.email = 'user@example.com';

      component.sendCode();

      expect(component.step()).toBe('email');
      expect(component.errorMessage).toBeTruthy();
      expect(component.loading).toBe(false);
    });

    it('shows the neutral rate-limit message when register() returns 429', () => {
      mockAuthService.register.mockReturnValue(throwError(() => ({ status: 429 })));
      component.email = 'user@example.com';

      component.sendCode();

      expect(component.errorMessage).toBeTruthy();
      expect(component.loading).toBe(false);
    });

    it('shows an error and stays on the code step when verifyEmail() fails', () => {
      mockAuthService.verifyEmail.mockReturnValue(throwError(() => ({ status: 401, error: { message: 'invalid_code' } })));
      component.step.set('code');
      component.email = 'user@example.com';
      component.otpValue = '000000';

      component.verifyCode();

      expect(component.step()).toBe('code');
      expect(component.errorMessage).toBeTruthy();
      expect(component.loading).toBe(false);
    });
  });

  describe('ES-05 / AD-1: passkey server-side registration failure', () => {
    it('does not navigate and surfaces an error when registerPasskey() fails', async () => {
      mockPasskeyApi.registerPasskey.mockReturnValue(throwError(() => ({ status: 500 })));
      component.deviceName = 'My Device';

      await component.createPasskeyForDevice();

      expect(mockRouter.navigateByUrl).not.toHaveBeenCalled();
      expect(component.errorMessage).toBeTruthy();
      expect(component.loading).toBe(false);
    });

    it('allows a retry that succeeds after a prior failure', async () => {
      mockPasskeyApi.registerPasskey
        .mockReturnValueOnce(throwError(() => ({ status: 500 })))
        .mockReturnValueOnce(of({ id: 'p1', credentialId: 'cred-local-1', displayName: 'My Device' }));
      component.deviceName = 'My Device';

      await component.createPasskeyForDevice();
      expect(mockRouter.navigateByUrl).not.toHaveBeenCalled();

      await component.createPasskeyForDevice();
      expect(mockRouter.navigateByUrl).toHaveBeenCalled();
    });

    it('does not navigate home before the server-side registration resolves (AD-1 ordering)', async () => {
      let resolveRegister!: (value: unknown) => void;
      mockPasskeyApi.registerPasskey.mockReturnValue(new Observable(subscriber => {
        resolveRegister = (value) => { subscriber.next(value); subscriber.complete(); };
      }));
      component.deviceName = 'My Device';

      const pending = component.createPasskeyForDevice();
      await Promise.resolve();
      await Promise.resolve();

      expect(mockRouter.navigateByUrl).not.toHaveBeenCalled();

      resolveRegister({ id: 'p1', credentialId: 'cred-local-1', displayName: 'My Device' });
      await pending;

      expect(mockRouter.navigateByUrl).toHaveBeenCalled();
    });
  });

  // EUD-104 traceability note: AC-03 (editable device name) and EC-02 (default name) are
  // already exercised above by 'AC-05: edited device name...' and 'EC-04: device name
  // defaults...' respectively — those EUD-103 test names predate this Story, but the
  // assertions are the same ones EUD-104 needs (the frontend can't distinguish a first vs.
  // second device; needsPasskeySetup is purely local state). Same for ES-02, fully covered
  // by 'ES-05 / AD-1: passkey server-side registration failure' below.
  describe('EUD-104 EC-01: no navigation before a passkey is actually registered', () => {
    it('stays on the passkey-setup screen and does not navigate home right after verify', () => {
      component.email = 'user@example.com';
      component.otpValue = '123456';

      component.verifyCode();

      expect(component.needsPasskeySetup).toBe(true);
      expect(component.step()).toBe('passkey');
      expect(mockRouter.navigateByUrl).not.toHaveBeenCalled();
    });
  });

  describe('R-1: existing-passkey verification path (needsPasskeySetup = false) is unaffected', () => {
    it('authenticates locally and navigates home on success', async () => {
      const mockCredentialsGet = jest.fn().mockResolvedValue({});
      Object.defineProperty(globalThis.navigator, 'credentials', {
        value: { get: mockCredentialsGet },
        configurable: true,
        writable: true,
      });
      component.needsPasskeySetup = false;

      await component.verifyPasskey();

      expect(mockCredentialsGet).toHaveBeenCalled();
      expect(mockRouter.navigateByUrl).toHaveBeenCalled();
    });
  });

  describe('credential sync coordination on login', () => {
    beforeEach(() => {
      const mockCredentialsGet = jest.fn().mockResolvedValue({});
      Object.defineProperty(globalThis.navigator, 'credentials', {
        value: { get: mockCredentialsGet },
        configurable: true,
        writable: true,
      });
      component.needsPasskeySetup = false;
    });

    it('marks the store as loading before navigating', async () => {
      await component.verifyPasskey();

      expect(mockCredentialCache.setLoading).toHaveBeenCalled();
      expect(mockRouter.navigateByUrl).toHaveBeenCalled();
    });

    it('does NOT block navigation on the sync for a normal login (no deep link)', async () => {
      await component.verifyPasskey();

      // Fire-and-forget sync path; navigation happens regardless.
      expect(mockWalletService.syncCredentials).toHaveBeenCalled();
      expect(mockRouter.navigateByUrl).toHaveBeenCalled();
    });

    it('AWAITS the sync before navigating when a protocol deep link is pending', async () => {
      sessionStorage.setItem(PENDING_DEEP_LINK_KEY, '/tabs/credentials?authorizationRequest=xyz');

      let resolveSync!: () => void;
      mockWalletService.syncCredentials.mockReturnValue(
        new Observable<void>(sub => { resolveSync = () => { sub.next(); sub.complete(); }; })
      );

      const pending = component.verifyPasskey();
      await Promise.resolve();
      await Promise.resolve();

      // Navigation is held until the credential sync completes.
      expect(mockRouter.navigateByUrl).not.toHaveBeenCalled();

      resolveSync();
      await pending;

      expect(mockRouter.navigateByUrl).toHaveBeenCalled();
    });

    it('sets the store to error (not stuck loading) and still navigates when the awaited sync fails', async () => {
      sessionStorage.setItem(PENDING_DEEP_LINK_KEY, '/tabs/credentials?authorizationRequest=xyz');
      mockWalletService.syncCredentials.mockReturnValue(throwError(() => new Error('server down')));

      await component.verifyPasskey();

      expect(mockCredentialCache.setError).toHaveBeenCalled();
      // navigation is not blocked by the failure — the page then surfaces the error state
      expect(mockRouter.navigateByUrl).toHaveBeenCalled();
    });
  });

  describe('Dedalo-1052543: expired wallet session on LEAR Employee email deep-link', () => {
    beforeEach(() => {
      localStorage.setItem('wallet_refresh_token', 'stale-refresh');
      sessionStorage.setItem(
        PENDING_DEEP_LINK_KEY,
        '/protocol/callback?credential_offer_uri=https://sandbox.stg.eudistack.net/issuer/oid4vci/v1/credential-offer/abc'
      );
      mockPrfService.hasPasskey.mockReturnValue(true);
      mockPrfService.getCredentialId.mockReturnValue('cred-local-1');
      Object.defineProperty(navigator, 'credentials', {
        configurable: true,
        value: {
          get: jest.fn().mockResolvedValue({ id: 'assertion' }),
        },
      });
    });

    it('AC-01: on refresh failure, stays on email step with i18n session-expired, clears token and keeps the pending offer link', async () => {
      mockAuthService.refreshAccessToken.mockImplementation(() => {
        localStorage.removeItem('wallet_refresh_token');
        return throwError(() => ({ status: 401, error: { detail: 'invalid_grant' } }));
      });

      component.ionViewWillEnter();
      expect(component.step).toBe('passkey');

      await component.verifyPasskey();

      expect(mockAuthService.refreshAccessToken).toHaveBeenCalledWith({ onAuthFailure: 'clear-only' });
      expect(component.step).toBe('email');
      expect(component.errorMessage).toBe('auth.errors.session-expired-request-code');
      expect(localStorage.getItem('wallet_refresh_token')).toBeNull();
      expect(sessionStorage.getItem(PENDING_DEEP_LINK_KEY)).toContain('credential_offer_uri');
      expect(mockRouter.navigateByUrl).not.toHaveBeenCalled();
    });

    it('AC-02: follows full flow (expiry -> email step -> OTP -> resume) and completes deep link', async () => {
      // 1. Start with an expired session
      mockAuthService.refreshAccessToken.mockReturnValue(
        throwError(() => ({ status: 401, error: { detail: 'invalid_grant' } }))
      );

      component.ionViewWillEnter();
      await component.verifyPasskey();

      expect(component.step).toBe('email');
      expect(component.errorMessage).toBe('auth.errors.session-expired-request-code');
      expect(sessionStorage.getItem(PENDING_DEEP_LINK_KEY)).toBeTruthy();

      // 2. User re-authenticates via OTP
      component.email = 'user@example.com';
      component.otpValue = '123456';
      mockAuthService.verifyEmail.mockReturnValue(of({ accessToken: 'a', refreshToken: 'r', expiresIn: 900 }));
      mockPasskeyApi.listPasskeys.mockReturnValue(of([])); // Force needsPasskeySetup = true

      component.verifyCode();
      expect(component.step).toBe('passkey');
      expect(component.needsPasskeySetup).toBe(true);

      // 3. Complete passkey registration
      mockPasskeyApi.registerPasskey.mockReturnValue(of({ id: 'p1' }));
      await component.createPasskeyForDevice();

      // 4. Verification: resumes the offer and clears the pending key
      expect(mockRouter.navigateByUrl).toHaveBeenCalledWith(expect.stringContaining('credential_offer_uri=https://sandbox.stg.eudistack.net/issuer/oid4vci/v1/credential-offer/abc'));
      expect(sessionStorage.getItem(PENDING_DEEP_LINK_KEY)).toBeNull();
    });

    it('stays on passkey step if WebAuthn is cancelled, without clearing the token', async () => {
      // Simulate manual cancellation of the biometrics prompt
      Object.defineProperty(navigator, 'credentials', {
        configurable: true,
        value: {
          get: jest.fn().mockResolvedValue(null),
        },
      });

      localStorage.setItem('wallet_refresh_token', 'stale-refresh');
      component.ionViewWillEnter();
      expect(component.step).toBe('passkey');

      await component.verifyPasskey();

      // Result: user stays on passkey screen and token is still there
      expect(component.step).toBe('passkey');
      expect(component.errorMessage).toBe('Authentication cancelled');
      expect(localStorage.getItem('wallet_refresh_token')).toBe('stale-refresh');
      expect(mockAuthService.refreshAccessToken).not.toHaveBeenCalled();
    });
  });

  describe('LoginPage Coverage Improvements', () => {
    it('throws error in authenticateLocally if no credentialId is found', async () => {
      mockPrfService.getCredentialId.mockReturnValue(null);
      await expect(component['authenticateLocally']()).rejects.toThrow('No passkey found');
    });

    it('handles sync error in syncCredentialsThenNavigate for protocol links', async () => {
      sessionStorage.setItem(PENDING_DEEP_LINK_KEY, '/protocol/callback?offer=123');
      mockWalletService.syncCredentials.mockReturnValue(throwError(() => new Error('Sync failed')));
      const consoleSpy = jest.spyOn(console, 'error').mockImplementation();
      const cacheSpy = jest.spyOn(mockCredentialCache, 'setError');

      await component['syncCredentialsThenNavigate']();

      expect(consoleSpy).toHaveBeenCalledWith('Credential sync failed', expect.any(Error));
      expect(cacheSpy).toHaveBeenCalled();
      expect(mockRouter.navigateByUrl).toHaveBeenCalled();
    });

    it('identifies different types of protocol deep links', () => {
      expect(component['isProtocolDeepLink']('/protocol/test')).toBe(true);
      expect(component['isProtocolDeepLink']('/wallet/protocol/test')).toBe(true);
      expect(component['isProtocolDeepLink']('/tabs/vc-selector')).toBe(true);
      expect(component['isProtocolDeepLink']('?credential_offer_uri=...')).toBe(true);
      expect(component['isProtocolDeepLink']('/other')).toBe(false);
      expect(component['isProtocolDeepLink'](null)).toBe(false);
    });

    it('detects device names correctly based on UserAgent', () => {
      const originalUA = navigator.userAgent;
      const setUA = (ua: string) => {
        Object.defineProperty(navigator, 'userAgent', { value: ua, configurable: true });
      };

      setUA('iPhone'); expect(component['getDeviceName']()).toBe('iPhone');
      setUA('Android'); expect(component['getDeviceName']()).toBe('Android Device');
      setUA('Windows'); expect(component['getDeviceName']()).toBe('Windows PC');
      setUA('Unknown'); expect(component['getDeviceName']()).toBe('Unknown Device');

      setUA(originalUA);
    });

    it('handles passkey registration failure in createPasskeyForDevice', async () => {
      component.email = 'test@example.com';
      mockPrfService.createPasskey.mockRejectedValue(new Error('Hardware fail'));

      await component.createPasskeyForDevice();

      expect(component.errorMessage).toBe('Hardware fail');
      expect(component.loading).toBe(false);
    });

    it('handles case where createPasskey succeeds but getCredentialId returns null', async () => {
      component.email = 'test@example.com';
      mockPrfService.createPasskey.mockResolvedValue('ok');
      mockPasskeyStore.getCredentialId.mockReturnValue(null);

      await component.createPasskeyForDevice();

      expect(component.errorMessage).toBe('Failed to create passkey');
      expect(component.loading).toBe(false);
    });

    it('handles sync error in syncCredentialCache (non-protocol link)', () => {
      sessionStorage.removeItem(PENDING_DEEP_LINK_KEY);
      mockWalletService.syncCredentials.mockReturnValue(throwError(() => new Error('Async sync failed')));
      const consoleSpy = jest.spyOn(console, 'error').mockImplementation();
      const cacheSpy = jest.spyOn(mockCredentialCache, 'setError');

      component['syncCredentialCache']();

      expect(consoleSpy).toHaveBeenCalledWith('Sync failed', expect.any(Error));
      expect(cacheSpy).toHaveBeenCalled();
    });

    it('PWA installation: promptInstall and skipInstall', async () => {
      const pwaInstallService = TestBed.inject(PwaInstallService);
      const promptSpy = jest.spyOn(pwaInstallService, 'promptInstall').mockResolvedValue(true);
      component.showInstallScreen = true;

      await component.installApp();
      expect(promptSpy).toHaveBeenCalled();
      expect(component.showInstallScreen).toBe(false);

      component.showInstallScreen = true;
      component.skipInstall();
      expect(component.showInstallScreen).toBe(false);
    });

    it('Browser mode: login and passkey creation', async () => {
      // Re-configure for browser mode
      Object.defineProperty(component, 'isBrowserMode', { value: true });
      jest.spyOn(component as any, 'authenticateLocally').mockResolvedValue(undefined);

      const markSpy = jest.fn();
      (mockAuthService as any).markAuthenticated = markSpy;

      const setupSpy = jest.fn().mockResolvedValue(undefined);
      (mockAuthService as any).setupPasskey = setupSpy;

      const navigateSpy = jest.spyOn(mockRouter, 'navigateByUrl');

      // Local login
      await component.loginBrowserMode();
      expect(markSpy).toHaveBeenCalled();
      expect(navigateSpy).toHaveBeenCalledWith('/tabs/home');

      // Local setup
      await component.createWalletBrowserMode();
      expect(setupSpy).toHaveBeenCalled();
      expect(navigateSpy).toHaveBeenCalledTimes(2);
    });

    it('Browser mode: handles failures in login and setup', async () => {
      Object.defineProperty(component, 'isBrowserMode', { value: true });

      // Test default error message for setup
      (mockAuthService as any).setupPasskey = jest.fn().mockRejectedValue({});
      await component.createWalletBrowserMode();
      expect(component.errorMessage).toBe('Failed to create passkey');

      // authenticateLocally fail
      jest.spyOn(component as any, 'authenticateLocally').mockRejectedValue(new Error('Local fail'));
      await component.loginBrowserMode();
      expect(component.errorMessage).toBe('Local fail');

      // Test default error message for login
      jest.spyOn(component as any, 'authenticateLocally').mockRejectedValue({});
      await component.loginBrowserMode();
      expect(component.errorMessage).toBe('Login failed');
    });

    it('OTP flow: onOtpCompleted and goBackToEmail', () => {
      const verifySpy = jest.spyOn(component, 'verifyCode').mockImplementation();
      component.onOtpCompleted('123456');
      expect((component as any).otpValue).toBe('123456');
      expect(verifySpy).toHaveBeenCalled();

      component.step = 'code';
      component.goBackToEmail();
      expect(component.step).toBe('email');
      expect((component as any).otpValue).toBe('');
    });

    it('verifyPasskey: handles error when NOT using refresh token path', async () => {
      component.step = 'passkey';
      (component as any).passkeyFromRefreshToken = false;
      jest.spyOn(component as any, 'authenticateLocally').mockResolvedValue(undefined);
      mockRouter.navigateByUrl.mockImplementation(() => { throw new Error('Sync failed'); });

      await component.verifyPasskey();

      expect(component.errorMessage).toBe('Sync failed');
      expect(component.step).toBe('passkey');
    });

    it('verifyPasskey: uses default error message if error has no message', async () => {
      component.step = 'passkey';
      (component as any).passkeyFromRefreshToken = false;
      jest.spyOn(component as any, 'authenticateLocally').mockResolvedValue(undefined);
      mockRouter.navigateByUrl.mockImplementation(() => { throw {}; });

      await component.verifyPasskey();

      expect(component.errorMessage).toBe('Passkey verification failed');
      expect(component.step).toBe('passkey');
    });

    it('getDeviceName: covers all OS branches', () => {
      const setUA = (ua: string) => {
        Object.defineProperty(navigator, 'userAgent', { value: ua, configurable: true });
      };
      const originalUA = navigator.userAgent;

      setUA('iPad'); expect(component['getDeviceName']()).toBe('iPad');
      setUA('Macintosh'); expect(component['getDeviceName']()).toBe('Mac');
      setUA('Windows'); expect(component['getDeviceName']()).toBe('Windows PC');
      setUA('Linux'); expect(component['getDeviceName']()).toBe('Linux');
      setUA('Other'); expect(component['getDeviceName']()).toBe('Unknown Device');

      setUA(originalUA);
    });

    it('sendCode: navigates to code step on success', () => {
      component.email = 'test@example.com';
      mockAuthService.register.mockReturnValue(of({ message: 'OK' }));

      component.sendCode();

      expect(component.step).toBe('code');
      expect(component.loading).toBe(false);
    });
  });

  describe('verification-code resend cooldown', () => {
    beforeEach(() => {
      jest.useFakeTimers();
      component.email = 'user@example.com';
    });

    afterEach(() => {
      component.ngOnDestroy();
      jest.useRealTimers();
    });

    it('starts a 3-minute cooldown once the code has been sent', () => {
      component.sendCode();

      expect(component.step()).toBe('code');
      expect(component.resendSecondsLeft()).toBe(180);
      expect(component.resendCountdown()).toBe('03:00');
    });

    it('counts down and formats the remaining time as mm:ss', () => {
      component.sendCode();

      jest.advanceTimersByTime(61_000);

      expect(component.resendSecondsLeft()).toBe(119);
      expect(component.resendCountdown()).toBe('01:59');
    });

    it('ignores a resend request while the cooldown is still running', () => {
      component.sendCode();
      expect(mockAuthService.register).toHaveBeenCalledTimes(1);

      component.resendCode();

      expect(mockAuthService.register).toHaveBeenCalledTimes(1);
    });

    it('requests a new code and restarts the cooldown once it has elapsed', () => {
      component.sendCode();
      jest.advanceTimersByTime(180_000);
      expect(component.resendSecondsLeft()).toBe(0);

      component.otpValue = '123456';
      component.resendCode();

      expect(mockAuthService.register).toHaveBeenCalledTimes(2);
      expect(component.resendSecondsLeft()).toBe(180);
      // the stale code the user may have typed is cleared
      expect(component.otpValue).toBe('');
    });

    it('does not leave the cooldown running after leaving the code step', () => {
      component.sendCode();

      component.goBackToEmail();

      expect(component.resendSecondsLeft()).toBe(0);
      jest.advanceTimersByTime(5_000);
      expect(component.resendSecondsLeft()).toBe(0);
    });

    it('stops the cooldown once the code has been verified', () => {
      component.sendCode();
      component.otpValue = '123456';

      component.verifyCode();

      expect(component.step()).toBe('passkey');
      expect(component.resendSecondsLeft()).toBe(0);
    });
  });

  describe('screen-driven presentation state', () => {
    it('picks the watermark that matches the current step', () => {
      component.step.set('email');
      expect(component.watermark()).toBe('email');

      component.step.set('code');
      expect(component.watermark()).toBe('verify');

      component.step.set('passkey');
      expect(component.watermark()).toBe('passkey');
    });

    it('shows the access screen and its watermark when the app is installable', async () => {
      await rebuildWithInstallDecision(true);

      expect(component.showInstallScreen()).toBe(true);
      expect(component.screen()).toBe('access');
      expect(component.watermark()).toBe('access');
    });

    it('does not fall back to the access watermark when the app is not installable', () => {
      expect(component.showInstallScreen()).toBe(true);

      expect(component.screen()).toBe('email');
      expect(component.watermark()).toBe('email');
    });

    it('renders nothing decorative until the installability probe settles', async () => {
      TestBed.resetTestingModule();
      await TestBed.configureTestingModule({
        imports: [LoginPage, TranslateModule.forRoot()],
        providers: baseProviders.map(provider => provider.provide === PwaInstallService
          ? {
              provide: PwaInstallService,
              // never emits — mirrors the probe still running
              useValue: { installDecision$: NEVER, isStandalone: false, promptInstall: jest.fn() },
            }
          : provider),
      }).compileComponents();
      fixture = TestBed.createComponent(LoginPage);
      component = fixture.componentInstance;

      expect(component.screen()).toBe('checking');
      expect(component.watermark()).toBeNull();
      expect(component.canGoBack()).toBe(false);

      // Without a mask the element would paint its background-color in full.
      fixture.detectChanges();
      const watermark = fixture.nativeElement.querySelector('.auth-watermark') as HTMLElement;
      expect(watermark.style.display).toBe('none');
    });

    it('masks the watermark with the artwork of the current screen', () => {
      fixture.detectChanges();
      const watermark = fixture.nativeElement.querySelector('.auth-watermark') as HTMLElement;

      expect(watermark.getAttribute('data-shape')).toBe('email');
      expect(watermark.style.getPropertyValue('mask-image')).toContain('user-solid.svg');
      expect(watermark.style.getPropertyValue('mask-size')).toBe('contain');

      component.step.set('code');
      fixture.detectChanges();

      expect(watermark.style.getPropertyValue('mask-image')).toContain('envelope-circle-check-solid.svg');
      expect(watermark.style.display).toBe('');
    });

    it('falls back to a generic brand name when the tenant theme is unavailable', () => {
      expect(component.brandName()).toBe('Wallet');
    });

    it('offers a back affordance only on the OTP and passkey steps', () => {
      component.step.set('email');
      expect(component.canGoBack()).toBe(false);

      component.step.set('code');
      expect(component.canGoBack()).toBe(true);

      component.step.set('passkey');
      expect(component.canGoBack()).toBe(true);
    });
  });
});
