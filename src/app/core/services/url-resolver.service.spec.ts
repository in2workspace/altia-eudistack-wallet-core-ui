import { TestBed } from '@angular/core/testing';
import { UrlResolverService } from './url-resolver.service';
import { environment } from 'src/environments/environment';

describe('UrlResolverService', () => {
  let service: UrlResolverService;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [UrlResolverService]
    });
    service = TestBed.inject(UrlResolverService);
  });

  it('should be created', () => {
    expect(service).toBeTruthy();
  });

  describe('serverUrl', () => {
    it('should return server_url from environment if present', () => {
      const original = environment.server_url;
      (environment as any).server_url = 'https://api.test.com';
      expect(service.serverUrl()).toBe('https://api.test.com');
      (environment as any).server_url = original;
    });

    it('should fallback to window.location.origin if environment.server_url is missing', () => {
      const originalEnv = environment.server_url;
      (environment as any).server_url = undefined;

      const originalLocation = window.location;
      delete (window as any).location;
      (window as any).location = { origin: 'http://localhost:4200' };

      expect(service.serverUrl()).toBe('http://localhost:4200/business-wallet');

      (window as any).location = originalLocation;
      (environment as any).server_url = originalEnv;
    });
  });

  describe('websocketUrl', () => {
    it('should return websocket_url from environment if present', () => {
      const original = environment.websocket_url;
      (environment as any).websocket_url = 'wss://ws.test.com';
      expect(service.websocketUrl()).toBe('wss://ws.test.com');
      (environment as any).websocket_url = original;
    });

    it('should fallback to window.location.origin with ws protocol if environment.websocket_url is missing', () => {
      const originalEnv = environment.websocket_url;
      (environment as any).websocket_url = undefined;

      const originalLocation = window.location;
      delete (window as any).location;
      (window as any).location = { origin: 'http://localhost:4200' };

      expect(service.websocketUrl()).toBe('ws://localhost:4200/business-wallet');

      (window as any).location = originalLocation;
      (environment as any).websocket_url = originalEnv;
    });

    it('should handle https to wss conversion for fallback', () => {
        (environment as any).websocket_url = undefined;
        const originalLocation = window.location;
        delete (window as any).location;
        (window as any).location = { origin: 'https://wallet.example-domain.com' };

        expect(service.websocketUrl()).toBe('wss://wallet.example-domain.com/business-wallet');

        (window as any).location = originalLocation;
      });
  });
});
