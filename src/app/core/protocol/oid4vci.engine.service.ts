import { CredentialResponseWithStatus, CredentialService } from './credential.service';
import { inject, Injectable } from '@angular/core';
import { CredentialOfferService } from './credential-offer.service';
import { CredentialIssuerMetadataService } from './credential-issuer-metadata.service';
import { AuthorisationServerMetadataService } from './authorisation-server-metadata.service';
import { AuthenticationService } from 'src/app/services/authentication.service';
import { PreAuthorizedTokenService } from './pre-authorized-token.service';
import { CredentialIssuerMetadata, CredentialsConfigurationsSuppported } from '../models/CredentialIssuerMetadata';
import { CredentialOffer } from '../models/CredentialOffer';
import { ProofBuilderService } from './proof-builder.service';
import { WebCryptoKeyStorageProvider } from '../spi-impl/web-crypto-key-storage.service';
import { TokenResponse } from '../models/TokenResponse';
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { environment } from 'src/environments/environment';
import { SERVER_PATH } from 'src/app/constants/api.constants';
import { options } from 'src/app/services/wallet.service';

interface CredentialConfigurationContext {
  credentialConfigurationId: string;
  configuration: CredentialsConfigurationsSuppported;
  format: string;
  isCryptographicBindingSupported: boolean;
}

@Injectable({ providedIn: 'root' })
export class Oid4vciEngineService {
  private readonly authorisationServerMetadataService = inject(AuthorisationServerMetadataService);
  private readonly authService = inject(AuthenticationService);
  private readonly credentialIssuerMetadataService = inject(CredentialIssuerMetadataService);
  private readonly credentialOfferService = inject(CredentialOfferService);
  private readonly credentialService = inject(CredentialService);
  private readonly http = inject(HttpClient);
  private readonly keyStorageProvider = inject(WebCryptoKeyStorageProvider);
  private readonly preAuthorizedTokenService = inject(PreAuthorizedTokenService);
  private readonly proofBuilderService = inject(ProofBuilderService);

  public async executeOid4vciFlow(credentialOfferUri: string): Promise<void> {
    const token = this.authService.getToken();
    console.log("Token:", token);
    
    const credentialOffer = await this.credentialOfferService.getCredentialOfferFromCredentialOfferUri(credentialOfferUri);
    console.log("Credential Offer:", credentialOffer);
    
    const credentialIssuerMetadata = await this.credentialIssuerMetadataService.getCredentialIssuerMetadataFromCredentialOffer(credentialOffer);
    console.log("Credential Issuer Metadata:", credentialIssuerMetadata);
    
    const authorisationServerMetadata = await this.authorisationServerMetadataService.getAuthorizationServerMetadataFromCredentialIssuerMetadata(credentialIssuerMetadata);
    console.log("Authorisation Server Metadata:", authorisationServerMetadata);
    
    const tokenResponse: TokenResponse = await this.preAuthorizedTokenService.getPreAuthorizedToken(credentialOffer, authorisationServerMetadata);
    console.log("tokenResponse:", tokenResponse);
    
    const cfg = this.resolveCredentialConfigurationContext(credentialOffer, credentialIssuerMetadata);
    console.log("Credential Configuration Context:", cfg);

    const nonce = this.getNonce();
    const tokenObtainedAt = new Date();

    let jwtProof = null;
    if (cfg.isCryptographicBindingSupported && credentialIssuerMetadata.credentialIssuer) {
      jwtProof = await this.buildProofJwt({
        nonce,
        credentialIssuer: credentialIssuerMetadata.credentialIssuer,
        iss: '', // TODO: wallet identifier (not did:key)
      });
    }
    console.log("JWT Proof:", jwtProof);

    // Reuse the resolved config. No repetition.
    const format = cfg.format;
    const credentialConfigurationId = cfg.credentialConfigurationId;
    const credentialResponse: CredentialResponseWithStatus = await this.credentialService.getCredential({
      jwtProof, 
      tokenResponse,
      credentialIssuerMetadata,
      format,
      credentialConfigurationId
    });
    console.log("Credential response: ", credentialResponse);

      //todo
      this.http.post<JSON>(
          environment.server_url + SERVER_PATH.REQUEST_CREDENTIAL,
          { qr_content: credentialResponse },
          options
        );
  }

  private resolveCredentialConfigurationContext(
    credentialOffer: CredentialOffer,
    credentialIssuerMetadata: CredentialIssuerMetadata
  ): CredentialConfigurationContext {
    const ids = credentialOffer.credentialConfigurationsIds;
    if (!ids || ids.length === 0) {
      throw new Error('Missing credentialConfigurationsIds in credential offer');
    }

    // todo handle multiple credential configurations
    const credentialConfigurationId = ids[0];

    const configs = credentialIssuerMetadata.credential_configurations_supported;
    if (!configs) {
      throw new Error('Missing credentialsConfigurationsSupported in CredentialIssuerMetadata');
    }

    const configuration = configs[credentialConfigurationId];
    if (!configuration) {
      throw new Error(`No configuration found for ID: ${credentialConfigurationId}`);
    }

    const format = configuration.format;
    if (!format) {
      throw new Error(`Missing format for credential configuration ID: ${credentialConfigurationId}`);
    }

    const methods = configuration.cryptographic_binding_methods_supported;
    const isCryptographicBindingSupported = !!(methods && methods.length > 0);

    return {
      credentialConfigurationId,
      configuration,
      format,
      isCryptographicBindingSupported,
    };
  }

  private async buildProofJwt(params: { nonce: string; credentialIssuer: string; iss: string }): Promise<string> {
    console.log("Building proof JWT with params:", params);
    const keyInfo = await this.keyStorageProvider.generateKeyPair('ES256', crypto.randomUUID());
    console.log("Generated key info:", keyInfo);

    const headerAndPayload = this.proofBuilderService.buildHeaderAndPayload(
      params.nonce,
      params.credentialIssuer,
      params.iss,
      keyInfo.publicKeyJwk
    );
    console.log("Header and Payload for JWT:", headerAndPayload);

    //todo potser tindria més sentit fer que retorni directament tipus compatible amb Uint8Array<ArrayBufferLike> per a sign()
    const signingInput = this.buildSigningInput(headerAndPayload);
    console.log("Signing input for JWT:", signingInput);

    const sig = await this.keyStorageProvider.sign(keyInfo.keyId, new TextEncoder().encode(signingInput));
    console.log("DER signature from key storage provider:", sig);
    const sigJose = this.ecdsaSigToJose(sig, 64);
    console.log("JOSE-formatted signature:", sigJose);

    return `${signingInput}.${this.base64UrlEncode(sigJose)}`;
  }

  private buildSigningInput(parts: { header: unknown; payload: unknown }): string {
    const enc = new TextEncoder();
    const headerB64 = this.base64UrlEncode(enc.encode(JSON.stringify(parts.header)));
    const payloadB64 = this.base64UrlEncode(enc.encode(JSON.stringify(parts.payload)));
    return `${headerB64}.${payloadB64}`;
  }

  private base64UrlEncode(bytes: Uint8Array): string {
    let binary = '';
    const chunkSize = 0x8000;

    for (let i = 0; i < bytes.length; i += chunkSize) {
      binary += String.fromCharCode(...bytes.subarray(i, i + chunkSize));
    }

    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
  }

  private ecdsaSigToJose(sig: Uint8Array, joseLen: number): Uint8Array {
  // If it's already raw (r||s), keep it.
  if (sig.length === joseLen) return sig;

  // If it looks like DER (ASN.1 SEQUENCE), convert it.
  if (sig.length >= 8 && sig[0] === 0x30) {
    return this.ecdsaDerToJose(sig, joseLen);
  }

  throw new Error(
    `Unexpected ECDSA signature format. len=${sig.length}, first=0x${sig[0].toString(16)}`
  );
}

  private ecdsaDerToJose(derSig: Uint8Array, joseLen: number): Uint8Array {
    if (derSig.length < 8 || derSig[0] !== 0x30) {
      throw new Error('Invalid DER signature');
    }

    let offset = 2;
    if (derSig[1] & 0x80) {
      const n = derSig[1] & 0x7f;
      offset = 2 + n;
    }

    if (derSig[offset] !== 0x02) throw new Error('Invalid DER signature (r)');
    const rLen = derSig[offset + 1];
    const r = derSig.slice(offset + 2, offset + 2 + rLen);
    offset = offset + 2 + rLen;

    if (derSig[offset] !== 0x02) throw new Error('Invalid DER signature (s)');
    const sLen = derSig[offset + 1];
    const s = derSig.slice(offset + 2, offset + 2 + sLen);

    const out = new Uint8Array(joseLen);
    const half = joseLen / 2;

    out.set(this.leftPad(this.stripLeadingZeros(r), half), 0);
    out.set(this.leftPad(this.stripLeadingZeros(s), half), half);

    return out;
  }

  private stripLeadingZeros(bytes: Uint8Array): Uint8Array {
    let i = 0;
    while (i < bytes.length - 1 && bytes[i] === 0x00) i++;
    return bytes.slice(i);
  }

  private leftPad(bytes: Uint8Array, size: number): Uint8Array {
    if (bytes.length > size) {
      return bytes.slice(bytes.length - size);
    }
    const out = new Uint8Array(size);
    out.set(bytes, size - bytes.length);
    return out;
  }

  // todo use nonce endpoint when it is supported
  private getNonce(): string {
    return '';
  }
}