import { Injectable } from '@angular/core';

export interface JwtHeaderAndPayload {
  header: JwtHeader;
  payload: JwtPayload;
}

export interface JwtPayload {
  iss: string;
  aud: string[];
  iat: number;
  exp: number;
  nonce: string;
}

export interface JwtHeader {
  alg: 'ES256';
  typ: 'proof';
  jwk: JsonWebKey;
}



@Injectable({
  providedIn: 'root'
})
export class ProofBuilderService {
  //todo consider changing name to buildJwtProofPayload
  public buildHeaderAndPayload(nonce: string, issuer: string, iss: string, publicKeyJwk: JsonWebKey): JwtHeaderAndPayload {
    const nowSeconds = Math.floor(Date.now() / 1000);
    const expSeconds = nowSeconds + 10 * 24 * 60 * 60;

    return {
      header: { alg: 'ES256', typ: 'proof', jwk: publicKeyJwk },
      payload: { iss, aud: [issuer], iat: nowSeconds, exp: expSeconds, nonce },
    };
  }
  
}
