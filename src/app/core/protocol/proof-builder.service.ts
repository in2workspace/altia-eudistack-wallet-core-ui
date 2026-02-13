import { Injectable } from '@angular/core';
import { JWT_PROOF_CLAIM } from 'src/app/constants/jwt-proof.constants';
import { JwtProofHeaderAndPayload } from '../models/JwtProof';



@Injectable({
  providedIn: 'root'
})
export class ProofBuilderService {
  //todo consider changing name to buildJwtProofPayload
  public buildHeaderAndPayload(nonce: string, issuer: string, publicKeyJwk: JsonWebKey): JwtProofHeaderAndPayload {
    const nowSeconds = Math.floor(Date.now() / 1000);
    const expSeconds = nowSeconds + 10 * 24 * 60 * 60;

    return {
      header: { alg: 'ES256', typ: JWT_PROOF_CLAIM, jwk: publicKeyJwk },
      payload: { aud: [issuer], iat: nowSeconds, exp: expSeconds, nonce },
    };
  }
  
}
