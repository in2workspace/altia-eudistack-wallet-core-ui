import { inject, Injectable } from '@angular/core';
import { VCReply } from 'src/app/interfaces/verifiable-credential-reply';
import { VerifiablePresentation } from './models/VerifiablePresentation';
import { HttpClient } from '@angular/common/http';
import { environment } from 'src/environments/environment';
import { WebCryptoKeyStorageProvider } from '../../spi-impl/web-crypto-key-storage.service';

@Injectable({
  providedIn: 'root'
})
export class Oid4vpiEngineService {

  private readonly http = inject(HttpClient);
  private readonly keyStorageProvider = inject(WebCryptoKeyStorageProvider);

  //todo move here the logic to get the credentials to select (from vc selector page)

  public buildVerifiablePresentationWithSelectedVCs(token: string, selectorResponse: VCReply){
    const aud = this.generateAudience();
    const credential = this.getVerifiableCredential(selectorResponse.selectedVcList);
    //todo
    //create unsigned payload
    //extract cnf from credential, compute thumbprint and lookup key in keystore
    //sign the VP with the key referenced in the cnf
    //build request with the VP
    //send VP request
    
  }

  private getVerifiableCredential(selectedVcList: any[]): any{
    return this.http.get<any>(environment.server_url + "path-per-determinar");
  }
  //todo review this
  private generateAudience(){
    return "https://self-issued.me/v2";
  }

  private createSignedVerifiablePresentation(token: string, selectedVcList: any[], audience: string): VerifiablePresentation{

  }
}
