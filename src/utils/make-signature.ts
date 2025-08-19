import * as forge from 'node-forge';
import * as fs from 'fs';

class MakeSignature {
  private data: string;
  private key: string;
  private passKey: string;

  constructor(data: string, priKeyPath: string, priKeyPass: string) {
    this.data = data;
    this.key = priKeyPath;
    this.passKey = priKeyPass;
  }

  public getSignature(): string {
    const key = this.getKey();
    return MakeSignature.sign(this.data, key);
  }

  public static sign(
    content: string,
    privateKey: forge.pki.rsa.PrivateKey,
  ): string {
    // Create a SHA-1 digest
    const md = forge.md.sha1.create();
    md.update(content, 'utf8');

    // Sign the digest with the private key
    const signature = privateKey.sign(md);

    // Convert the signature to Base64
    return forge.util.encode64(signature);
  }

  private getKey(): forge.pki.rsa.PrivateKey {
    // Read the certificate file (PFX/PKCS#12 format)
    const pfxData = fs.readFileSync(
      'D:\\Bach\\7A_Digital_Signature_Middleware_Service_v2\\dist\\configs\\ssl\\MPKI_BVQY7A_QK7.p12',
    );

    // Parse the PFX file with the provided password
    const pfx = forge.pkcs12.pkcs12FromAsn1(
      forge.asn1.fromDer(pfxData.toString('binary')),
      false, // strict parsing
      this.passKey,
    );

    // Extract the private key from the PFX
    const bags = pfx.getBags({ bagType: forge.pki.oids.pkcs8ShroudedKeyBag });
    const keyBag = bags[forge.pki.oids.pkcs8ShroudedKeyBag]?.[0];
    if (!keyBag || !keyBag.key) {
      throw new Error('Private key not found in certificate');
    }

    console.log('keyBag.key', keyBag.key);

    return keyBag.key as forge.pki.rsa.PrivateKey;
  }
}

export default MakeSignature;
