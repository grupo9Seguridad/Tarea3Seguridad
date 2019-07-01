package com.seguridad.modelo;


import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import javax.enterprise.context.Dependent;
import javax.inject.Named;


@Named(value = "verificadorFirmas")
@Dependent
public class VerificadorFirmas {

private byte[] doc;
private byte[] firmaOrig;
private byte[] clavePubFirma;




public VerificadorFirmas(byte[] doc, byte[] firmaOrig, byte[] clavePubFirma) {
    this.doc = doc;
    this.firmaOrig = firmaOrig;
    this.clavePubFirma = clavePubFirma;
}

  
/*
Metodo que verifica la firma del archivo utilizando SHA-256 y RSA
*/
public boolean verificaFirma () throws Exception {
   
    X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(this.clavePubFirma);

    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
    PublicKey clavePublica = keyFactory.generatePublic(pubKeySpec);

    Signature sig = Signature.getInstance("SHA256withRSA"); 
    sig.initVerify(clavePublica);
    sig.update(this.doc);
    return sig.verify(this.firmaOrig);
            
}


}