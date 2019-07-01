package com.seguridad.modelo;

import java.io.*;
import java.security.*;

public class GeneradorClaves {
    
   private PrivateKey privateKey;
   private PublicKey publicKey;
   
   // Genera el par de claves publica/privada usando el algoritmo RSA
   public GeneradorClaves(int largo) throws NoSuchAlgorithmException, NoSuchProviderException {
      
     
      KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
      SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
      keyGen.initialize(largo, random);
      KeyPair pair = keyGen.generateKeyPair();
      this.privateKey = pair.getPrivate();
      this.publicKey = pair.getPublic(); 
   }
   
   public PrivateKey getPrivateKey() {
      return this.privateKey;
   }

   public PublicKey getPublicKey() {
      return this.publicKey;
   }
   
   /*
        Genera un archivo con la clave publica
    */
   public void copiarPubKArchivo(PublicKey pubKey, String path) throws Exception {
       
        byte[] clave = pubKey.getEncoded();
        FileOutputStream clavefos = new FileOutputStream(path);
        clavefos.write(clave);
        clavefos.close(); 
      }
   
   /*
        Genera un archivo con la clave privada
    */
   public void copiarPrivKArchivo(PrivateKey privKey, String path) throws Exception {
       
        byte[] clave = privKey.getEncoded();
        FileOutputStream clavefos = new FileOutputStream(path);
        clavefos.write(clave);
        clavefos.close(); 
      }
   
 }
   
