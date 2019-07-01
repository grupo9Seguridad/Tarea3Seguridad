package com.seguridad.modelo;

import java.io.*;
import java.security.*;
import javax.enterprise.context.Dependent;
import javax.inject.Named;


@Named(value = "GeneradorFirmas")
@Dependent
public class GeneradorFirmas {
    
    private Signature firma;
    
    /*
    Crea un objeto Signature y lo iniciaiza con la clave privada 
    Usando Algoritmo SHA-256 y RSA
    */
    public GeneradorFirmas(PrivateKey privateKey) throws Exception {
       Signature rsa_firma = Signature.getInstance("SHA256withRSA"); 
       rsa_firma.initSign(privateKey);
       this.firma = rsa_firma;
    }
    
    /*
    Metodo que genera la firma del archivo
    */
    public byte[] firmaDoc (String nombreDoc) throws Exception {
            
        FileInputStream fis = new FileInputStream(nombreDoc);
        BufferedInputStream bufin = new BufferedInputStream(fis);
        byte[] buffer = new byte[1024];
        int len;
        while (bufin.available() != 0) {
           len = bufin.read(buffer);
           this.firma.update(buffer, 0, len);
         };
        bufin.close();
        byte[] docFirmado = this.firma.sign();
     
        return docFirmado;     
    }
    
    /*
    Convierte la firma de array de bytes a archivo
    */
    public void copiaFirmaArchivo(byte[] firma, String ruta) throws Exception {
       
        FileOutputStream firmafos = new FileOutputStream(ruta);
        firmafos.write(firma);
        firmafos.close();
        
    }
    
}
   
                    

