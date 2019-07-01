/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.seguridad.controlador;

import com.seguridad.modelo.GeneradorFirmas;
import com.seguridad.modelo.Usuario;
import com.seguridad.modelo.VerificadorFirmas;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.Serializable;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import javax.faces.application.FacesMessage;
import javax.faces.context.FacesContext;
import javax.inject.Named;
import javax.faces.view.ViewScoped;

/**
 *
 * @author Alejandro
 */
@Named(value = "controlDeFirma")
@ViewScoped
public class controlDeFirma implements Serializable{

    
    private GeneradorFirmas genFirmas;
    private VerificadorFirmas firmVerif;
    private String nombreUsuario;
    
    private String rutaArchivoFirmar;
    private String direccionKeyPrivadas = "C:\\Users\\Alejandro\\Documents\\NetBeansProjects\\PruebaWeb5\\web\\resources\\ClavesPrivadas\\";
    private String direccionKeyPublicas = "C:\\Users\\Alejandro\\Documents\\NetBeansProjects\\PruebaWeb5\\web\\resources\\ClavesPublicas\\";
    private String direccionFirmas = "C:\\Users\\Alejandro\\Documents\\NetBeansProjects\\PruebaWeb5\\web\\resources\\ArchivosFirma\\";
    private String archivoFirma;
    /**
     * Creates a new instance of controlDeFirma
     */
    public controlDeFirma() throws NoSuchAlgorithmException, InvalidKeySpecException, Exception {
        
        
    }
    

    public String getDireccionFirmas() {
        return direccionFirmas;
    }

    public void setDireccionFirmas(String direccionFirmas) {
        this.direccionFirmas = direccionFirmas;
    }

    public String getArchivoFirma() {
        return archivoFirma;
    }

    public void setArchivoFirma(String archivoFirma) {
        this.archivoFirma = archivoFirma;
    }
    
   
    // Metodo que se llama del la interfaz web para firmar una archivo
    public void firmarArchivo() throws Exception{
        try{
           //paso archivo de private Key a byte[] buscandolo con nombre de usurio
            byte[] bytePrivada = fileToBytes(direccionKeyPrivadas+nombreUsuario+".prv");
            KeyFactory kf = KeyFactory.getInstance("RSA");
            PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(bytePrivada);
            // genero mi clave privada de tipo privateKey a partir del archivo
            PrivateKey privatekey = kf.generatePrivate(privateKeySpec);
            // Inicializar objecto generadorFirmas
            genFirmas = new GeneradorFirmas(privatekey);

            // Creo byte[] del archivo a firmar
            byte[] byteFirma = genFirmas.firmaDoc(this.rutaArchivoFirmar);
            // Crea otro archivo firma desde el byte[] generado
            genFirmas.copiaFirmaArchivo(byteFirma, this.direccionFirmas+archivoFirma+".frm");

            //Mostramos mensaje de que el archivo encriptado fue guradado correctamente
            FacesMessage mensaje = new FacesMessage("Archivo firma generado !");
            FacesContext contexto = FacesContext.getCurrentInstance();
            contexto.addMessage(null,mensaje); 
        }
        catch(Exception e){
            //Mostramos mensaje de que el archivo encriptado fue guradado correctamente
            FacesMessage mensaje = new FacesMessage("Error al generar firma");
            FacesContext contexto = FacesContext.getCurrentInstance();
            contexto.addMessage(null,mensaje); 
        }
        
        
        
    }
    
    // Metodo que se llama de la interfaz wep para verificar la firma de un archivo
    public void verificarArchivo() throws Exception {
        
        try{
            
            // creo un Byte[] del archivo clave publica del usuario
            byte[] bytePublica = fileToBytes(direccionKeyPublicas+nombreUsuario+".pub");
            // creo un Byte[] del archivo clave publica del usuario
            byte[] byteArchivoAVerificar = fileToBytes(this.rutaArchivoFirmar);
            // creo un byte[] del archivo firma con el cual voy a verificar el archivo original
            byte[] byteArchivoFirma = fileToBytes(direccionFirmas+archivoFirma+".frm");

            // creo una instancia de VerificadorFirmas
            firmVerif = new VerificadorFirmas(byteArchivoAVerificar,byteArchivoFirma,bytePublica);
            // el metodo verificarFirma() me devuelve true si el se valido la verificacion
            boolean verificado = firmVerif.verificaFirma();
         
            if(verificado == true){
                FacesMessage mensaje = new FacesMessage("Documento válido");
                FacesContext contexto = FacesContext.getCurrentInstance();
                contexto.addMessage(null,mensaje);
                }
                else{
                FacesMessage mensaje = new FacesMessage("Documento inválido");
                FacesContext contexto = FacesContext.getCurrentInstance();
                contexto.addMessage(null,mensaje);
            }
      
        }
        catch(SignatureException e){
            FacesMessage mensaje = new FacesMessage("Error: Firma Invalida o corrupta");
            FacesContext contexto = FacesContext.getCurrentInstance();
            contexto.addMessage(null,mensaje);
        }
        catch(Exception e){
            FacesMessage mensaje = new FacesMessage("Error al verificar el archivo");
            FacesContext contexto = FacesContext.getCurrentInstance();
            contexto.addMessage(null,mensaje);
            
        }
        
        
        
        
        
        
        
    }

    public String getRutaArchivoFirmar() {
        return rutaArchivoFirmar;
    }

    public void setRutaArchivoFirmar(String rutaArchivoFirmar) {
        this.rutaArchivoFirmar = rutaArchivoFirmar;
    }

    public String getNombreUsuario() {
        return nombreUsuario;
    }

    public void setNombreUsuario(String nombreUsuario) {
        this.nombreUsuario = nombreUsuario;
    }

    public String getDireccionKeyPrivadas() {
        return direccionKeyPrivadas;
    }

    public void setDireccionKeyPrivadas(String direccionKeyPrivadas) {
        this.direccionKeyPrivadas = direccionKeyPrivadas;
    }

    
    
    public GeneradorFirmas getGenFirmas() {
        return genFirmas;
    }

    public void setGenFirmas(GeneradorFirmas genFirmas) {
        this.genFirmas = genFirmas;
    }
    
    
    // Convierte un archivo a un array de bytes
    public static byte[] fileToBytes (String archivo) {
       try{
           File file = new File(archivo);
           //init array with file length
            byte[] bytesArray = new byte[(int) file.length()]; 

            FileInputStream fis = new FileInputStream(file);
            fis.read(bytesArray); //read file into bytes[]
            fis.close();
        
            return bytesArray;

            }
            catch(IOException e ){
            
            return null;
            
        }
    }
}
