/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.seguridad.controlador;

import com.seguridad.modelo.EncriptDecriptFiles;
import java.io.Serializable;
import javax.inject.Named;
import javax.enterprise.context.Dependent;
import javax.faces.application.FacesMessage;
import javax.faces.context.FacesContext;
import javax.faces.view.ViewScoped;

/**
 *
 * @author Alejandro
 */
@Named(value = "controlDeEncriptacion")
@ViewScoped
public class controlDeEncriptacion implements Serializable{

    /**
     * Crea instancias de objetos necesarias para controlDeEncriptacion
     */
    private EncriptDecriptFiles encriptDecriptObject;
    private String rutaArchivoDestino ="C:\\Users\\Alejandro\\Documents\\NetBeansProjects\\PruebaWeb5\\web\\resources\\ArchivosEncriptados\\";
    
    
    
    public controlDeEncriptacion(){
        
       encriptDecriptObject = new EncriptDecriptFiles();
        
    }

    public EncriptDecriptFiles getEncriptDecriptObject() {
        return encriptDecriptObject;
    }

    public void setEncriptDecriptObject(EncriptDecriptFiles encriptDecriptObject) {
        this.encriptDecriptObject = encriptDecriptObject;
    }
        
    // Metodo que es llamado de la interfaz web para encriptar un archivo
    public void encriptar() throws Exception{
       
        try{
            encriptDecriptObject.encriptarArchivo(this.encriptDecriptObject.getRutaOrigen(), this.encriptDecriptObject.getPassword(), rutaArchivoDestino+this.encriptDecriptObject.getNombreArchivoDestino());
    
            //Mensaje de que se genero un archivo encriptado con exito
            FacesMessage mensaje = new FacesMessage("Archivo cifrado generado !");
            FacesContext contexto = FacesContext.getCurrentInstance();
            contexto.addMessage(null,mensaje);
        }
        catch(Exception e){
            
            //Mensaje de que no se pudo generar un archivo encriptado
            FacesMessage mensaje = new FacesMessage("Error al cifrar archivo !");
            FacesContext contexto = FacesContext.getCurrentInstance();
            contexto.addMessage(null,mensaje);
        }
        
        
        
        
    }
    
    // Metodo que es llamado de la interfaz web para desencriptar un archivo
    public void desencriptar() throws Exception{
        
        try{
            encriptDecriptObject.desencriptarArchivo(this.encriptDecriptObject.getRutaOrigen(), this.encriptDecriptObject.getPassword(), rutaArchivoDestino+this.encriptDecriptObject.getNombreArchivoDestino());

            //Mensaje de que se genero un archivo encriptado con exito
            FacesMessage mensaje = new FacesMessage("Archivo descifrado generado !");
            FacesContext contexto = FacesContext.getCurrentInstance();
            contexto.addMessage(null,mensaje);
        }
        catch(Exception e){
            
            //Mensaje de que fallo al intentar desencriptar el archivo
            FacesMessage mensaje = new FacesMessage(" Error al descifrar archivo");
            FacesContext contexto = FacesContext.getCurrentInstance();
            contexto.addMessage(null,mensaje);
        }
        
        
    
    
    }
     
    
        
    }
    

