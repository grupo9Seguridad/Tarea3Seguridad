/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.seguridad.controlador;

import com.seguridad.modelo.*;
import java.io.Serializable;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.util.Calendar;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.inject.Named;
import javax.faces.application.FacesMessage;
import javax.faces.context.FacesContext;
import javax.faces.view.ViewScoped;
import static javax.faces.application.FacesMessage.SEVERITY_ERROR;
import static javax.faces.application.FacesMessage.SEVERITY_INFO;

/**
 *
 * @author Alejandro
 */
@Named(value = "controlDeUsuario")
@ViewScoped
public class controlDeUsuario implements Serializable{
    
    //private ManejadorArchivosGenerico marchivo = new ManejadorArchivosGenerico();
    private Usuario usuario;
    
    private String rutaArchivo="C:\\Users\\Alejandro\\Documents\\NetBeansProjects\\PruebaWeb5\\web\\resources\\datos.txt";

    /**
     * Creates a new instance of controller
     */
    public controlDeUsuario() throws NoSuchAlgorithmException, NoSuchProviderException {
        usuario = new Usuario();
        
        
    }
    
    /*@PostConstruct
    public void init(){
        usuario = new Usuario();
    }*/

    public Usuario getUsuario() {
        return usuario;
    }

    public void setUsuario(Usuario usuario) {
        this.usuario = usuario;
    }
    
    // Metodo de registro de usuario que valida la fortaleza de la password
    public boolean registrarUsuario() throws NoSuchProviderException, Exception{
        
        if(existeUsuario(this.usuario.getUsuario())){
            FacesMessage mensaje = new FacesMessage("El usuario ya existe, ingrese un nuevo nombre");
            FacesContext contexto = FacesContext.getCurrentInstance();
            contexto.addMessage(null,mensaje);
        }else if(usuarioCorto(this.usuario.getUsuario())){
            FacesMessage mensaje = new FacesMessage("El nombre de usuario tiene que tener al menos 5 caracteres");
            FacesContext contexto = FacesContext.getCurrentInstance();
            contexto.addMessage(null,mensaje);
        }else if(claveCorta(this.usuario.getPassword())){
            FacesMessage mensaje = new FacesMessage("La password tiene que tener al menos 8 caracteres, ingrese una nueva password");
            FacesContext contexto = FacesContext.getCurrentInstance();
            contexto.addMessage(null,mensaje);
        }else if(!tieneMayusculas(this.usuario.getPassword())){
            FacesMessage mensaje = new FacesMessage("La password tiene que tener al menos 1 letra mayúscula");
            FacesContext contexto = FacesContext.getCurrentInstance();
            contexto.addMessage(null,mensaje);
        }else if(!tieneMinúsculas(this.usuario.getPassword())){
            FacesMessage mensaje = new FacesMessage("La password tiene que tener al menos 1 letra minúscula");
            FacesContext contexto = FacesContext.getCurrentInstance();
            contexto.addMessage(null,mensaje);
        }else if(!tieneSímbolos(this.usuario.getPassword())){
            FacesMessage mensaje = new FacesMessage("La password tiene que tener al menos 1 símbolo");
            FacesContext contexto = FacesContext.getCurrentInstance();
            contexto.addMessage(null,mensaje);
        }else{ 
            String[] datosAGuardar = new String[1];
            String fecha = fechaExpira(7);
            
            String sal =sal();
            String password=hashClave(this.usuario.getPassword()+sal);
            
            // Metodo que genera el par de claves publico privado de un usuario
            usuario.generarClavePublicaPrivada();
            
            datosAGuardar[0]=this.usuario.getNombre()+","+this.usuario.getApellido()+","+this.usuario.getUsuario()+","+password+","+sal+","+fecha+",usuario,false,false";
            
            if(ManejadorArchivosGenerico.escribirArchivo(rutaArchivo, datosAGuardar)){
                FacesMessage msg = new FacesMessage();
                FacesContext.getCurrentInstance().addMessage(null, new FacesMessage(SEVERITY_INFO, "El usuario se creo correctamente", null));
                return true;
            }

        }
            FacesMessage msg2 = new FacesMessage();
            FacesContext.getCurrentInstance().addMessage(null, new FacesMessage(SEVERITY_ERROR, "El usuario no se creo, intente nuevamente", null));
            return false;
    }
    
    
    // Metodo que verifica si el usuario existe y si la clave es correcta 
    public boolean autenticarUsuario() {
        if (existeUsuario(this.usuario.getUsuario())) {
            String sal = devolverSalDeUsuario(this.usuario.getUsuario());
            String password = hashClave(this.usuario.getPassword() + sal);
            if (comprobarClave(password)) {
                FacesMessage msg2 = new FacesMessage();
                FacesContext.getCurrentInstance().addMessage(null, new FacesMessage(SEVERITY_INFO, "Usuario autenticado", null));
                return true;
            } else {
                FacesMessage msg2 = new FacesMessage();
                FacesContext.getCurrentInstance().addMessage(null, new FacesMessage(SEVERITY_ERROR, "El usuario y/o la clave no son correctas", null));
            }

        } else {
            FacesMessage msg2 = new FacesMessage();
            FacesContext.getCurrentInstance().addMessage(null, new FacesMessage(SEVERITY_ERROR, "El usuario y/o la clave no son correctas", null));
        }
        return false;
    }
        
    private boolean existeUsuario(String usuario){
        
        String[] usuarios = ManejadorArchivosGenerico.leerArchivo(rutaArchivo);
        
        if(usuarios==null){
            return false;
        }
        
        String[] datos;
        for(String s: usuarios){
            datos=s.split(",");
            if(datos[2].equals(usuario)){
                return true;
            }
            
        }
        return  false;
    }
    
    private String devolverSalDeUsuario(String usuario){
        
        String[] usuarios = ManejadorArchivosGenerico.leerArchivo(rutaArchivo);
                
        String[] datos=null;
        for(String s: usuarios){
            datos=s.split(",");
        }
        return datos[4];
    }
    
    private String devolverPasswordDeUsuario(String usuario){
        
        String[] usuarios = ManejadorArchivosGenerico.leerArchivo(rutaArchivo);
                
        String[] datos=null;
        for(String s: usuarios){
            datos=s.split(",");
        }
        return datos[3];
    }
    
    private String fechaExpira(int meses){
        Calendar fecha = Calendar.getInstance();
        fecha.add(Calendar.MONTH, meses);
        
        String dia = Integer.toString(fecha.get(Calendar.DAY_OF_MONTH));
        String mes = Integer.toString(fecha.get(Calendar.MONTH)+1);
        String año = Integer.toString(fecha.get(Calendar.YEAR));
        
        return dia+"/"+mes+"/"+año;
    }
    
    private boolean comprobarClave(String clave){
        String passAlmacenada=devolverPasswordDeUsuario(this.usuario.getUsuario());
        if(passAlmacenada.equals(clave)){
            return true;
        }
        return false;
    }
    
    private boolean claveCorta(String clave){
        if(clave.length()<8){
            return true;
        }
        return false;
    }
    
    private boolean usuarioCorto(String usuario){
        if(usuario.length()<5){
            return true;
        }
        return false;
    }
    
    private boolean tieneMayusculas(String clave){
    
        for(int i = 0;i<clave.length();i++){
            if(clave.charAt(i)>=65 && clave.charAt(i)<=90){
                return true;
            }
        }
        return false;
    }
    private boolean tieneMinúsculas(String clave){
    
        for(int i = 0;i<clave.length();i++){
            if(clave.charAt(i)>=95 && clave.charAt(i)<=122){
                return true;
            }
        }
        return false;
    }
    
    private boolean tieneSímbolos(String clave){
    
        for(int i = 0;i<clave.length();i++){
            if((clave.charAt(i)>=32 && clave.charAt(i)<=47)||(clave.charAt(i)>=58 && clave.charAt(i)<=64)||(clave.charAt(i)>=91 && clave.charAt(i)<=96)||(clave.charAt(i)==126)){
                return true;
            }
        }
        return false;
    }
    
    private String hashClave(String clave){
        try {
            MessageDigest md=MessageDigest.getInstance("SHA-256");
            byte[] hashEnBytes = md.digest(clave.getBytes(StandardCharsets.UTF_8));
            return bytesAHexadecimal(hashEnBytes);
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(controlDeUsuario.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }
    
    private String bytesAHexadecimal(byte[] hashEnBytes){
        StringBuilder sb = new StringBuilder();
        for (byte b : hashEnBytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
    
    private String sal(){
        byte[] sal = new byte[32];
                
        try {
            
            SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
            sr.nextBytes(sal);
    
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(controlDeUsuario.class.getName()).log(Level.SEVERE, null, ex);
        }
        return bytesAHexadecimal(sal);
    }
}
