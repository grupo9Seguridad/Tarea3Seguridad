/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.seguridad.modelo;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import javax.inject.Named;
import javax.enterprise.context.Dependent;

/**
 *
 * @author Alejandro
 */
@Named(value = "usuario")
@Dependent
public class Usuario {
    
    private String nombre;
    private String apellido;
    private String usuario;
    private String password;
    private String sal;
    private String fechaExpira;
    private String tipoUsuario;
    private String expirado;
    private String bloqueado;
      

    /**
     * Crea una instancia de Usuario
     */
    public Usuario() throws NoSuchAlgorithmException, NoSuchProviderException {
        
    }

    public String getNombre() {
        return nombre;
    }

    public void setNombre(String nombre) {
        this.nombre = nombre;
    }

    public String getApellido() {
        return apellido;
    }

    public void setApellido(String apellido) {
        this.apellido = apellido;
    }

    public String getUsuario() {
        return usuario;
    }

    public void setUsuario(String usuario) {
        this.usuario = usuario;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getSal() {
        return sal;
    }

    public void setSal(String sal) {
        this.sal = sal;
    }

    public String getFechaExpira() {
        return fechaExpira;
    }

    public void setFechaExpira(String fechaExpira) {
        this.fechaExpira = fechaExpira;
    }

    public String getTipoUsuario() {
        return tipoUsuario;
    }

    public void setTipoUsuario(String tipoUsuario) {
        this.tipoUsuario = tipoUsuario;
    }

    public String isExpirado() {
        return expirado;
    }

    public void setExpirado(String expirado) {
        this.expirado = expirado;
    }

    public String isBloqueado() {
        return bloqueado;
    }

    public void setBloqueado(String bloqueado) {
        this.bloqueado = bloqueado;
    }
    
    /*
    Metodo para generar las claves prublica y privada de un usuario
    */
    public void generarClavePublicaPrivada() throws NoSuchAlgorithmException, NoSuchProviderException, Exception{
       
        GeneradorClaves keyGenerator = new GeneradorClaves(1024);
        PrivateKey privada = keyGenerator.getPrivateKey();
        PublicKey publica = keyGenerator.getPublicKey();
        
        keyGenerator.copiarPubKArchivo(publica, "C:\\Users\\Alejandro\\Documents\\NetBeansProjects\\PruebaWeb5\\web\\resources\\ClavesPublicas\\"+this.getUsuario()+".pub");
        keyGenerator.copiarPrivKArchivo(privada, "C:\\Users\\Alejandro\\Documents\\NetBeansProjects\\PruebaWeb5\\web\\resources\\ClavesPrivadas\\"+this.getUsuario()+".prv");
    }
    
    
}

