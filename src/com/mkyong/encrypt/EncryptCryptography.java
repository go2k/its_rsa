package com.mkyong.encrypt;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.file.Files;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import java.util.*;

public class EncryptCryptography {
    private Cipher cipher;

    public EncryptCryptography() throws NoSuchAlgorithmException, NoSuchPaddingException{
        this.cipher = Cipher.getInstance("RSA");
    }
    //https://docs.oracle.com/javase/8/docs/api/java/security/spec/PKCS8EncodedKeySpec.html
    public PrivateKey getPrivate(String filename) throws Exception {
        byte[] keyBytes = Files.readAllBytes(new File(filename).toPath());
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(spec);
    }
    //https://docs.oracle.com/javase/8/docs/api/java/security/spec/X509EncodedKeySpec.html
    public PublicKey getPublic(String filename) throws Exception {
        byte[] keyBytes = Files.readAllBytes(new File(filename).toPath());
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(spec);
    }

    public void encryptFile(byte[] input, File output, PublicKey key) throws IOException, GeneralSecurityException {
        this.cipher.init(Cipher.ENCRYPT_MODE, key);
        writeToFile(output, this.cipher.doFinal(input));
    }


    private void writeToFile(File output, byte[] toWrite) throws IllegalBlockSizeException, BadPaddingException, IOException{
        FileOutputStream fos = new FileOutputStream(output);
        fos.write(toWrite);
        fos.flush();
        fos.close();
    }

    public byte[] getFileInBytes(File f) throws IOException{
        FileInputStream fis = new FileInputStream(f);
        byte[] fbytes = new byte[(int) f.length()];
        fis.read(fbytes);
        fis.close();
        return fbytes;
    }

    public static void main(String[] args) throws Exception {
        EncryptCryptography ac = new EncryptCryptography();
     //   PublicKey publicKey  = ac.getPublic("KeyPair/publicKey");

     //   String msg = "Cryptography is fun!";
     //   String encrypted_msg = ac.encryptText(msg, privateKey);
     //   String decrypted_msg = ac.decryptText(encrypted_msg, publicKey);
     //   System.out.println("Original Message: " + msg + "\nEncrypted Message: " + encrypted_msg + "\nDecrypted Message: " + decrypted_msg);

        Scanner sc = new Scanner(System.in);
        System.out.print("Bitte geben Sie den Dateinamen der zu verschlüsselnden Datei an: ");
        String eingabe = sc.next();
        System.out.println("Es wird die Datei KeyPair/" + eingabe + " verwendet.");

        System.out.print("Bitte geben Sie den Dateinamen des zu verwendenen Schlüssels an: ");
        String keyfile = sc.next();
        System.out.println("Es wird die Datei KeyPair/" + keyfile + " verwendet.");


        if(new File("KeyPair/"+eingabe).exists() && new File("KeyPair/"+keyfile).exists()){
            PublicKey publicKey = ac.getPublic("KeyPair/"+keyfile);
            ac.encryptFile(ac.getFileInBytes(new File("KeyPair/"+eingabe)), new File("KeyPair/encrypted_"+eingabe), publicKey);
         //   ac.decryptFile(ac.getFileInBytes(new File("KeyPair/text_encrypted.txt")), new File("KeyPair/text_decrypted.txt"), publicKey);
        }else{
            System.out.println("Datei KeyPair/"+eingabe+" oder Schlüssel KeyPair/"+keyfile+" nicht gefunden");
        }
    }
}

