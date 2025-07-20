package pt.sirs.secureaccess.securedocument;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.util.Base64;

public class Utils {

    public static String[] privateFields = {"access_code", "timestamp"};

    public static byte[] generateIV() {
        System.out.println("Generating IV...");
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        return iv;
    }

    public static byte[] extractIV(JsonObject file, Key key) throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        byte[] encrypted_IV = decodeBase64(file.get("IV").getAsString());
        return asymCipher(Cipher.DECRYPT_MODE, encrypted_IV, key);
    }

    //ns
    public static void writeKey(String path, Key key) throws IOException {
        System.out.println("Saving key to " + path + "...");
        FileOutputStream fos = new FileOutputStream(path);
        fos.write(key.getEncoded());
        fos.close();
    }

    //ns
    public static byte[] readKey(String path) throws IOException {
        System.out.println("Reading key from " + path + "...");
        FileInputStream fis = new FileInputStream(path);
        byte[] encoded = new byte[fis.available()];
        fis.read(encoded);
        fis.close();
        return encoded;
    }

    public static Key extractSecret(JsonObject file, Key key) throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        byte[] encrypted_secret = Utils.decodeBase64(file.get("secret").getAsString());
        return getSymKey(asymCipher(Cipher.DECRYPT_MODE, encrypted_secret, key));
    }

    public static Key generateSymKey() throws NoSuchAlgorithmException {
        System.out.println("Generating AES key...");
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128);
        return keyGen.generateKey();
    }

    public static Key getSymKey(byte[] encodedKey) {
        return new SecretKeySpec(encodedKey, 0, 16, "AES");
    }

    public static KeyPair generateAsymKeyPair() throws NoSuchAlgorithmException, IOException {
        System.out.println("Generating RSA key...");
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        return keyGen.generateKeyPair();
    }

    public static PublicKey getPubKey(byte[] encodedKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
        X509EncodedKeySpec pubSpec = new X509EncodedKeySpec(encodedKey);
        KeyFactory keyFacPub = KeyFactory.getInstance("RSA");
        return keyFacPub.generatePublic(pubSpec);
    }

    public static PrivateKey getPrivKey(byte[] encodedKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
        PKCS8EncodedKeySpec privSpec = new PKCS8EncodedKeySpec(encodedKey);
        KeyFactory keyFacPriv = KeyFactory.getInstance("RSA");
        return keyFacPriv.generatePrivate(privSpec);
    }

    public static String encodeBase64(byte[] content) {
        return Base64.getEncoder().encodeToString(content);
    }

    public static byte[] decodeBase64(String content) {
        return Base64.getDecoder().decode(content);
    }

    public static byte[] symCipher(int mode, byte[] content, Key key, byte[] iv) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(mode, key, new GCMParameterSpec(128, iv));
        return cipher.doFinal(content);
    }

    public static byte[] asymCipher(int mode, byte[] content, Key key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(mode, key);
        return cipher.doFinal(content);
    }

    public static byte[] generateMAC(JsonObject content, Key key) throws NoSuchAlgorithmException, InvalidKeyException {
        // System.out.println("Generating MAC...");
        content.remove("secret");
        content.remove("IV");
        content.remove("MAC");
        byte[] bytes = new Gson().toJson(content).getBytes();
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(key);
        return  mac.doFinal(bytes);
    }

    public static boolean checkMAC(JsonObject content, Key key) throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
        // System.out.println("Checking MAC...");
        Key secret = extractSecret(content, key);
        byte[] givenMAC = decodeBase64(content.get("MAC").getAsString());
        return Arrays.equals(givenMAC, generateMAC(content, secret));
    }

    public static void sign(JsonObject request, PrivateKey key) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        // System.out.println("Signing document...");
        byte[] bytes = new Gson().toJson(request).getBytes();
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(key);
        signature.update(bytes);
        request.addProperty("signature", encodeBase64(signature.sign()));
    }

    public static boolean checkSignature(JsonObject request, PublicKey key) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        byte[] givenSignature = decodeBase64(request.get("signature").getAsString());
        request.remove("signature");
        byte[] bytes = new Gson().toJson(request).getBytes();
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initVerify(key);
        signature.update(bytes);
        return signature.verify(givenSignature);
    }

    public static byte[] generateDigest(JsonArray content) throws NoSuchAlgorithmException {
        MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
        messageDigest.update(new Gson().toJson(content).getBytes());
        return messageDigest.digest();
    }

    public static boolean checkDigest(JsonArray content, byte[] givenDigest) throws NoSuchAlgorithmException {
        return Arrays.equals(givenDigest, generateDigest(content));
    }

    public static void writeJSON(String path, JsonObject file) throws IOException {
        // System.out.println("Saving file...");
        FileWriter fw = new FileWriter(path);
        Gson gson = new GsonBuilder().setPrettyPrinting().create();
        gson.toJson(file, fw);
        fw.close();
    }

    public static JsonObject readJSON(String path) throws IOException {
        // System.out.println("Reading file...");
        Gson gson = new Gson();
        FileReader fr = new FileReader(path);
        JsonObject file = gson.fromJson(fr, JsonObject.class);
        fr.close();
        return file;
    }

    public static String toJSONString(JsonObject obj) {
        return new Gson().toJson(obj);
    }

    public static JsonObject fromJSONString(String s) {
        return new Gson().fromJson(s, JsonObject.class);
    }

    public static JsonObject createCode(JsonObject owner, Key pubKey, String access_code, int id) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {

        Key secretKey = generateSymKey();
        byte[] iv = generateIV();

        byte[] accessCodeCiphered = symCipher(Cipher.ENCRYPT_MODE, access_code.getBytes(), secretKey, iv);

        byte[] secret = asymCipher(Cipher.ENCRYPT_MODE, secretKey.getEncoded(), pubKey);
        byte[] ivCiphered = asymCipher(Cipher.ENCRYPT_MODE, iv, pubKey);

        String timestamp = DateTimeFormatter.ISO_INSTANT.format(Instant.now()).split("[.]")[0];

        JsonObject note = new JsonObject();

        note.addProperty("id", id);
        note.addProperty("access_code", encodeBase64(accessCodeCiphered));
        note.addProperty("timestamp", timestamp);
        note.addProperty("secret", encodeBase64(secret));
        note.addProperty("IV", encodeBase64(ivCiphered));

        note.addProperty("MAC", encodeBase64(generateMAC(note, secretKey)));

        //writeJSON(path, note);
        return note;
    }

}
