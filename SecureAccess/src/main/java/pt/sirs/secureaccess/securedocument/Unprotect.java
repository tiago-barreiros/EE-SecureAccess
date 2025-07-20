package pt.sirs.secureaccess.securedocument;

import com.google.gson.JsonObject;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;

public class Unprotect {

    public static void run(JsonObject file, PrivateKey key) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {

        System.out.println("Starting decryption process...");

        // Confirma que MAC existe e valida integridade antes de descifrar
        if (!file.has("MAC"))
            throw new IllegalArgumentException("Documento não está protegido! MAC em falta.");
        if (!Utils.checkMAC(file, key))
            throw new SecurityException("MAC inválido! Documento pode ter sido alterado ou corrompido.");

        Key secret = Utils.extractSecret(file, key);
        byte[] iv = Utils.extractIV(file, key);

        for (String field_name : Utils.privateFields) {
            byte[] ciphertext = Utils.decodeBase64(file.get(field_name).getAsString());
            byte[] plaintext = Utils.symCipher(Cipher.DECRYPT_MODE, ciphertext, secret, iv);
            file.addProperty(field_name, new String(plaintext));
        }

        file.remove("MAC");
    }

    public static void run(String input_file, String output_file, PrivateKey key) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IOException {
        JsonObject file = Utils.readJSON(input_file);
        run(file, key);
        Utils.writeJSON(output_file, file);
    }

        public static void main(String[] args) {

        if (args.length < 3) {
            System.err.println("Usage: unprotect <input_file> <output_file> <client>");
            return;
        }

        final String input_file = args[0];
        final String output_file = args[1];
        final String client = args[2];

        try {
            PrivateKey privKey = Utils.getPrivKey(Utils.readKey("demo/users/" + client + "/" + client + ".priv"));

            run("demo/storage/" + input_file, "demo/storage/" + output_file, privKey);

        } catch (NoSuchAlgorithmException | IOException | InvalidAlgorithmParameterException | NoSuchPaddingException |
                 IllegalBlockSizeException | BadPaddingException | InvalidKeyException | InvalidKeySpecException e) {
            System.err.println(e);
        }
    }
}