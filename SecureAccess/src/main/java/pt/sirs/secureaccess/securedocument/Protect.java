package pt.sirs.secureaccess.securedocument;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;

public class Protect {

    public static void run(JsonObject file, PrivateKey key) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {

        if (file.has("MAC")) return;

        System.out.println("Starting encryption process...");

        Key secret = Utils.extractSecret(file, key);
        byte[] iv = Utils.extractIV(file, key);

        String tmp_secret = file.get("secret").getAsString();
        String tmp_IV = file.get("IV").getAsString();

        for (String field_name : Utils.privateFields) {
            if (!file.has(field_name)) {
                System.err.println("Field not found: " + field_name);
                continue; // ou lança exceção, conforme a política
            }
            byte[] plaintext = file.get(field_name).getAsString().getBytes();
            byte[] ciphertext = Utils.symCipher(Cipher.ENCRYPT_MODE, plaintext, secret, iv);
            file.addProperty(field_name, Utils.encodeBase64(ciphertext));
        }

        byte[] mac = Utils.generateMAC(file, secret);
        file.addProperty("secret", tmp_secret);
        file.addProperty("IV", tmp_IV);
        file.addProperty("MAC", Utils.encodeBase64(mac));

    }

    public static void run(String input_file, String output_file, PrivateKey key) throws IOException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        JsonObject file = Utils.readJSON(input_file);
        run(file, key);
        Utils.writeJSON(output_file, file);
    }

    public static void main(String[] args) {

        if (args.length < 4) {
            System.err.println("Usage: protect <input_file> <output_file> <client> <id>");
            return;
        }

        final String input_file = args[0];
        final String output_file = args[1];
        final String client = args[2];
        final int id = Integer.parseInt(args[3]);

        try {
            PrivateKey privKey = Utils.getPrivKey(Utils.readKey("demo/users/" + client + "/" + client + ".priv"));
            PublicKey pubKey = Utils.getPubKey(Utils.readKey("demo/users/" + client + "/" + client + ".pub"));

            JsonObject owner = Utils.readJSON("demo/users/" + client + "/" + client + ".json");

            Utils.createCode(owner, pubKey, "test code", -1);

            run("demo/storage/" + input_file, "demo/storage/" + output_file, privKey);

        } catch (NoSuchAlgorithmException | IOException | InvalidAlgorithmParameterException | NoSuchPaddingException |
                 IllegalBlockSizeException | BadPaddingException | InvalidKeyException | InvalidKeySpecException e) {
            System.err.println(e);
        }
    }
}