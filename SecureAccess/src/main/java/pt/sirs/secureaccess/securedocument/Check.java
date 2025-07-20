package pt.sirs.secureaccess.securedocument;

import com.google.gson.JsonObject;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;

public class Check {

    public static boolean run(JsonObject file, PrivateKey key) throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
        if (!file.has("MAC")) {
            System.err.println("MAC not found. File is not protected.");
            return false;
        }
        return Utils.checkMAC(file, key);
    }

    public static boolean run(String input_file, PrivateKey key) throws IOException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        JsonObject file = Utils.readJSON(input_file);
        return run(file, key);
    }

    public static void main(String[] args) {

        if (args.length < 2) {
            System.err.println("Usage: check <input_file> <client>");
            return;
        }

        final String input_file = args[0];
        final String client = args[1];

        try {
            PrivateKey privKey = Utils.getPrivKey(Utils.readKey("demo/users/" + client + "/" + client + ".priv"));

            if (run("demo/storage/" + input_file, privKey)) {
                System.out.println("File is secure.");
            } else {
                System.out.println("File is not secure.");
            }

        } catch (IOException | NoSuchAlgorithmException | InvalidKeyException | InvalidKeySpecException |
                 NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException e) {
            System.err.println(e);
        }
    }
}
