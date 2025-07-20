package pt.sirs.secureaccess.access.controller;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import pt.sirs.secureaccess.securedocument.Utils;

import javax.crypto.Cipher;
import java.security.*;
import java.security.spec.InvalidKeySpecException;

@RestController
public class AccessController {

    // Endpoint para receber pedidos de acesso
    @PostMapping("/access")
    public String processAccess(@RequestBody String payload) {
        JsonObject request = JsonParser.parseString(payload).getAsJsonObject();

        try {
            // Obter chave privada do servidor
            PrivateKey serverPrivKey = Utils.getPrivKey(Utils.readKey("demo/server/server.priv"));

            Key secret = Utils.extractSecret(request, serverPrivKey);
            byte[] iv = Utils.extractIV(request, serverPrivKey);

            String accessCode = new String(Utils.symCipher(
                    Cipher.DECRYPT_MODE,
                    Utils.decodeBase64(request.get("access_code").getAsString()),
                    secret,
                    iv
            ));
            String timestamp = new String(Utils.symCipher(
                    Cipher.DECRYPT_MODE,
                    Utils.decodeBase64(request.get("timestamp").getAsString()),
                    secret,
                    iv
            ));

            boolean macOk = Utils.checkMAC(request, serverPrivKey);
            if (!macOk) {
                return buildResponse("ERROR", "MAC inválido (integridade comprometida)");
            }

            // Validar pedido na base de dados
            // Exemplo: boolean acesso = bdService.validaCodigoAcesso(userId, accessCode, timestamp);
            boolean acesso = true; // TODO: integrar com BD

            String resposta = acesso ? "ACCESS_GRANTED" : "ACCESS_DENIED";

            // Gera resposta cifrada (opcional)
            JsonObject response = new JsonObject();
            response.addProperty("status", resposta);

            // (Opcional) Cifrar resposta para o cliente, se necessário

            return buildResponse("OK", response);

        } catch (Exception e) {
            return buildResponse("ERROR", "Falha a processar pedido: " + e.getMessage());
        }
    }

    private String buildResponse(String status, String payload) {
        JsonObject response = new JsonObject();
        response.addProperty("status", status);
        response.addProperty("payload", payload);
        return response.toString();
    }

    private String buildResponse(String status, JsonObject payload) {
        JsonObject response = new JsonObject();
        response.addProperty("status", status);
        response.add("payload", payload);
        return response.toString();
    }
}