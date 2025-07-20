package pt.sirs.secureaccess.client;

import com.google.gson.JsonObject;
import pt.sirs.secureaccess.securedocument.Utils;

import java.io.IOException;
import java.net.URI;
import java.net.http.*;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Scanner;

public class ClientApp {

    public static void main(String[] args) {
        try (Scanner scanner = new Scanner(System.in)) {
            System.out.println("========= SecureAccess Client =========");

            HttpClient httpClient = HttpClient.newBuilder().build();

            System.out.print("Username: ");
            String username = scanner.nextLine();

            PrivateKey privKey = null;
            PublicKey pubKey = null;
            JsonObject owner = null;
            try {
                privKey = Utils.getPrivKey(Utils.readKey("demo/users/" + username + "/" + username + ".priv"));
                pubKey = Utils.getPubKey(Utils.readKey("demo/users/" + username + "/" + username + ".pub"));
                owner = Utils.readJSON("demo/users/" + username + "/" + username + ".json");
            } catch (Exception e) {
                System.err.println("Erro ao carregar chaves/owner: " + e);
                return;
            }

            System.out.print("API URL [ex: https://192.168.0.100:8443/access]: ");
            String apiUrl = scanner.nextLine();

            // Ciclo principal
            while (true) {
                System.out.print("\nComando (request/exit/help): ");
                String cmd = scanner.nextLine().trim();
                if (cmd.equalsIgnoreCase("exit")) {
                    System.out.println("A terminar...");
                    break;
                }
                if (cmd.equalsIgnoreCase("help")) {
                    System.out.println("Comandos disponíveis:");
                    System.out.println("  request - gerar e enviar pedido de acesso");
                    System.out.println("  exit    - sair");
                    continue;
                }
                if (cmd.equalsIgnoreCase("request")) {
                    System.out.print("Código de acesso: ");
                    String accessCode = scanner.nextLine().trim();
                    System.out.print("ID do pedido: ");
                    int requestId = Integer.parseInt(scanner.nextLine().trim());

                    try {
                        // 1. Gerar pedido seguro
                        JsonObject accessRequest = Utils.createCode(owner, pubKey, accessCode, requestId);
                        String payload = new com.google.gson.Gson().toJson(accessRequest);

                        // 2. Enviar pedido para a API
                        HttpRequest httpRequest = HttpRequest.newBuilder()
                                .uri(URI.create(apiUrl))
                                .header("Content-Type", "application/json")
                                .POST(HttpRequest.BodyPublishers.ofString(payload))
                                .build();

                        HttpResponse<String> response = httpClient.send(httpRequest, HttpResponse.BodyHandlers.ofString());

                        // 3. Processar resposta da API (simples: só mostrar, ou descifrar se necessário)
                        System.out.println("\nResposta da API:");
                        System.out.println(response.body());

                        // Se a resposta for cifrada, processa aqui (decifrar com privKey, etc.)

                    } catch (Exception e) {
                        System.err.println("Erro ao processar pedido: " + e);
                        e.printStackTrace();
                    }
                } else {
                    System.out.println("Comando desconhecido. Escreve help para ver os comandos disponíveis.");
                }
            }
        }
    }
}
