package pt.sirs.secureaccess.access.service;

import com.google.gson.JsonObject;
import org.springframework.stereotype.Service;
import pt.sirs.secureaccess.access.domain.Access;

import java.sql.*;
import java.util.*;

@Service
public class AccessService {

    private Connection connection;

    public boolean logInDatabase() {
        if (isConnectionValid()) return true;
        try {
            String url = "jdbc:postgresql://192.168.1.1:5432/sirs";
            String user = "postgres";
            String password = "admin";
            Properties props = new Properties();
            props.setProperty("user", user);
            props.setProperty("password", password);
            props.setProperty("sslmode", "require");
            props.setProperty("sslrootcert", "/etc/postgresql/17/certs/cert.pem");

            connection = DriverManager.getConnection(url, props);
            System.out.println("Database connection established.");
            return true;
        } catch (SQLException e) {
            e.printStackTrace();
            System.err.println("Failed to establish database connection.");
            return false;
        }
    }

    private boolean isConnectionValid() {
        try {
            return connection != null && !connection.isClosed();
        } catch (SQLException e) {
            e.printStackTrace();
            return false;
        }
    }

    /**
     * Guarda um pedido de acesso na base de dados.
     */
    public boolean storeAccessRequest(Access req) {
        if (!isConnectionValid()) throw new IllegalStateException("ERROR: No valid database connection.");
        String query = "INSERT INTO access_requests " +
                "(id, user_id, access_code, timestamp, secret, iv, mac) VALUES (?, ?, ?, ?, ?, ?, ?)";

        try (PreparedStatement ps = connection.prepareStatement(query)) {
            ps.setInt(1, req.getId());
            ps.setString(2, req.getUserId());
            ps.setString(3, req.getAccessCode());
            ps.setString(4, req.getTimestamp());
            ps.setString(5, req.getSecret());
            ps.setString(6, req.getIv());
            ps.setString(7, req.getMac());
            ps.executeUpdate();
            return true;
        } catch (SQLException e) {
            System.err.println("Failed to store access request: " + e.getMessage());
            return false;
        }
    }

    /**
     * Verifica se um código de acesso existe e está válido para um dado user_id.
     */
    public boolean validateAccessCode(String userId, String accessCode) {
        if (!isConnectionValid()) throw new IllegalStateException("ERROR: No valid database connection.");
        String query = "SELECT COUNT(*) FROM access_codes WHERE user_id = ? AND code = ?";
        try (PreparedStatement ps = connection.prepareStatement(query)) {
            ps.setString(1, userId);
            ps.setString(2, accessCode);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    return rs.getInt(1) > 0;
                }
            }
        } catch (SQLException e) {
            System.err.println("Error validating access code: " + e.getMessage());
        }
        return false;
    }

    public List<Access> getAllAccessRequests() {
        if (!isConnectionValid()) throw new IllegalStateException("ERROR: No valid database connection.");
        String query = "SELECT * FROM access_requests";
        List<Access> requests = new ArrayList<>();
        try (Statement stmt = connection.createStatement();
             ResultSet rs = stmt.executeQuery(query)) {
            while (rs.next()) {
                Access req = new Access();
                req.setId(rs.getInt("id"));
                req.setUserId(rs.getString("user_id"));
                req.setAccessCode(rs.getString("access_code"));
                req.setTimestamp(rs.getString("timestamp"));
                req.setSecret(rs.getString("secret"));
                req.setIv(rs.getString("iv"));
                req.setMac(rs.getString("mac"));
                requests.add(req);
            }
        } catch (SQLException e) {
            System.err.println("Error retrieving access requests: " + e.getMessage());
        }
        return requests;
    }

}
