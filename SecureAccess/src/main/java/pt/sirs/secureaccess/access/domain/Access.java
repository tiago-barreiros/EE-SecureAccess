package pt.sirs.secureaccess.access.domain;

import com.google.gson.JsonObject;

public class Access {

    private Integer id;
    private String userId;
    private String accessCode;
    private String timestamp;
    private String secret;
    private String iv;
    private String mac;

    public Access() {}

    // Construtor a partir de um JsonObject
    public Access(JsonObject obj) {
        this.id = obj.has("id") ? obj.get("id").getAsInt() : null;
        this.userId = obj.has("user_id") ? obj.get("user_id").getAsString() : null;
        this.accessCode = obj.has("access_code") ? obj.get("access_code").getAsString() : null;
        this.timestamp = obj.has("timestamp") ? obj.get("timestamp").getAsString() : null;
        this.secret = obj.has("secret") ? obj.get("secret").getAsString() : null;
        this.iv = obj.has("IV") ? obj.get("IV").getAsString() : null;
        this.mac = obj.has("MAC") ? obj.get("MAC").getAsString() : null;
    }

    // Getters e setters
    public Integer getId() { return id; }
    public void setId(Integer id) { this.id = id; }

    public String getUserId() { return userId; }
    public void setUserId(String userId) { this.userId = userId; }

    public String getAccessCode() { return accessCode; }
    public void setAccessCode(String accessCode) { this.accessCode = accessCode; }

    public String getTimestamp() { return timestamp; }
    public void setTimestamp(String timestamp) { this.timestamp = timestamp; }

    public String getSecret() { return secret; }
    public void setSecret(String secret) { this.secret = secret; }

    public String getIv() { return iv; }
    public void setIv(String iv) { this.iv = iv; }

    public String getMac() { return mac; }
    public void setMac(String mac) { this.mac = mac; }
}
