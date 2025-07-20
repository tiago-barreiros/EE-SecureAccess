CREATE TABLE IF NOT EXISTS users (
                                     id          SERIAL PRIMARY KEY,
                                     username    TEXT UNIQUE NOT NULL,
                                     public_key  TEXT,                 -- Chave pública para operações seguras (opcional)
                                     created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS access_codes (
                                            id              SERIAL PRIMARY KEY,
                                            user_id         INTEGER NOT NULL REFERENCES users(id),
    access_code     TEXT    NOT NULL,     -- Deve estar cifrado/hasheado
    timestamp       TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    secret          TEXT,                 -- Chave simétrica cifrada (opcional)
    iv              TEXT,                 -- Vetor de inicialização cifrado (opcional)
    mac             TEXT,                 -- Código de autenticação da mensagem (opcional)
    valid           BOOLEAN DEFAULT TRUE  -- Flag de validade do código
    );

CREATE TABLE IF NOT EXISTS access_logs (
                                           id              SERIAL PRIMARY KEY,
                                           user_id         INTEGER REFERENCES users(id),
    action          TEXT NOT NULL,                -- Ex: 'login', 'code_check', 'logout'
    access_code_id  INTEGER REFERENCES access_codes(id),
    success         BOOLEAN,
    log_time        TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    details         TEXT
    );

