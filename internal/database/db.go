package database

import (
	"database/sql"
	"log"

	_ "modernc.org/sqlite"
)

var DB *sql.DB

func InitDB(dbPath string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", dbPath+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)")
	if err != nil {
		return nil, err
	}
	
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	DB = db

	if err := migrate(); err != nil {
		return nil, err
	}

	log.Println("Database initialized successfully")
	return db, nil
}

func migrate() error {
	queries := []string{
		`PRAGMA journal_mode = WAL;`,
		`PRAGMA busy_timeout = 5000;`,
		`PRAGMA synchronous = NORMAL;`,
		`CREATE TABLE IF NOT EXISTS system_settings (
			setting_key TEXT PRIMARY KEY, 
			setting_value TEXT NOT NULL, 
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);`,
		`CREATE TABLE IF NOT EXISTS oidc_clients (
			client_id TEXT PRIMARY KEY, 
			client_secret_hash TEXT NOT NULL, 
			client_name TEXT NOT NULL, 
			redirect_uris TEXT NOT NULL, 
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);`,
		`CREATE TABLE IF NOT EXISTS admin_users (
			username TEXT PRIMARY KEY, 
			password_hash TEXT NOT NULL, 
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);`,
		`INSERT OR IGNORE INTO system_settings (setting_key, setting_value) VALUES 
			('site_name', '统一身份认证中心'),
			('site_logo', ''),
			('background_url', 'https://images.unsplash.com/photo-1618005182384-a83a8bd57fbe?auto=format&fit=crop&w=1920&q=80'),
			('custom_css', ''),
			('target_group_id', '87654321'),
			('onebot_token', 'oneauth_secure_secret_token'),
			('code_ttl', '180');`,
	}

	for _, q := range queries {
		if _, err := DB.Exec(q); err != nil {
			return err
		}
	}
	
	return nil
}

func GetSetting(key, defaultVal string) string {
	var val string
	err := DB.QueryRow("SELECT setting_value FROM system_settings WHERE setting_key = ?", key).Scan(&val)
	if err != nil {
		if err == sql.ErrNoRows {
			return defaultVal
		}
		log.Printf("Error getting setting %s: %v", key, err)
		return defaultVal
	}
	return val
}

func SetSetting(key, val string) error {
	_, err := DB.Exec(`
		INSERT INTO system_settings (setting_key, setting_value, updated_at) 
		VALUES (?, ?, CURRENT_TIMESTAMP) 
		ON CONFLICT(setting_key) DO UPDATE SET 
		setting_value = excluded.setting_value, 
		updated_at = CURRENT_TIMESTAMP
	`, key, val)
	return err
}
