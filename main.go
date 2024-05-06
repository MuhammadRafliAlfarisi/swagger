package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"

	"strings"
	"time"

	"swagger-rest-api/database"

	"github.com/dgrijalva/jwt-go"
	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/mux"
	"github.com/rs/cors"
)

var jwtKey = []byte("your_secret_key")

type Mahasiswa struct {
	Id       int    `json:"id"`
	Nama     string `json:"nama"`
	NPM      int    `json:"npm"`
	Kelas    string `json:"kelas"`
	Asalkota string `json:"asal_kota"`
}

func main() {

	defer database.DB.Close()
	db := database.DB

	type User struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	router := mux.NewRouter()

	router.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		var user User
		err := json.NewDecoder(r.Body).Decode(&user)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// Here you should add your database logic to check user credentials
		// For simplicity, we assume the user is authenticated if username and password are not empty
		if user.Username != "" && user.Password != "" {
			tokenString, err := GenerateJWT()
			if err != nil {
				http.Error(w, "Error generating token", http.StatusInternalServerError)
				return
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"token": tokenString})
		} else {
			http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		}
	})

	router.HandleFunc("/user", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "OPTIONS" {
			// Handle preflight request
			w.Header().Set("Access-Control-Allow-Origin", "http://127.0.0.1:5500")
			w.Header().Set("Access-Control-Allow-Origin", "https://MuhammadRafliAlfarisi.github.io/")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
			return
		}
		switch r.Method {
		case "GET":
			idStr := r.URL.Query().Get("id")
			if idStr != "" {
				getMahasiswa(db, w, r)
			} else {
				getMahasiswas(db, w, r)
			}
		case "POST":
			bearerToken := r.Header.Get("Authorization")
			strArr := strings.Split(bearerToken, " ")
			if len(strArr) == 2 {
				isValid, _ := ValidateToken(strArr[1])
				if isValid {
					createMahasiswa(db, w, r)
				} else {
					http.Error(w, "Unauthorized", http.StatusUnauthorized)
				}
			} else {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
			}
		case "PUT":
			updateMahasiswa(db, w, r)
		case "DELETE":
			deleteMahasiswa(db, w, r)
		default:
			http.Error(w, "Unsupported HTTP Method", http.StatusBadRequest)
		}
	})

	// Set up CORS middleware
	c := cors.New(cors.Options{
		AllowedOrigins: []string{"http://127.0.0.1:5500", "https://MuhammadRafliAlfarisi.github.io/"},
		AllowedMethods: []string{"GET", "POST", "PUT", "DELETE"},
		AllowedHeaders: []string{"Content-Type", "Authorization"},
		Debug:          true,
	})

	handler := c.Handler(router)

	fmt.Println("Server is running on http://localhost:8085")
	log.Fatal(http.ListenAndServe(":8085", handler))
}

func GenerateJWT() (string, error) {
	token := jwt.New(jwt.SigningMethodHS256)

	claims := token.Claims.(jwt.MapClaims)
	claims["authorized"] = true
	claims["exp"] = time.Now().Add(time.Minute * 30).Unix()

	tokenString, err := token.SignedString(jwtKey)

	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func ValidateToken(tokenString string) (bool, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})

	if err != nil {
		return false, err
	}

	return token.Valid, nil
}

func getMahasiswa(db *sql.DB, w http.ResponseWriter, r *http.Request) {
	//panic("unimplemented")
	idStr := r.URL.Query().Get("id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		http.Error(w, "Invalid users ID", http.StatusBadRequest)
		return
	}

	row := db.QueryRow("SELECT id, nama, npm, kelas, asal_kota  FROM user WHERE id = ?", id)

	var m Mahasiswa
	if err := row.Scan(&m.Id, &m.Nama, &m.NPM, &m.Kelas, &m.Asalkota); err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "Product not found", http.StatusNotFound)
		} else {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(m)
}

func getMahasiswas(db *sql.DB, w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query("SELECT id, nama, npm, kelas, asal_kota  FROM user")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var mahasiswas []Mahasiswa
	for rows.Next() {
		var m Mahasiswa
		if err := rows.Scan(&m.Id, &m.Nama, &m.NPM, &m.Kelas, &m.Asalkota); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		mahasiswas = append(mahasiswas, m)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(mahasiswas)
}

func createMahasiswa(db *sql.DB, w http.ResponseWriter, r *http.Request) {
	var m Mahasiswa
	if err := json.NewDecoder(r.Body).Decode(&m); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	result, err := db.Exec("INSERT INTO user (id, nama, npm,kelas,asal_kota) VALUES (?, ?, ?,?,?)", m.Id, m.Nama, m.NPM, m.Kelas, m.Asalkota)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	id, err := result.LastInsertId()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	m.Id = int(id)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(m)
}

func updateMahasiswa(db *sql.DB, w http.ResponseWriter, r *http.Request) {
	var m Mahasiswa
	if err := json.NewDecoder(r.Body).Decode(&m); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if _, err := db.Exec("UPDATE user SET nama = ?, npm = ?, kelas = ?, asal_kota = ?  WHERE id = ?", m.Nama, m.NPM, m.Kelas, m.Asalkota, m.Id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func deleteMahasiswa(db *sql.DB, w http.ResponseWriter, r *http.Request) {
	idStr := r.URL.Query().Get("id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		http.Error(w, "Invalid ticket ID", http.StatusBadRequest)
		return
	}

	if _, err := db.Exec("DELETE FROM user WHERE id = ?", id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
