package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	_ "github.com/lib/pq"
)

type Person struct {
	ID       int    `json:"id"`
	Password string `json:"password"`
	UserName string `json:"username"`
	Email    string `json:"email"`
}

type MenuItem struct {
	ID       int     `json:"id"`
	Name     string  `json:"name"`
	Category string  `json:"category"`
	Price    float64 `json:"price"`
	Photo    string  `json:"photo"`
}

var db *sql.DB

func main() {
	var err error
	connStr := "user=postgres dbname=cafe password=0000 host=localhost sslmode=disable"
	db, err = sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	// Определение обработчиков
	http.HandleFunc("/people", peopleHandler)
	http.HandleFunc("/people/", personHandler)
	http.HandleFunc("/menu", menuHandler)
	http.HandleFunc("/health", healthCheckHandler)
	http.HandleFunc("/", serveIndex)
	http.HandleFunc("/home", home)
	http.HandleFunc("/menu1", menu)
	http.HandleFunc("/admin", adminHandler)

	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	log.Println("Listening on port 8080")
	err = http.ListenAndServe("localhost:8080", nil)
	if err != nil {
		log.Fatal(err)
	}
}

func home(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "home.html")
}

func menu(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "menu.html")
}

func serveIndex(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "register.html")
}

func adminHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		http.ServeFile(w, r, "admin.html")
	case http.MethodDelete:
		id := r.URL.Query().Get("id")
		if id == "" {
			http.Error(w, "Missing ID parameter", http.StatusBadRequest)
			return
		}
		deletePerson(w, r, id)
	default:
		http.Error(w, "invalid method", http.StatusMethodNotAllowed)
	}
}

func peopleHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		getPeople(w, r)
	case http.MethodPost:
		postPerson(w, r)
	default:
		http.Error(w, "invalid method", http.StatusMethodNotAllowed)
	}
}

func personHandler(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Path[len("/people/"):]

	switch r.Method {
	case http.MethodGet:
		getPerson(w, r, id)
	case http.MethodPut:
		updatePerson(w, r, id)
	case http.MethodDelete:
		deletePerson(w, r, id)
	default:
		http.Error(w, "invalid method", http.StatusMethodNotAllowed)
	}
}

func getPerson(w http.ResponseWriter, r *http.Request, id string) {
	row := db.QueryRow("SELECT id, username, password, email FROM users WHERE id=$1", id)

	var person Person
	if err := row.Scan(&person.ID, &person.UserName, &person.Password, &person.Email); err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "User not found", http.StatusNotFound)
		} else {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(person)
}

func getPeople(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query("SELECT id, username, password, email FROM users")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var people []Person
	for rows.Next() {
		var person Person
		if err := rows.Scan(&person.ID, &person.UserName, &person.Password, &person.Email); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		people = append(people, person)
	}

	if err := rows.Err(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(people)
}

func postPerson(w http.ResponseWriter, r *http.Request) {
	var person Person
	err := json.NewDecoder(r.Body).Decode(&person)
	if err != nil {
		http.Error(w, fmt.Sprintf("Invalid JSON format: %v", err), http.StatusBadRequest)
		return
	}

	if person.UserName == "" || person.Password == "" || person.Email == "" {
		http.Error(w, "Missing required fields", http.StatusBadRequest)
		return
	}

	_, err = db.Exec("INSERT INTO users (username, password, email) VALUES ($1, $2, $3)", person.UserName, person.Password, person.Email)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error inserting into database: %v", err), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	fmt.Fprintf(w, "Person created successfully")
}

func updatePerson(w http.ResponseWriter, r *http.Request, id string) {
	var person Person
	err := json.NewDecoder(r.Body).Decode(&person)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	_, err = db.Exec("UPDATE users SET username=$1, password=$2, email=$3 WHERE id=$4", person.UserName, person.Password, person.Email, id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func deletePerson(w http.ResponseWriter, r *http.Request, id string) {
	_, err := db.Exec("DELETE FROM users WHERE id=$1", id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
	fmt.Fprintf(w, "Person with ID %s deleted successfully", id)
}

func menuHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		getMenu(w, r)
	case http.MethodPost:
		postMenuItem(w, r)
	default:
		http.Error(w, "invalid method", http.StatusMethodNotAllowed)
	}
}

func postMenuItem(w http.ResponseWriter, r *http.Request) {
	var menuItem MenuItem
	err := json.NewDecoder(r.Body).Decode(&menuItem)
	if err != nil {
		http.Error(w, fmt.Sprintf("Invalid JSON format: %v", err), http.StatusBadRequest)
		return
	}

	if menuItem.Name == "" || menuItem.Category == "" || menuItem.Price <= 0 {
		http.Error(w, "Missing required fields", http.StatusBadRequest)
		return
	}

	_, err = db.Exec("INSERT INTO menu (name, category, price, photo) VALUES ($1, $2, $3, $4)", menuItem.Name, menuItem.Category, menuItem.Price, menuItem.Photo)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error inserting into database: %v", err), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	fmt.Fprintf(w, "Menu item created successfully")
}

func getMenu(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query("SELECT id, name, category, price, photo FROM menu")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var menuItems []MenuItem
	for rows.Next() {
		var menuItem MenuItem
		if err := rows.Scan(&menuItem.ID, &menuItem.Name, &menuItem.Category, &menuItem.Price, &menuItem.Photo); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		menuItems = append(menuItems, menuItem)
	}

	if err := rows.Err(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(menuItems)
}

func healthCheckHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintln(w, "OK")
}
