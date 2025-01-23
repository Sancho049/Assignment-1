package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/gorilla/sessions"
	_ "github.com/gorilla/sessions"
	_ "github.com/lib/pq"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/time/rate"
	"io"
	"log"
	"net/http"
	"net/smtp"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	_ "testing"
	"time"
)

type Person struct {
	ID                int           `json:"id"`
	Password          string        `json:"password"`
	UserName          string        `json:"username"`
	Email             string        `json:"email"`
	RoleID            sql.NullInt32 `json:"role_id"`
	RoleName          string        `json:"role_name"`
	IsVerified        bool          `json:"is_verified"`
	VerificationToken string        `json:"-"`
}

type MenuItem struct {
	ID       int     `json:"id"`
	Name     string  `json:"name"`
	Category string  `json:"category"`
	Price    float64 `json:"price"`
	Photo    string  `json:"photo"`
}

var db *sql.DB
var limiter = rate.NewLimiter(1, 5) // Ограничение запросов: 1 запрос в секунду с максимум 5 запросов за раз
var logger = logrus.New()

func main() {
	// Настройка логирования
	logger.SetFormatter(&logrus.JSONFormatter{})
	logger.SetOutput(os.Stdout)

	var err error
	connStr := "user=postgres dbname=cafe password=0000 host=localhost sslmode=disable"
	db, err = sql.Open("postgres", connStr)
	if err != nil {
		logger.WithError(err).Fatal("Ошибка подключения к базе данных")
	}
	defer db.Close()
	updatePasswords()

	fetchMenuDataFromAPI()

	// Определение обработчиков с логированием
	mux := http.NewServeMux()
	mux.HandleFunc("/people", peopleHandler)
	mux.HandleFunc("/people/", personHandler)
	mux.HandleFunc("/menu", menuHandler)
	mux.HandleFunc("/health", healthCheckHandler)
	mux.HandleFunc("/", serveIndex)
	mux.HandleFunc("/home", home)
	mux.HandleFunc("/menu1", menu)
	mux.HandleFunc("/admin", adminMiddleware(adminHandler))
	mux.HandleFunc("/admin/send", sendEmailHandler)
	mux.HandleFunc("/signup", signup)
	mux.HandleFunc("/login", loginHandler)
	mux.HandleFunc("/confirm", confirmHandler)
	mux.HandleFunc("/verify", verifyHandler)
	mux.HandleFunc("/resend", resendHandler)
	mux.HandleFunc("/check_verification", checkVerificationStatusHandler)
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	loggedRouter := loggingMiddleware(mux)

	logger.Info("Запуск сервера на порту 8080")

	srv := &http.Server{
		Addr:    "localhost:8080",
		Handler: loggedRouter,
	}

	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.WithError(err).Fatal("Ошибка запуска сервера")
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)
	<-quit
	logger.Info("Остановка сервера...")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		logger.WithError(err).Fatal("Принудительное завершение сервера")
	}
	logger.Info("Сервер успешно остановлен")
}

func rateLimitMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !limiter.Allow() {
			logger.Warn("Превышение лимита запросов")
			http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	}
}

func home(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "home.html")
}

func menu(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "menu.html")
}

func serveIndex(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "home.html")
}
func verifyHandler(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "verify.html") // Страница с уведомлением
}

func signup(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		http.ServeFile(w, r, "register.html") // Отображение страницы регистрации
	case http.MethodPost:
		handleSignup(w, r)
	default:
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
	}
}

func handleSignup(w http.ResponseWriter, r *http.Request) {
	// Проверяем метод запроса
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	// Декодируем данные из тела запроса
	var person Person
	err := json.NewDecoder(r.Body).Decode(&person)
	if err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	// Проверяем обязательные поля
	if person.UserName == "" || person.Password == "" || person.Email == "" {
		http.Error(w, "All fields are required", http.StatusBadRequest)
		return
	}

	// Хэшируем пароль пользователя
	hashedPassword, err := hashPassword(person.Password)
	if err != nil {
		http.Error(w, "Failed to hash password", http.StatusInternalServerError)
		return
	}

	// Генерируем токен подтверждения
	verificationToken := generateToken()

	// Сохраняем пользователя в базе данных
	_, err = db.Exec(
		"INSERT INTO users (username, password, email, is_verified, verification_token) VALUES ($1, $2, $3, $4, $5)",
		person.UserName, hashedPassword, person.Email, false, verificationToken,
	)
	if err != nil {
		logger.WithError(err).Error("Error inserting user into database")
		http.Error(w, fmt.Sprintf("Failed to save user: %v", err), http.StatusInternalServerError)
		return
	}

	// Асинхронно отправляем письмо с подтверждением
	go sendVerificationEmail(person.Email, verificationToken)

	// Формируем URL страницы подтверждения
	verificationURL := fmt.Sprintf("/verify?token=%s", verificationToken)

	// Возвращаем успешный JSON-ответ
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{
		"message":          "Registration successful. Please verify your email.",
		"verification_url": verificationURL,
	})
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
	logger.WithFields(logrus.Fields{
		"method": r.Method,
		"path":   r.URL.Path,
	}).Info("Запрос на обработку пользователей")

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
		logger.WithError(err).Error("Ошибка запроса к базе данных")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var people []Person
	for rows.Next() {
		var person Person
		if err := rows.Scan(&person.ID, &person.UserName, &person.Password, &person.Email); err != nil {
			logger.WithError(err).Error("Ошибка сканирования строки из базы данных")
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		people = append(people, person)
	}

	if err := rows.Err(); err != nil {
		logger.WithError(err).Error("Ошибка обработки строк из базы данных")
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

	// Проверка обязательных полей
	if person.UserName == "" || person.Password == "" || person.Email == "" {
		http.Error(w, "Missing required fields", http.StatusBadRequest)
		return
	}

	// Хешируем пароль перед сохранением
	hashedPassword, err := hashPassword(person.Password)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error hashing password: %v", err), http.StatusInternalServerError)
		return
	}

	// Генерация токена подтверждения
	verificationToken := generateToken()

	// Сохраняем пользователя с хешированным паролем и токеном
	_, err = db.Exec("INSERT INTO users (username, password, email, is_verified, verification_token) VALUES ($1, $2, $3, $4, $5)",
		person.UserName, hashedPassword, person.Email, false, verificationToken)

	if err != nil {
		http.Error(w, fmt.Sprintf("Error inserting into database: %v", err), http.StatusInternalServerError)
		return
	}

	// Отправляем email
	go sendVerificationEmail(person.Email, verificationToken)

	w.WriteHeader(http.StatusCreated)
	fmt.Fprintf(w, "Registration successful! Please check your email to confirm your account.")
}
func sendVerificationEmail(email, token string) {
	verificationURL := fmt.Sprintf("http://localhost:8080/confirm?token=%s", token)

	subject := "Email Confirmation"
	body := fmt.Sprintf("Click the following link to verify your email: %s", verificationURL)

	smtpHost := "smtp.gmail.com"
	smtpPort := "587"
	senderEmail := "mamyrbeksanat282@gmail.com"
	password := "negl phgr aanr jxen"

	auth := smtp.PlainAuth("", senderEmail, password, smtpHost)

	message := fmt.Sprintf("From: %s\nTo: %s\nSubject: %s\n\n%s", senderEmail, email, subject, body)
	err := smtp.SendMail(smtpHost+":"+smtpPort, auth, senderEmail, []string{email}, []byte(message))
	if err != nil {
		log.Printf("Failed to send email: %v", err)
	}
}
func confirmHandler(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		http.Error(w, "Missing token", http.StatusBadRequest)
		return
	}

	// Проверяем токен в базе данных
	var userId int
	err := db.QueryRow("SELECT id FROM users WHERE verification_token = $1 AND is_verified = FALSE", token).Scan(&userId)
	if err == sql.ErrNoRows {
		http.Error(w, "Invalid or expired token", http.StatusBadRequest)
		return
	} else if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Обновляем статус пользователя
	_, err = db.Exec("UPDATE users SET is_verified = TRUE, verification_token = NULL WHERE id = $1", userId)
	if err != nil {
		http.Error(w, "Failed to update user", http.StatusInternalServerError)
		return
	}

	// Перенаправляем на страницу подтверждения
	http.Redirect(w, r, "confirm.html?token="+token, http.StatusSeeOther)
}
func handleLogin(w http.ResponseWriter, r *http.Request) {
	var creds struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	// Декодируем данные из тела запроса
	err := json.NewDecoder(r.Body).Decode(&creds)
	if err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	// Проверяем наличие имени пользователя и пароля
	if creds.Username == "" || creds.Password == "" {
		http.Error(w, "Username and password are required", http.StatusBadRequest)
		return
	}

	var user Person
	// Получаем пользователя из базы данных
	err = db.QueryRow(
		"SELECT id, username, password, email, role_id, is_verified FROM users WHERE username = $1",
		creds.Username,
	).Scan(&user.ID, &user.UserName, &user.Password, &user.Email, &user.RoleID, &user.IsVerified)

	// Проверяем, найден ли пользователь и совпадает ли пароль
	if err == sql.ErrNoRows || bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(creds.Password)) != nil {
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	// Проверяем, подтвержден ли пользователь
	if !user.IsVerified {
		http.Error(w, "Your account is not verified. Please check your email.", http.StatusForbidden)
		return
	}

	// Сохраняем информацию в сессии
	session, _ := store.Get(r, "session")
	session.Values["authenticated"] = true
	session.Values["username"] = user.UserName
	session.Values["role_id"] = int(user.RoleID.Int32) // Преобразование sql.NullInt32 в int
	session.Values["is_verified"] = user.IsVerified
	session.Save(r, w)

	// Определяем URL для перенаправления
	redirectURL := "/"
	if user.RoleID.Int32 == 1 {
		redirectURL = "/admin" // Для администратора
	} else if user.RoleID.Int32 == 2 {
		redirectURL = "/home" // Для пользователя
	}

	// Возвращаем успешный JSON-ответ
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"message":      "Login successful",
		"redirect_url": redirectURL,
	})
}

// Генерация токена
func generateToken() string {
	return base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%d:%s", time.Now().UnixNano(), "secret-key")))
}

// Функция для обновления пользователя
func updatePerson(w http.ResponseWriter, r *http.Request, id string) {
	var person Person
	err := json.NewDecoder(r.Body).Decode(&person)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Если новый пароль предоставлен, хэшируем его
	if person.Password != "" {
		hashedPassword, err := hashPassword(person.Password)
		if err != nil {
			http.Error(w, fmt.Sprintf("Error hashing password: %v", err), http.StatusInternalServerError)
			return
		}
		person.Password = hashedPassword
	}

	// Обновление пользователя в базе данных
	_, err = db.Exec("UPDATE users SET username=$1, password=$2, email=$3, role_id=$4 WHERE id=$5",
		person.UserName, person.Password, person.Email, person.RoleID, id) // Добавляем role_id в запрос
	if err != nil {
		http.Error(w, fmt.Sprintf("Error updating user: %v", err), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "User updated successfully")
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

// Функция обрабатывает HTTP-запросы (вызывает getMenu для получения данных о меню
// и вызывает postMenuItem для добавления новых позиций в меню)
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

// Функция обрабатывает запрос на получения списка меню
// с поддержкой фильтрации, сортировки и пагинации
func getMenu(w http.ResponseWriter, r *http.Request) {
	nameFilter := r.URL.Query().Get("nameFilter")
	priceFilter := r.URL.Query().Get("priceFilter")
	sort := r.URL.Query().Get("sort")
	page := getCurrentPage(r)
	// Параметры пагинации - количество записей на одной странице
	// и смещение для SQL-запроса на основе текущей страницы
	pageSize := 3
	offset := (page - 1) * pageSize

	// Setup for SQL-query
	query := "SELECT id, name, category, price, photo FROM menu"
	whereClauses := []string{}
	args := []interface{}{}
	argIdx := 1

	// Фильтрация на основе имени продукта
	if nameFilter != "" {
		// Сравнение наименования блюд без учета регистра
		whereClauses = append(whereClauses, fmt.Sprintf("LOWER(name) LIKE LOWER($%d)", argIdx))
		// Идет поиск подстроки для нахождения определенной последовательности символов
		args = append(args, "%"+nameFilter+"%")
		argIdx++
	}

	// Фильтрация на основе цены продукта
	if priceFilter != "" {
		// Преобразование значения в число
		if price, err := strconv.ParseFloat(priceFilter, 64); err == nil {
			whereClauses = append(whereClauses, fmt.Sprintf("price <= $%d", argIdx))
			args = append(args, price)
			argIdx++
		}
	}

	// Если есть условия для фильтрации, то они объединяются и добавляются в запрос
	if len(whereClauses) > 0 {
		query += " WHERE " + strings.Join(whereClauses, " AND ")
	}

	// Сортировка блюд по умолчанию, по имени, по цене(по возрастанию и убыванию)
	if sort == "name" || sort == "price_asc" || sort == "price_desc" {
		var orderBy string
		switch sort {
		case "name":
			orderBy = "name"
		case "price_asc":
			orderBy = "price ASC"
		case "price_desc":
			orderBy = "price DESC"
		default:
			orderBy = "id"
		}
		query += fmt.Sprintf(" ORDER BY %s", orderBy)
	}

	// Задействование пагинации, где идет ограничение количества записей и установления смещения
	query += fmt.Sprintf(" LIMIT $%d OFFSET $%d", argIdx, argIdx+1)
	args = append(args, pageSize, offset)

	// Выполнение запроса с подготовленнными аргументами
	rows, err := db.Query(query, args...)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	// Обрабатывает SQL-запросы в строки и добавляет их в массив для дальнейшей работы
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

	// Вычисление общего количества страниц для составления пагинации
	// и генерация массива номеров страниц
	totalPages := calculateTotalPages()
	pages := generatePages(totalPages)

	// JSON-ответ
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(struct {
		MenuItems   []MenuItem `json:"menuItems"`
		TotalPages  int        `json:"totalPages"`
		CurrentPage int        `json:"currentPage"`
		Pages       []int      `json:"pages"`
	}{menuItems, totalPages, page, pages})
}

// Функция для обработки POST-запроса и добавления новых позиций в меню
func postMenuItem(w http.ResponseWriter, r *http.Request) {
	// Чтение JSON-запроса,
	// где в переменную menuItem сохраняются данные о новых блюдах,
	// преобразуя сам запрос в объект
	var menuItem MenuItem
	err := json.NewDecoder(r.Body).Decode(&menuItem)
	if err != nil {
		http.Error(w, fmt.Sprintf("Invalid JSON format: %v", err), http.StatusBadRequest)
		return
	}

	// Валидация данных
	if menuItem.Name == "" || menuItem.Category == "" || menuItem.Price <= 0 {
		http.Error(w, "Missing required fields", http.StatusBadRequest)
		return
	}

	// Добавление в базу данных
	_, err = db.Exec("INSERT INTO menu (name, category, price, photo) VALUES ($1, $2, $3, $4)", menuItem.Name, menuItem.Category, menuItem.Price, menuItem.Photo)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error inserting into database: %v", err), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	fmt.Fprintf(w, "Menu item created successfully")
}

// Функция для определения текущей страницы для пагинации
func getCurrentPage(r *http.Request) int {
	pageStr := r.URL.Query().Get("page")
	if page, err := strconv.Atoi(pageStr); err == nil && page > 0 {
		return page
	}
	return 1
}

// Функция для вычисления общего количества страниц
// где идет подсчет записей в SQL-таблице и дальнейшее вычисление страниц
func calculateTotalPages() int {
	var totalItems int
	db.QueryRow("SELECT COUNT(*) FROM menu").Scan(&totalItems)
	return (totalItems + 3 - 1) / 3 // 3 - размер страницы по умолчанию
}

// Функция для генерации страниц с учетом массива totalPages
func generatePages(totalPages int) []int {
	pages := make([]int, totalPages)
	for i := 0; i < totalPages; i++ {
		pages[i] = i + 1
	}
	return pages
}

func healthCheckHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintln(w, "OK")
}

func sendEmailHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	r.ParseMultipartForm(10 << 20) // Ограничение размера формы до 10 MB

	to := r.FormValue("to")
	subject := r.FormValue("subject")
	body := r.FormValue("body")

	// Создаем границу (boundary) для MIME-сообщения
	boundary := "my-boundary-123"
	var emailBuffer bytes.Buffer

	// Добавляем заголовки MIME-сообщения
	emailBuffer.WriteString("From: mamyrbeksanat282@gmail.com\r\n")
	emailBuffer.WriteString("To: " + to + "\r\n")
	emailBuffer.WriteString("Subject: " + subject + "\r\n")
	emailBuffer.WriteString("MIME-Version: 1.0\r\n")
	emailBuffer.WriteString("Content-Type: multipart/mixed; boundary=" + boundary + "\r\n")
	emailBuffer.WriteString("\r\n")

	// Добавляем тело письма как часть
	emailBuffer.WriteString("--" + boundary + "\r\n")
	emailBuffer.WriteString("Content-Type: text/plain; charset=\"utf-8\"\r\n")
	emailBuffer.WriteString("\r\n")
	emailBuffer.WriteString(body + "\r\n")
	emailBuffer.WriteString("\r\n")

	// Проверяем наличие файла
	file, handler, err := r.FormFile("file")
	if err == nil {
		defer file.Close()

		// Читаем содержимое файла
		fileBytes, err := io.ReadAll(file)
		if err != nil {
			http.Error(w, "Error reading file: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// Добавляем файл как вложение
		emailBuffer.WriteString("--" + boundary + "\r\n")
		emailBuffer.WriteString("Content-Type: application/octet-stream\r\n")
		emailBuffer.WriteString("Content-Disposition: attachment; filename=\"" + handler.Filename + "\"\r\n")
		emailBuffer.WriteString("Content-Transfer-Encoding: base64\r\n")
		emailBuffer.WriteString("\r\n")
		emailBuffer.WriteString(encodeToBase64(fileBytes) + "\r\n")
		emailBuffer.WriteString("\r\n")
	}

	// Завершаем MIME-сообщение
	emailBuffer.WriteString("--" + boundary + "--")

	// Настройки SMTP
	smtpHost := "smtp.gmail.com"
	smtpPort := "587"
	senderEmail := "mamyrbeksanat282@gmail.com"
	password := "negl phgr aanr jxen"

	// Авторизация
	auth := smtp.PlainAuth("", senderEmail, password, smtpHost)

	// Отправляем письмо
	err = smtp.SendMail(smtpHost+":"+smtpPort, auth, senderEmail, []string{to}, emailBuffer.Bytes())
	if err != nil {
		http.Error(w, "Failed to send email: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Возвращаем успешный ответ
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"message":"Email sent successfully"}`))
}

// Вспомогательная функция для кодирования в base64
func encodeToBase64(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

func fetchMenuDataFromAPI() {
	// Проверяем, есть ли записи в таблице menu
	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM menu").Scan(&count)
	if err != nil {
		log.Fatalf("Ошибка при проверке записей в таблице menu: %v", err)
	}

	if count > 0 {
		log.Println("Данные в таблице menu уже существуют. Заполнение пропущено.")
		return
	}

	// Запрос к API
	apiURL := "https://dummyjson.com/products"
	response, err := http.Get(apiURL)
	if err != nil {
		log.Fatalf("Ошибка при запросе к API: %v", err)
	}
	defer response.Body.Close()

	// Структура для парсинга ответа API
	var result struct {
		Products []struct {
			Title     string  `json:"title"`
			Category  string  `json:"category"`
			Price     float64 `json:"price"`
			Thumbnail string  `json:"thumbnail"`
		} `json:"products"`
	}

	// Декодирование JSON-ответа
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		log.Fatalf("Ошибка при декодировании ответа API: %v", err)
	}

	// Проверка и добавление данных в таблицу menu
	for _, product := range result.Products {
		category := mapCategory(product.Title, product.Category)

		if isFoodOrDrink(category) {
			_, err := db.Exec(
				"INSERT INTO menu (name, category, price, photo, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6)",
				product.Title, category, product.Price, product.Thumbnail, time.Now(), time.Now(),
			)
			if err != nil {
				log.Printf("Ошибка при добавлении записи в базу: %v", err)
			} else {
				log.Printf("Добавлено в меню: %s | Категория: %s", product.Title, category)
			}
		}
	}
}

func isFoodOrDrink(category string) bool {
	foodCategories := []string{"groceries", "beverages", "desserts", "snacks", "fruits", "meat"}

	for _, food := range foodCategories {
		if category == food {
			return true
		}
	}
	return false
}

func mapCategory(title string, category string) string {
	switch title {
	case "Apple":
		return "fruits"
	case "Beef Steak", "Chicken Meat":
		return "meat"
	case "Ice Cream":
		return "desserts"
	case "Juice":
		return "beverages"
	default:
		return category
	}
}

func logRequestToFile(r *http.Request, status int) {
	logFile, err := os.OpenFile("server.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		logger.WithError(err).Error("Failed to open log file")
		return
	}
	defer logFile.Close()
	logEntry := fmt.Sprintf("%s | Method: %s | URL: %s | RemoteAddr: %s | Status: %d\n",
		time.Now().Format(time.RFC3339), r.Method, r.URL.String(), r.RemoteAddr, status)

	if _, err := logFile.WriteString(logEntry); err != nil {
		logger.WithError(err).Error("Failed to write to log file")
	}
}
func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		status := http.StatusOK
		defer logRequestToFile(r, status)

		next.ServeHTTP(w, r)
	})
}

var store = sessions.NewCookieStore([]byte("a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6a7b8c9"))

func loginHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		http.ServeFile(w, r, "login.html") // Возвращает HTML-страницу для входа
	case http.MethodPost:
		handleLogin(w, r) // Обрабатывает POST-запрос для входа
	default:
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
	}
}

func hashPassword(password string) (string, error) {
	// Генерация хэша пароля
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

func updatePasswords() {
	rows, err := db.Query("SELECT id, password FROM users")
	if err != nil {
		log.Fatalf("Ошибка при получении пользователей: %v", err)
	}
	defer rows.Close()

	for rows.Next() {
		var id int
		var password string

		// Считываем текущие пароли
		err := rows.Scan(&id, &password)
		if err != nil {
			log.Printf("Ошибка чтения строки: %v", err)
			continue
		}

		// Пропускаем уже хэшированные пароли (если они в формате bcrypt)
		if len(password) > 0 && password[0] == '$' {
			continue
		}

		// Хэшируем пароль
		hashedPassword, err := hashPassword(password)
		if err != nil {
			log.Printf("Ошибка хэширования пароля для пользователя с ID %d: %v", id, err)
			continue
		}

		// Обновляем пароль в базе данных
		_, err = db.Exec("UPDATE users SET password = $1 WHERE id = $2", hashedPassword, id)
		if err != nil {
			log.Printf("Ошибка обновления пароля для пользователя с ID %d: %v", id, err)
		} else {
			fmt.Printf("Пароль для пользователя с ID %d успешно обновлен.\n", id)
		}
	}

	// Проверка на ошибки в процессе перебора строк
	if err = rows.Err(); err != nil {
		log.Printf("Ошибка обработки строк: %v", err)
	}
}

func resendHandler(w http.ResponseWriter, r *http.Request) {
	email := r.URL.Query().Get("email")
	if email == "" {
		http.Error(w, "Email is required", http.StatusBadRequest)
		return
	}

	// Получаем токен подтверждения для пользователя
	var token string
	err := db.QueryRow("SELECT verification_token FROM users WHERE email = $1 AND is_verified = FALSE", email).Scan(&token)
	if err == sql.ErrNoRows {
		http.Error(w, "No unverified account found for this email", http.StatusNotFound)
		return
	} else if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Отправляем подтверждающее письмо
	go sendVerificationEmail(email, token)

	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "Verification email resent to %s", email)
}

func checkVerificationStatusHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session")
	username, ok := session.Values["username"].(string)
	authenticated := session.Values["authenticated"]

	if ok && authenticated == true {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"is_verified": true,
			"username":    username,
		})
	} else {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"is_verified": false,
		})
	}
}
func adminMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, _ := store.Get(r, "session")
		authenticated, ok := session.Values["authenticated"].(bool)
		roleID, roleOk := session.Values["role_id"].(int)

		// Проверка аутентификации
		if !ok || !authenticated {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		// Проверка роли администратора
		if !roleOk || roleID != 1 {
			http.Redirect(w, r, "/home", http.StatusSeeOther)
			return
		}

		// Логирование доступа
		logger.WithFields(logrus.Fields{
			"username": session.Values["username"],
			"role_id":  roleID,
			"path":     r.URL.Path,
		}).Info("Admin access granted")

		next.ServeHTTP(w, r)
	}
}
