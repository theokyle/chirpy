package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
	"github.com/theokyle/chirpy/internal/auth"
	"github.com/theokyle/chirpy/internal/database"
)

type apiConfig struct {
	fileserverHits atomic.Int32
	db             *database.Queries
	platform       string
	jwt_secret     string
	polka_key      string
}

func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg.fileserverHits.Add(1)
		next.ServeHTTP(w, r)
	})
}

func (cfg *apiConfig) getMetricsHandler(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	str := fmt.Sprintf(`
<html>
  <body>
    <h1>Welcome, Chirpy Admin</h1>
    <p>Chirpy has been visited %d times!</p>
  </body>
</html>`, cfg.fileserverHits.Load())
	w.Write([]byte(str))
}

func (cfg *apiConfig) resetHandler() {
	cfg.fileserverHits.Store(0)
}

func main() {
	const port = "8080"
	godotenv.Load()
	dbURL := os.Getenv("DB_URL")
	platform := os.Getenv("PLATFORM")
	jwt_secret := os.Getenv("JWT_SECRET")
	polka_key := os.Getenv("POLKA_KEY")
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		fmt.Printf("Error loading database")
		os.Exit(1)
	}
	dbQueries := database.New(db)

	mux := http.NewServeMux()

	srv := &http.Server{
		Addr:    ":" + port,
		Handler: mux,
	}

	apiCfg := apiConfig{
		db:         dbQueries,
		platform:   platform,
		jwt_secret: jwt_secret,
		polka_key:  polka_key,
	}

	type User struct {
		ID        uuid.UUID `json:"id"`
		CreatedAt time.Time `json:"created_at"`
		UpdatedAt time.Time `json:"updated_at"`
		Email     string    `json:"email"`
	}

	type Chirp struct {
		ID        uuid.UUID `json:"id"`
		CreatedAt time.Time `json:"created_at"`
		UpdatedAt time.Time `json:"updated_at"`
		Body      string    `json:"body"`
		UserId    uuid.UUID `json:"user_id"`
	}

	mux.Handle("/app/", apiCfg.middlewareMetricsInc(http.StripPrefix("/app", http.FileServer(http.Dir('.')))))
	mux.HandleFunc("GET /api/healthz", func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})
	mux.HandleFunc("GET /admin/metrics", func(w http.ResponseWriter, req *http.Request) {
		apiCfg.getMetricsHandler(w, req)
	})
	mux.HandleFunc("POST /admin/reset", func(w http.ResponseWriter, req *http.Request) {
		if apiCfg.platform == "dev" {
			apiCfg.resetHandler()
			apiCfg.db.DeleteUsers(req.Context())
			apiCfg.db.DeleteChirps(req.Context())
			w.WriteHeader(200)
		} else {
			w.WriteHeader(http.StatusForbidden)
		}
	})

	mux.HandleFunc("POST /api/users", func(w http.ResponseWriter, req *http.Request) {
		type parameters struct {
			Email    string `json:"email"`
			Password string `json:"password"`
		}

		decoder := json.NewDecoder(req.Body)
		params := parameters{}
		err := decoder.Decode(&params)
		if err != nil {
			fmt.Printf("Error decoding params: %s", err)
			w.WriteHeader(400)
			return
		}

		hashed_password, err := auth.HashPassword(params.Password)
		if err != nil {
			fmt.Printf("Error hashing password: %s", err)
			w.WriteHeader(400)
			return
		}

		create_user_params := database.CreateUserParams{
			Email:          params.Email,
			HashedPassword: hashed_password,
		}

		user_sql, err := apiCfg.db.CreateUser(req.Context(), create_user_params)
		if err != nil {
			fmt.Printf("Error creating user: %s", err)
			w.WriteHeader(400)
			return
		}

		user := database.User{
			ID:          user_sql.ID,
			CreatedAt:   user_sql.CreatedAt,
			UpdatedAt:   user_sql.UpdatedAt,
			Email:       user_sql.Email,
			IsChirpyRed: user_sql.IsChirpyRed,
		}

		w.Header().Set("Content-type", "application/json")
		dat, err := json.Marshal(user)
		if err != nil {
			fmt.Printf("Error marshalling json: %s", err)
		}
		w.WriteHeader(201)
		w.Write(dat)
	})
	mux.HandleFunc("POST /api/login", func(w http.ResponseWriter, r *http.Request) {
		type parameters struct {
			Password string `json:"password"`
			Email    string `json:"email"`
		}
		type response struct {
			ID           uuid.UUID `json:"id"`
			CreatedAt    time.Time `json:"created_at"`
			UpdatedAt    time.Time `json:"updated_at"`
			Email        string    `json:"email"`
			IsChirpyRed  bool      `json:"is_chirpy_red"`
			Token        string    `json:"token"`
			RefreshToken string    `json:"refresh_token"`
		}

		decoder := json.NewDecoder(r.Body)
		params := parameters{}
		err := decoder.Decode(&params)
		if err != nil {
			fmt.Printf("Error decoding params: %s", err)
			w.WriteHeader(400)
			return
		}

		user, err := apiCfg.db.GetUser(r.Context(), params.Email)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("incorrect email or password"))
			return
		}

		err = auth.CheckPasswordHash(user.HashedPassword, params.Password)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("incorrect email or password"))
			return
		}

		expirationTime := time.Hour

		accessToken, err := auth.MakeJWT(
			user.ID,
			apiCfg.jwt_secret,
			expirationTime,
		)
		if err != nil {
			w.WriteHeader(400)
			return
		}

		refresh_token, _ := auth.MakeRefreshToken()
		create_refresh_token_params := database.CreateRefreshTokenParams{
			Token:     refresh_token,
			UserID:    user.ID,
			ExpiresAt: time.Now().Add(1440 * time.Hour),
		}
		_, err = apiCfg.db.CreateRefreshToken(r.Context(), create_refresh_token_params)
		if err != nil {
			w.WriteHeader(400)
			w.Write([]byte("unable to generate refresh token"))
			return
		}

		user_resp := response{
			ID:           user.ID,
			CreatedAt:    user.CreatedAt,
			UpdatedAt:    user.UpdatedAt,
			Email:        user.Email,
			IsChirpyRed:  user.IsChirpyRed,
			Token:        accessToken,
			RefreshToken: refresh_token,
		}

		dat, err := json.Marshal(user_resp)
		if err != nil {
			w.WriteHeader(400)
			return
		}

		w.WriteHeader(200)
		w.Write(dat)
	})

	mux.HandleFunc("POST /api/refresh", func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			w.WriteHeader(401)
			return
		}

		auth_slice := strings.Split(authHeader, " ")
		if auth_slice[0] != "Bearer" || len(auth_slice) < 2 {
			w.WriteHeader(401)
			return
		}

		refresh_token, err := apiCfg.db.GetUserFromRefreshToken(r.Context(), auth_slice[1])
		if err != nil {
			w.WriteHeader(401)
			return
		}

		if time.Now().After(refresh_token.ExpiresAt) || refresh_token.RevokedAt.Valid {
			w.WriteHeader(401)
			return
		}

		expirationTime := time.Hour

		accessToken, err := auth.MakeJWT(
			refresh_token.UserID,
			apiCfg.jwt_secret,
			expirationTime,
		)
		if err != nil {
			w.WriteHeader(400)
			return
		}

		type response struct {
			Token string `json:"token"`
		}

		resp := response{
			Token: accessToken,
		}

		dat, err := json.Marshal(resp)
		if err != nil {
			w.WriteHeader(400)
			return
		}

		w.WriteHeader(200)
		w.Write(dat)
	})

	mux.HandleFunc("PUT /api/users", func(w http.ResponseWriter, r *http.Request) {
		type parameters struct {
			Password string `json:"password"`
			Email    string `json:"email"`
		}

		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			w.WriteHeader(401)
			return
		}

		auth_slice := strings.Split(authHeader, " ")
		if auth_slice[0] != "Bearer" || len(auth_slice) < 2 {
			w.WriteHeader(401)
			return
		}

		access_token := auth_slice[1]
		user_id, err := auth.ValidateJWT(access_token, apiCfg.jwt_secret)
		if err != nil {
			w.WriteHeader(401)
			return
		}

		decoder := json.NewDecoder(r.Body)
		params := parameters{}
		err = decoder.Decode(&params)
		if err != nil {
			fmt.Printf("Error decoding params: %s", err)
			w.WriteHeader(400)
			return
		}

		hashed_password, err := auth.HashPassword(params.Password)
		if err != nil {
			fmt.Printf("Error hashing password: %s", err)
			w.WriteHeader(400)
			return
		}

		update_user_params := database.UpdateUserParams{
			Email:          params.Email,
			HashedPassword: hashed_password,
			ID:             user_id,
		}

		updated_user, err := apiCfg.db.UpdateUser(r.Context(), update_user_params)
		if err != nil {
			fmt.Printf("Error updating user: %s", err)
			w.WriteHeader(400)
			return
		}

		data, err := json.Marshal(updated_user)
		if err != nil {
			fmt.Printf("Error marshalling data: %s", err)
			w.WriteHeader(400)
			return
		}

		w.WriteHeader(200)
		w.Write(data)
	})

	mux.HandleFunc("DELETE /api/chirps/{chirpId}", func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			w.WriteHeader(401)
			return
		}

		auth_slice := strings.Split(authHeader, " ")
		if auth_slice[0] != "Bearer" || len(auth_slice) < 2 {
			w.WriteHeader(401)
			return
		}

		access_token := auth_slice[1]
		user_id, err := auth.ValidateJWT(access_token, apiCfg.jwt_secret)
		if err != nil {
			w.WriteHeader(401)
			return
		}

		chirpId, err := uuid.Parse(r.PathValue("chirpId"))
		if err != nil {
			w.WriteHeader(400)
			return
		}
		chirp, err := apiCfg.db.GetChirp(r.Context(), chirpId)
		if err != nil {
			w.WriteHeader(404)
			return
		}

		if chirp.UserID != user_id {
			w.WriteHeader(403)
			return
		}

		err = apiCfg.db.DeleteChirp(r.Context(), chirp.ID)
		if err != nil {
			w.WriteHeader(500)
			return
		}

		w.WriteHeader(204)
	})

	mux.HandleFunc("POST /api/revoke", func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			w.WriteHeader(401)
			return
		}

		auth_slice := strings.Split(authHeader, " ")
		if auth_slice[0] != "Bearer" || len(auth_slice) < 2 {
			w.WriteHeader(401)
			return
		}

		err := apiCfg.db.RevokeToken(r.Context(), auth_slice[1])
		if err != nil {
			w.WriteHeader(401)
			return
		}

		w.WriteHeader(204)
	})

	mux.HandleFunc("POST /api/chirps", func(w http.ResponseWriter, req *http.Request) {
		type parameters struct {
			Body string `json:"body"`
		}

		token, err := auth.GetBearerToken(req.Header)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		userId, err := auth.ValidateJWT(token, apiCfg.jwt_secret)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		decoder := json.NewDecoder(req.Body)
		params := parameters{}
		err = decoder.Decode(&params)
		if err != nil {
			fmt.Printf("Error decoding params: %s", err)
			w.WriteHeader(400)
			return
		}

		if len(params.Body) > 140 {
			fmt.Printf("Chirp is too long")
			w.WriteHeader(400)
			return
		}

		create_chirp_params := database.CreateChirpParams{
			Body:   params.Body,
			UserID: userId,
		}
		chirp_sql, err := apiCfg.db.CreateChirp(req.Context(), create_chirp_params)
		if err != nil {
			fmt.Printf("Error creating chirp: %s", err)
			w.WriteHeader(400)
			return
		}

		chirp := Chirp{
			ID:        chirp_sql.ID,
			CreatedAt: chirp_sql.CreatedAt,
			UpdatedAt: chirp_sql.UpdatedAt,
			Body:      chirp_sql.Body,
			UserId:    chirp_sql.UserID,
		}

		w.Header().Set("Content-Type", "application/json")
		dat, err := json.Marshal(chirp)
		if err != nil {
			w.WriteHeader(400)
			return
		}
		w.WriteHeader(201)
		w.Write(dat)
	})

	mux.HandleFunc("GET /api/chirps", func(w http.ResponseWriter, req *http.Request) {
		chirps, err := apiCfg.db.GetAllChirps(req.Context())
		if err != nil {
			fmt.Printf("error - failed to retrieve chirps: %s", err)
			w.WriteHeader(400)
			return
		}

		w.Header().Set("Content-type", "application/json")
		dat, err := json.Marshal(chirps)
		if err != nil {
			w.WriteHeader(400)
			return
		}
		w.WriteHeader(200)
		w.Write(dat)
	})

	mux.HandleFunc("GET /api/chirps/{chirpId}", func(w http.ResponseWriter, r *http.Request) {
		chirpId, err := uuid.Parse(r.PathValue("chirpId"))
		if err != nil {
			w.WriteHeader(400)
			return
		}
		chirp, err := apiCfg.db.GetChirp(r.Context(), chirpId)
		if err != nil {
			w.WriteHeader(404)
			return
		}

		w.Header().Set("Content-type", "application/json")
		dat, err := json.Marshal(chirp)
		if err != nil {
			w.WriteHeader(400)
			return
		}
		w.WriteHeader(200)
		w.Write(dat)
	})

	mux.HandleFunc("POST /api/polka/webhooks", func(w http.ResponseWriter, r *http.Request) {
		type Data struct {
			UserId string `json:"user_id"`
		}

		type RequestParams struct {
			Event string `json:"event"`
			Data  Data   `json:"data"`
		}

		api_key, err := auth.GetAPIKey(r.Header)
		if err != nil {
			w.WriteHeader(401)
			return
		}

		if api_key != apiCfg.polka_key {
			w.WriteHeader(401)
			return
		}

		request := RequestParams{}
		err = json.NewDecoder(r.Body).Decode(&request)
		if err != nil {
			w.WriteHeader(400)
			return
		}

		if request.Event != "user.upgraded" {
			w.WriteHeader(204)
			return
		}

		user_id, err := uuid.Parse(request.Data.UserId)
		if err != nil {
			w.WriteHeader(400)
			return
		}

		err = apiCfg.db.UpdateChirpyRed(r.Context(), user_id)
		if err != nil {
			w.WriteHeader(404)
		}

		w.WriteHeader(204)
	})

	log.Printf("Serving on port: %s\n", port)
	log.Fatal(srv.ListenAndServe())
}

func clean_string(str string) string {
	filtered_words := [3]string{"kerfuffle", "sharbert", "fornax"}
	str_slice := strings.Split(str, " ")
	for i, word := range str_slice {
		for _, filtered_word := range filtered_words {
			if strings.ToLower(word) == filtered_word {
				str_slice[i] = "****"
			}
		}
	}
	new_string := strings.Join(str_slice, " ")
	return new_string
}
