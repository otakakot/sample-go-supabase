package main

import (
	"cmp"
	"context"
	_ "embed"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/supabase-community/gotrue-go"
)

func main() {
	port := cmp.Or(os.Getenv("PORT"), "8080")

	hdl := http.NewServeMux()

	hdl.HandleFunc("/", LoginHandler)

	srv := &http.Server{
		Addr:              fmt.Sprintf(":%s", port),
		Handler:           hdl,
		ReadHeaderTimeout: 30 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)

	defer stop()

	go func() {
		slog.Info("start server listen")

		if err := srv.ListenAndServe(); err != nil && errors.Is(err, http.ErrServerClosed) {
			panic(err)
		}
	}()

	<-ctx.Done()

	slog.Info("start server shutdown")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)

	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		panic(err)
	}

	slog.Info("done server shutdown")
}

// const sessionkey = "__session__"

const view = `<!DOCTYPE html>
<html lang="en">

<head>
    <title>Login</title>
</head>

<body>
    <form method="POST" action="/">
        <label for="email">Email</label>
        <input type="email" name="email" id="email">

        <label for="password">Password</label>
        <input type="password" name="password" id="password">

        <button type="submit">Login</button>
    </form>
</body>

</html>
`

func LoginHandler(
	rw http.ResponseWriter,
	req *http.Request,
) {
	switch req.Method {
	case http.MethodGet:
		session, err := req.Cookie("__session__")
		if err != nil {
			rw.Write([]byte(view))

			return
		}

		projectReference := os.Getenv("SUPABASE_PROJECT_REFERENCE")
		if projectReference == "" {
			http.Error(rw, "SUPABASE_PROJECT_REFERENCE is required", http.StatusInternalServerError)

			return
		}

		apiKey := os.Getenv("SUPABASE_API_KEY")
		if apiKey == "" {
			http.Error(rw, "SUPABASE_API_KEY is required", http.StatusInternalServerError)

			return
		}

		cli := gotrue.New(projectReference, apiKey)

		res, err := cli.RefreshToken(session.Value)
		if err != nil {
			http.Error(rw, err.Error(), http.StatusUnauthorized)

			return
		}

		cookie := &http.Cookie{
			Name:     "__session__",
			Value:    res.RefreshToken,
			Expires:  time.Now().Add(24 * time.Hour * 180),
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteStrictMode,
			Domain:   req.Host,
		}

		http.SetCookie(rw, cookie)

		fmt.Fprintf(rw, "res: %+v", res)

		return
	case http.MethodPost:
		projectReference := os.Getenv("SUPABASE_PROJECT_REFERENCE")
		if projectReference == "" {
			http.Error(rw, "SUPABASE_PROJECT_REFERENCE is required", http.StatusInternalServerError)

			return
		}

		apiKey := os.Getenv("SUPABASE_API_KEY")
		if apiKey == "" {
			http.Error(rw, "SUPABASE_API_KEY is required", http.StatusInternalServerError)

			return
		}

		email := req.FormValue("email")

		password := req.FormValue("password")

		cli := gotrue.New(projectReference, apiKey)

		res, err := cli.SignInWithEmailPassword(email, password)
		if err != nil {
			http.Error(rw, err.Error(), http.StatusUnauthorized)

			return
		}

		cookie := &http.Cookie{
			Name:     "__session__",
			Value:    res.RefreshToken,
			Expires:  time.Now().Add(24 * time.Hour * 180),
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteStrictMode,
			Domain:   req.Host,
		}

		http.SetCookie(rw, cookie)

		fmt.Fprintf(rw, "%+v", res)
	default:
		http.Error(rw, "Method Not Allowed", http.StatusMethodNotAllowed)

		return
	}
}
