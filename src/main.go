package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/arnavdugar/google-external-auth/database/mongodb"
	"github.com/arnavdugar/google-external-auth/server"

	"github.com/kelseyhightower/envconfig"
)

type Configuration struct {
	AuthHeader         string        `envconfig:"AUTH_HEADER" required:"true"`
	ClientId           string        `envconfig:"CLIENT_ID" required:"true"`
	ClientSecret       string        `envconfig:"CLIENT_SECRET" required:"true"`
	CookieDomain       string        `envconfig:"COOKIE_DOMAIN" required:"true"`
	CookieDuration     time.Duration `envconfig:"COOKIE_DURATION" required:"true"`
	CookieName         string        `envconfig:"COOKIE_NAME" required:"true"`
	CookieSecret       string        `envconfig:"COOKIE_SECRET" required:"true"`
	DatabaseHost       string        `envconfig:"DB_HOST" required:"true"`
	DatabaseUsername   string        `envconfig:"DB_USERNAME" required:"true"`
	DatabasePassword   string        `envconfig:"DB_PASSWORD" required:"true"`
	DatabaseName       string        `envconfig:"DB_NAME" required:"true"`
	DatabaseCollection string        `envconfig:"DB_COLLECTION" required:"true"`
	Debug              bool          `envconfig:"DEBUG"`
	Domain             *url.URL      `envconfig:"DOMAIN" required:"true"`
	Port               string        `envconfig:"PORT" required:"true"`
}

type Clock struct{}

func (clock Clock) Now() time.Time {
	return time.Now()
}

func main() {
	errorValue := run()
	if errorValue != nil {
		log.Fatal(errorValue)
	}
}

func run() error {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	config := Configuration{}
	err := envconfig.Process("", &config)
	if err != nil {
		return err
	}

	database, err := mongodb.Create(&mongodb.Options{
		Username:   config.DatabaseUsername,
		Password:   config.DatabasePassword,
		Host:       config.DatabaseHost,
		Database:   config.DatabaseName,
		Collection: config.DatabaseCollection,
	}, context.Background())
	if err != nil {
		return err
	}

	server := &http.Server{
		Addr: fmt.Sprintf(":%s", config.Port),
		Handler: &server.Server{
			AuthHeader:     config.AuthHeader,
			ClientId:       config.ClientId,
			ClientSecret:   config.ClientSecret,
			Clock:          Clock{},
			CookieDomain:   config.CookieDomain,
			CookieDuration: config.CookieDuration,
			CookieName:     config.CookieName,
			CookieSecret:   []byte(config.CookieSecret),
			Database:       database,
			Domain:         config.Domain,
			HttpClient:     http.DefaultClient,
		},
	}

	serverError := make(chan error, 1)
	serverDone := make(chan os.Signal, 1)
	signal.Notify(serverDone, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

	log.Printf("Starting server on port %s.\n", config.Port)

	go func() {
		serverError <- server.ListenAndServe()
	}()

	select {
	case err = <-serverError:
		return err
	case <-serverDone:
		break
	}

	log.Println("Shutting down.")

	shutdownContext, cancel :=
		context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err = server.Shutdown(shutdownContext)
	if err != nil {
		return err
	}
	return nil
}
