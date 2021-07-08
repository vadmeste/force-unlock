package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"time"

	jwtgo "github.com/dgrijalva/jwt-go"
	"github.com/minio/minio/pkg/madmin"
)

var resource string
var alias string
var customMCDir string

var endpoint string
var accessKey string
var secretKey string

func init() {
	flag.StringVar(&alias, "alias", "", "Alias name defined in .mc/config.json (mandatory)")
	flag.StringVar(&resource, "resource", "", "Resource name that you want to unlock, e.g: testbucket/testobject (mandatory)")
	flag.StringVar(&customMCDir, "custom-mc-dir", "", "Path where mc config directory lives (optional)")
}

type aliasInfo struct {
	URL       string `json:"url"`
	AccessKey string `json:"accessKey"`
	SecretKey string `json:"secretKey"`
}

type mcConfig struct {
	Aliases map[string]aliasInfo `json:"aliases"`
}

// StandardClaims are basically standard claims with "accessKey"
type StandardClaims struct {
	AccessKey string `json:"accessKey,omitempty"`
	jwtgo.StandardClaims
}

// MapClaims - implements custom unmarshaller
type MapClaims struct {
	AccessKey string `json:"accessKey,omitempty"`
	jwtgo.MapClaims
}

// NewStandardClaims - initializes standard claims
func NewStandardClaims() *StandardClaims {
	return &StandardClaims{}
}

// SetIssuer sets issuer for these claims
func (c *StandardClaims) SetIssuer(issuer string) {
	c.Issuer = issuer
}

// SetAudience sets audience for these claims
func (c *StandardClaims) SetAudience(aud string) {
	c.Audience = aud
}

// SetExpiry sets expiry in unix epoch secs
func (c *StandardClaims) SetExpiry(t time.Time) {
	c.ExpiresAt = t.Unix()
}

// SetAccessKey sets access key as jwt subject and custom
// "accessKey" field.
func (c *StandardClaims) SetAccessKey(accessKey string) {
	c.Subject = accessKey
	c.AccessKey = accessKey
}

// Valid - implements https://godoc.org/github.com/dgrijalva/jwt-go#Claims compatible
// claims interface, additionally validates "accessKey" fields.
func (c *StandardClaims) Valid() error {
	if err := c.StandardClaims.Valid(); err != nil {
		return err
	}

	if c.AccessKey == "" && c.Subject == "" {
		return jwtgo.NewValidationError("accessKey/sub missing",
			jwtgo.ValidationErrorClaimsInvalid)
	}

	return nil
}

func getNodeToken(accessKey, secretKey, audience string) (string, error) {
	claims := NewStandardClaims()
	claims.SetExpiry(time.Now().UTC().Add(time.Hour))
	claims.SetAccessKey(accessKey)
	claims.SetAudience(audience)

	jwt := jwtgo.NewWithClaims(jwtgo.SigningMethodHS512, claims)
	return jwt.SignedString([]byte(secretKey))
}

var customTransport = &http.Transport{
	TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
}

func main() {
	flag.Parse()

	if alias == "" || resource == "" {
		flag.Usage()
		fmt.Println("")
		fmt.Printf("EXAMPLE:\n")
		fmt.Printf("   %s --alias play --resource testbucket/testobject\n", os.Args[0])
		os.Exit(-1)
	}

	var configPath string

	if customMCDir != "" {
		configPath = path.Join(customMCDir, "config.json")
	} else {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			log.Fatal("Unable to find the home directory:", err)
		}
		configPath = path.Join(homeDir, ".mc", "config.json")
	}

	configData, err := ioutil.ReadFile(configPath)
	if err != nil {
		log.Fatal("Unable to read", configPath, ":", err)
	}

	var config mcConfig

	err = json.Unmarshal(configData, &config)
	if err != nil {
		log.Fatal("Unable to parse the mc config file", configPath, ":", err)
	}

	aliasConfig, ok := config.Aliases[alias]
	if !ok {
		log.Fatal("Unable to find the alias", alias, "in", configPath)
	}

	u, err := url.Parse(aliasConfig.URL)
	if err != nil {
		log.Fatal("Unable to parse the URL", aliasConfig.URL, ":", err)
	}

	madmClnt, err := madmin.New(u.Host, aliasConfig.AccessKey, aliasConfig.SecretKey, strings.ToLower(u.Scheme) == "https")
	if err != nil {
		log.Fatalln(err)
	}

	madmClnt.SetCustomTransport(customTransport)

	info, err := madmClnt.ServerInfo(context.Background())
	if err != nil {
		log.Fatalln(err)
	}

	var endpoints []string
	for _, server := range info.Servers {
		for _, d := range server.Disks {
			if d.DrivePath != "" {
				endpoints = append(endpoints,
					strings.ToLower(u.Scheme)+"://"+server.Endpoint+path.Join("/minio/lock/", d.DrivePath, "/v4/force-unlock"))
			}
		}
	}

	for _, endpoint := range endpoints {

		var buffer bytes.Buffer
		buffer.WriteString(resource)
		buffer.WriteString("\n")

		q := url.Values{}
		q.Add("quorum", "0")
		query := q.Encode()

		url := endpoint + "?" + query
		req, err := http.NewRequest("POST", url, &buffer)
		if err != nil {
			log.Fatal(err)
		}

		token, err := getNodeToken(aliasConfig.AccessKey, aliasConfig.SecretKey, query)
		if err != nil {
			log.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("X-Minio-Time", time.Now().UTC().Format(time.RFC3339))

		client := &http.Client{Transport: customTransport}
		r, err := client.Do(req)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println("Calling", url, "=>", r.Status)
		r.Body.Close()
	}

	log.Println(resource, "unlocked.")
}
