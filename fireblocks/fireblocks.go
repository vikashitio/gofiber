package fireblocks

import (
	"bytes"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"template/models"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/session"
	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
)

// func init() {
// 	privateKeyPath := "./fireblocks_secret.key"
// 	apiKey := "053c5036-525b-41fd-af32-2cf9776be07c"
// 	tokenProvider, err := NewApiTokenProvider(privateKeyPath, apiKey)
// 	if err != nil {
// 		fmt.Printf("Error initializing token provider: %v\n", err)
// 		return
// 	}

// }
var store = session.New()

type ApiTokenProvider struct {
	privateKey *rsa.PrivateKey
	apiKey     string
}

func UsersView(c *fiber.Ctx) error {

	// check session
	s, _ := store.Get(c)
	// Get value
	LoginMerchantID := s.Get("LoginMerchantID")
	fmt.Println("==>", LoginMerchantID)

	privateKeyPath := "./fireblocks_secret.key"
	apiKey := "053c5036-525b-41fd-af32-2cf9776be07c" //API user: vikash API
	tokenProvider, err := NewApiTokenProvider(privateKeyPath, apiKey)
	if err != nil {
		fmt.Printf("Error initializing token provider: %v\n", err)
		//return
	}

	// Example API calls
	// Ensure functions getAccountsPaged and createAccount are correctly defined to use this main function.

	path := "/v1/users"
	respBody, err := MakeAPIRequest("GET", path, nil, tokenProvider)
	if err != nil {
		return fmt.Errorf("error making GET request to accounts_paged: %w", err)
	}

	//var DataList = string(respBody)
	//fmt.Println("======", DataList)
	//////////////////////////

	// Parse the JSON data into the struct
	var fireblocksData []models.FireblocksUsers
	if err := json.Unmarshal([]byte(respBody), &fireblocksData); err != nil {
		fmt.Println(err)
	}

	//fmt.Println(fireblocksData)
	return c.Render("fireblocks-users", fiber.Map{
		"Title":    "Fire Blocked User List",
		"Subtitle": "User List",
		//"LoginHistory": loginHistory,
		"Data": fireblocksData,
	})
}

func CreateVaultWallet(c *fiber.Ctx) error {

	VID := c.FormValue("VID")
	WID := c.FormValue("WID")

	//fmt.Println(VID, WID)

	// check session
	s, err := store.Get(c)
	if err != nil {
		panic(err)
	}
	// Get value

	privateKeyPath := "./fireblocks_secret.key"
	apiKey := "053c5036-525b-41fd-af32-2cf9776be07c"
	tokenProvider, err := NewApiTokenProvider(privateKeyPath, apiKey)
	if err != nil {
		fmt.Println("Error")
	}
	path := "/v1/vault/accounts/" + VID + "/" + WID
	//fmt.Println("======", path)
	respBody, err := MakeAPIRequest("POST", path, nil, tokenProvider)
	if err != nil {
		fmt.Println(err)
	}

	//var DataList = string(respBody)
	//fmt.Println("======", DataList)

	//FireblocksWallet
	var fireblocksData models.FireblocksWallet
	if err := json.Unmarshal([]byte(respBody), &fireblocksData); err != nil {
		fmt.Println(err)
	}

	fmt.Println("======", fireblocksData.Message)
	s.Set("Alerts", fireblocksData.Message)
	if err := s.Save(); err != nil {
		panic(err)
	}
	Alerts := s.Get("Alerts")
	fmt.Println("==>Message :: ", Alerts)

	//////////////////////////
	return c.Redirect("/vault")
	//return c.Redirect("/generate-new-wallet-address/" + VID + "/" + WID)

}

func NewApiTokenProvider(privateKeyPath, apiKey string) (*ApiTokenProvider, error) {
	privateKeyBytes, err := os.ReadFile(privateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("error reading private key from %s: %w", privateKeyPath, err)
	}

	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM(privateKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("error parsing RSA private key: %w", err)
	}

	return &ApiTokenProvider{
		privateKey: privateKey,
		apiKey:     apiKey,
	}, nil
}

func (a *ApiTokenProvider) SignJwt(path string, bodyJson interface{}) (string, error) {
	nonce := uuid.New().String()
	now := time.Now().Unix()
	expiration := now + 55 // Consider making this configurable

	bodyBytes, err := json.Marshal(bodyJson)
	if err != nil {
		return "", fmt.Errorf("error marshaling JSON: %w", err)
	}

	h := sha256.New()
	h.Write(bodyBytes)
	hashed := h.Sum(nil)

	claims := jwt.MapClaims{
		"uri":      path,
		"nonce":    nonce,
		"iat":      now,
		"exp":      expiration,
		"sub":      a.apiKey,
		"bodyHash": hex.EncodeToString(hashed),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tokenString, err := token.SignedString(a.privateKey)
	if err != nil {
		return "", fmt.Errorf("error signing token: %w", err)
	}

	return tokenString, nil
}

var httpClient = &http.Client{} // Reuse HTTP client

func MakeAPIRequest(method, path string, body interface{}, tokenProvider *ApiTokenProvider) ([]byte, error) {
	var url = "https://sandbox-api.fireblocks.io" + path

	var reqBodyBytes []byte
	if body != nil {
		var err error
		reqBodyBytes, err = json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("error marshaling request body: %w", err)
		}
	}

	token, err := tokenProvider.SignJwt(path, body)
	if err != nil {
		return nil, fmt.Errorf("error signing JWT: %w", err)
	}

	req, err := http.NewRequest(method, url, bytes.NewBuffer(reqBodyBytes))
	if err != nil {
		return nil, fmt.Errorf("error creating HTTP request: %w", err)
	}

	if method == "POST" {
		req.Header.Set("Content-Type", "application/json")
	}

	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-API-KEY", tokenProvider.apiKey)

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error sending HTTP request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading response body: %w", err)
	}

	return respBody, nil
}

// getAccountsPaged makes a GET request to retrieve paged accounts
func GetAccountsPaged(tokenProvider *ApiTokenProvider) error {
	path := "/v1/vault/accounts_paged"
	respBody, err := MakeAPIRequest("GET", path, nil, tokenProvider)
	if err != nil {
		return fmt.Errorf("error making GET request to accounts_paged: %w", err)
	}
	fmt.Printf("unexpected type %T", respBody)
	//fmt.Printf("Response body for accounts_paged: %s\n", string(respBody))
	return nil
}

// getAccountsPaged makes a GET request to retrieve paged accounts
func getListUsers(tokenProvider *ApiTokenProvider) error {
	path := "/v1/users"
	respBody, err := MakeAPIRequest("GET", path, nil, tokenProvider)
	if err != nil {
		return fmt.Errorf("error making GET request to accounts_paged: %w", err)
	}

	fmt.Printf("Response body for users: %s\n", string(respBody))
	return nil
}

// createAccount makes a POST request to create a new account
func createAccount(tokenProvider *ApiTokenProvider) error {
	path := "/v1/vault/accounts"
	body := map[string]interface{}{
		"name":       "MyGoVault",
		"hiddenOnUI": true,
	}

	respBody, err := MakeAPIRequest("POST", path, body, tokenProvider)
	if err != nil {
		return fmt.Errorf("error making POST request to create account: %w", err)
	}

	fmt.Printf("Response body for createAccount: %s\n", string(respBody))
	return nil
}
