package handlers

import (
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"template/database"
	"template/fireblocks"
	"template/function"
	"template/models"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/session"
	"golang.org/x/crypto/bcrypt"
)

var store = session.New()

type ApiTokenProvider struct {
	privateKey *rsa.PrivateKey
	apiKey     string
}

func LoginView(c *fiber.Ctx) error {
	return c.Render("login", fiber.Map{
		"Title": "Login Form",
		"Alert": "",
	})
}

func LoginPost(c *fiber.Ctx) error {
	// Parses the request body
	getUserName := c.FormValue("username")
	getPassword := c.FormValue("password")

	//fmt.Println(getUserName, getPassword)
	Alerts := ""
	loginList := models.LoginList{}
	result := database.DB.Db.Table("client_master").Where("username = ?", getUserName).Find(&loginList)

	//fmt.Println(loginList.Status)

	if result.Error != nil {
		//fmt.Println("ERROR in QUERY")
		Alerts = "ERROR in QUERY"
	}

	if result.RowsAffected == 1 {
		//fmt.Println(loginList)
		//fmt.Println(Full_name)

		if loginList.Status != 1 {
			//fmt.Println("Account Not Activate / Deleted")
		} else if loginList.Password != "" {
			//fmt.Println(loginList.Password)
			err := bcrypt.CompareHashAndPassword([]byte(loginList.Password), []byte(getPassword))
			if err == nil {
				//fmt.Println("You have successfully logged in")

				s, _ := store.Get(c)

				//s.Set("name", "john")

				// Set key/value
				loginIp := c.Context().RemoteIP().String()
				s.Set("LoginMerchantName", loginList.Full_name)
				s.Set("LoginMerchantID", loginList.Client_id)
				s.Set("LoginMerchantEmail", getUserName)
				s.Set("LoginMerchantStatus", loginList.Status)
				s.Set("LoginVoltID", loginList.Volt_id)
				s.Set("LoginIP", c.Context().RemoteIP().String())
				s.Set("LoginTime", time.Unix(time.Now().Unix(), 0).UTC().String())
				s.Set("LoginAgent", string(c.Request().Header.UserAgent()))

				//Save sessions
				if err := s.Save(); err != nil {
					panic(err)
				}

				qry := models.LoginHistory{Client_id: loginList.Client_id, Login_ip: loginIp}
				result := database.DB.Db.Table("login_history").Select("client_id", "login_ip").Create(&qry)
				fmt.Println(result)

				return c.Redirect("/")

			} else {
				//fmt.Println("Wrong Password")
				Alerts = "Wrong Password"
			}

		}

	} else {
		//fmt.Println("Account Not Found")
		Alerts = "Account Not Found"

	}

	return c.Render("login", fiber.Map{
		"Title": "Login Form",
		"Alert": Alerts,
		//"Facts":    facts,
	})
}

func RegistrationView(c *fiber.Ctx) error {
	//facts := []models.Fact{}
	//fmt.Println("===>", facts)
	return c.Render("registration", fiber.Map{
		"Title": "Registration Form",
		"Alert": "",
		//"Facts":    facts,
	})
}

func RegistrationPost(c *fiber.Ctx) error {
	// Parses the request body
	getName := c.FormValue("name")
	getEmail := c.FormValue("email")

	//fmt.Println(getName, getEmail)

	// Find Duplicate Email in DB

	Alerts := ""
	loginList := models.LoginList{}
	result := database.DB.Db.Table("client_master").Where("username = ?", getEmail).Find(&loginList)
	if result.Error != nil {
		fmt.Println(result.Error)
	}

	receivedId := loginList.Client_id
	fmt.Println("XXX ", receivedId)

	if receivedId == 0 {

		// END Find Duplicate Email in DB

		var password = function.PasswordGenerator(8)
		//fmt.Println(password)

		var hash []byte
		// func GenerateFromPassword(password []byte, cost int) ([]byte, error)
		hash, _ = bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)

		//fmt.Println(hash)
		//loginList := models.Client_Master{}
		//result := database.DB.Db.Table("client_master").Create(&loginList)

		qry := models.Client_Master{Username: getEmail, Password: string(hash), Full_name: getName, Status: 1}
		//result := database.DB.Db.Table("client_master").Create(&[]models.Client_Master{{Username: getEmail, Password: string(hash), Full_name: getName, Status: 1}})
		result = database.DB.Db.Table("client_master").Select("username", "full_name", "password", "status").Create(&qry)
		//fmt.Println(result)

		if result.Error != nil {
			fmt.Println(result.Error)
		} else {
			fmt.Println(result.RowsAffected)
			fmt.Println(qry.Client_id)
			ClientID := qry.Client_id

			//  Email///
			//var domName = "http://localhost:8080"
			var subject = "Test Message"
			//var HTMLbody = "Hi this is message"
			HTMLbody :=
				`<html>
			<p><strong>Hello , ` + getName + `</strong></p>
			<br/>
			<p>Welcome to Golang Bank! We are pleased to inform that your account has been created.</p>
			<br/>
			<strong>Login Details for Your Account:<br/>=====================<br/><strong>
			<p>Username :  ` + getEmail + `</p>
			<p>Password :  ` + password + `</p>
			
			<br/>
			Cheers,
			<br/>
            <strong>Golang Bank</strong>
		</html>`
			err := function.SendEmail(subject, HTMLbody)
			if err != nil {
				fmt.Println("issue sending verification email")
			} else {
				fmt.Println("Mail Going")
			}

			s, _ := store.Get(c)

			//s.Set("name", "john")

			// Set key/value
			s.Set("LoginMerchantName", getName)
			s.Set("LoginMerchantID", ClientID)
			s.Set("LoginMerchantEmail", getEmail)
			s.Set("LoginMerchantStatus", 1)
			s.Set("LoginIP", c.Context().RemoteIP().String())
			s.Set("LoginTime", time.Unix(time.Now().Unix(), 0).UTC().String())
			s.Set("LoginAgent", string(c.Request().Header.UserAgent()))

			if err := s.Save(); err != nil {
				panic(err)
			}

			return c.Redirect("/")

		}
	} else {
		//fmt.Println("Duplicate = ", loginList.Client_id)
		Alerts = "Duplicate Email ID"

	}

	return c.Render("registration", fiber.Map{
		"Title": "Registration Form",
		"Alert": Alerts,
		//"Facts":    facts,
	})
}

// For Login History

func Loginhistory(c *fiber.Ctx) error {

	// check session
	s, _ := store.Get(c)
	// Get value
	LoginMerchantID := s.Get("LoginMerchantID")
	if LoginMerchantID == nil {
		return c.Redirect("/login")
	}

	loginHistory := []models.LoginHistory{}
	database.DB.Db.Table("login_history").Order("token_id desc").Where("client_id = ?", LoginMerchantID).Find(&loginHistory)
	//.Select("login_time")
	userProfileData, err := GetUserSessionData(c)
	if err != nil {
		panic(err)
	}

	//fmt.Println(loginHistory)
	return c.Render("login-history", fiber.Map{
		"Title":          "Login History",
		"Subtitle":       "Login History",
		"LoginHistory":   loginHistory,
		"CurrentSession": userProfileData.LoginMerchantName,
		"Sessions":       userProfileData.Sessions,
	})
}
func CreateVaultWalletView(c *fiber.Ctx) error {
	VID := c.Params("VID")

	// check session
	s, _ := store.Get(c)
	// Get value
	LoginMerchantID := s.Get("LoginMerchantID")
	Alerts := s.Get("Alerts")
	s.Delete("Alerts")
	if err := s.Save(); err != nil {
		panic(err)
	}
	if LoginMerchantID == nil {
		return c.Redirect("/login")
	}

	userProfileData, err := GetUserSessionData(c)
	if err != nil {
		panic(err)
	}

	//fmt.Println(profile)
	//fmt.Println(userProfileData)
	return c.Render("create-wallet", fiber.Map{
		"Title":          "Create Wallet",
		"Subtitle":       "Create Wallet",
		"Alert":          Alerts,
		"VoltID":         VID,
		"CurrentSession": userProfileData.LoginMerchantName,
		"Sessions":       userProfileData.Sessions,
	})
}

func ProfileView(c *fiber.Ctx) error {

	// check session
	s, _ := store.Get(c)
	// Get value
	LoginMerchantID := s.Get("LoginMerchantID")
	Alerts := s.Get("Alerts")
	s.Delete("Alerts")
	if err := s.Save(); err != nil {
		panic(err)
	}
	if LoginMerchantID == nil {
		return c.Redirect("/login")
	}

	profile := []models.Profile{}
	database.DB.Db.Table("client_details").Where("client_id = ?", LoginMerchantID).Find(&profile)
	//.Select("login_time")
	userProfileData, err := GetUserSessionData(c)
	if err != nil {
		panic(err)
	}

	//fmt.Println(profile)
	//fmt.Println(userProfileData)
	return c.Render("profile", fiber.Map{
		"Title":          "Profile",
		"Subtitle":       "Profile",
		"Alert":          Alerts,
		"Profile":        profile,
		"CurrentSession": userProfileData.LoginMerchantName,
		"Sessions":       userProfileData.Sessions,
	})
}

func ProfilePost(c *fiber.Ctx) error {
	// Parses the request body
	getGender := c.FormValue("gender")
	getBirthDate := c.FormValue("birth_date")
	getCountryCode := c.FormValue("country_code")
	getMobile := c.FormValue("mobile")
	getAddressLine1 := c.FormValue("address_line1")
	getAddressLine2 := c.FormValue("address_line2")

	//fmt.Println(getGender, getBirthDate, getCountryCode, getMobile, getAddressLine1, getAddressLine2)

	result := database.DB.Db.Table("client_details").Save(&models.Profile{Client_id: 72, Gender: getGender, BirthDate: getBirthDate, CountryCode: getCountryCode, Mobile: getMobile, AddressLine1: getAddressLine1, AddressLine2: getAddressLine2})

	//fmt.Println(loginList.Status)
	Alerts := "Profile Updated successfully"
	if result.Error != nil {
		//fmt.Println("ERROR in QUERY")
		Alerts = "Profile Not Updated"
	}

	// check session
	s, _ := store.Get(c)
	s.Set("Alerts", Alerts)
	if err := s.Save(); err != nil {
		panic(err)
	}

	return c.Redirect("/profile")

}

func VoltView(c *fiber.Ctx) error {

	s, _ := store.Get(c)

	// Get value
	LoginMerchantID := s.Get("LoginMerchantID")

	if LoginMerchantID == nil {
		return c.Redirect("/login")
	}

	Alerts := s.Get("Alerts")
	s.Delete("Alerts")

	privateKeyPath := "./fireblocks_secret.key"
	apiKey := "053c5036-525b-41fd-af32-2cf9776be07c"
	tokenProvider, err := fireblocks.NewApiTokenProvider(privateKeyPath, apiKey)
	if err != nil {
		fmt.Println("Error")
	}
	//#############################//
	var voltID = s.Get("LoginVoltID").(string)
	//fmt.Println("LoginVoltID -> ", voltID)
	var fireblocksData models.FireblocksResponse

	if voltID != "" {
		path := "/v1/vault/accounts/" + voltID //+ voltID
		//fmt.Println(path)
		respBody, err := fireblocks.MakeAPIRequest("GET", path, nil, tokenProvider)
		if err != nil {
			fmt.Println(err)
		}
		//fmt.Println(string(respBody))
		// Parse the JSON data into the struct
		//var fireblocksData models.FireblocksResponse
		if err := json.Unmarshal([]byte(respBody), &fireblocksData); err != nil {
			fmt.Println(err)
		}

	}
	///////////////////////////////////
	userProfileData, err := GetUserSessionData(c)

	if err != nil {
		fmt.Println(err)
	}

	//fmt.Println(fireblocksData)
	//return c.Render("vault", fireblocksData)
	return c.Render("vault", fiber.Map{
		"Title":          "Wallet List",
		"Subtitle":       "Wallet List",
		"Alert":          Alerts,
		"LoginVoltID":    voltID,
		"CurrentSession": userProfileData.LoginMerchantName,
		"Sessions":       userProfileData.Sessions,
		"ID":             fireblocksData.ID,
		"Name":           fireblocksData.Name,
		"HiddenOnUI":     fireblocksData.HiddenOnUI,
		"AutoFuel":       fireblocksData.AutoFuel,
		"Assets":         fireblocksData.Assets,
	})
}

func WalletView(c *fiber.Ctx) error {

	VID := c.Params("VID")
	WID := c.Params("WID")

	//fmt.Println(VID, WID)

	s, _ := store.Get(c)
	// Get value
	LoginMerchantID := s.Get("LoginMerchantID")
	if LoginMerchantID == nil {
		return c.Redirect("/login")
	}

	privateKeyPath := "./fireblocks_secret.key"
	apiKey := "053c5036-525b-41fd-af32-2cf9776be07c"
	tokenProvider, err := fireblocks.NewApiTokenProvider(privateKeyPath, apiKey)
	if err != nil {
		fmt.Println("Error")
	}
	path := "/v1/vault/accounts/" + VID + "/" + WID + "/addresses_paginated"
	respBody, err := fireblocks.MakeAPIRequest("GET", path, nil, tokenProvider)
	if err != nil {
		fmt.Println(err)
	}
	//fmt.Println(string(respBody))
	// Parse the JSON data into the struct
	var fireblocksData models.FireblocksAddress
	if err := json.Unmarshal([]byte(respBody), &fireblocksData); err != nil {
		fmt.Println(err)
	}
	///////////////////////////////////
	userProfileData, err := GetUserSessionData(c)

	if err != nil {
		fmt.Println(err)
	}

	//fmt.Println(fireblocksData)
	//return c.Render("vault", fireblocksData)
	return c.Render("wallet", fiber.Map{
		"Title":          "Wallet Address",
		"VoltID":         VID,
		"AssetID":        WID,
		"CurrentSession": userProfileData.LoginMerchantName,
		"Sessions":       userProfileData.Sessions,
		"Assets":         fireblocksData.Addresses,
	})
}

func CreateNewVault(c *fiber.Ctx) error {

	s, _ := store.Get(c)
	Alerts := "Account Generated Successfully"
	// Get value
	LoginMerchantID := s.Get("LoginMerchantID")
	LoginMerchantEmail := s.Get("LoginMerchantEmail").(string)
	if LoginMerchantID == nil {
		return c.Redirect("/login")
	}

	privateKeyPath := "./fireblocks_secret.key"
	apiKey := "053c5036-525b-41fd-af32-2cf9776be07c"
	tokenProvider, err := fireblocks.NewApiTokenProvider(privateKeyPath, apiKey)
	if err != nil {
		fmt.Println("Error")
	}

	path := "/v1/vault/accounts"
	Mydata := struct {
		Name string `json:"name"`
	}{
		Name: LoginMerchantEmail,
	}

	respBody, err := fireblocks.MakeAPIRequest("POST", path, Mydata, tokenProvider)
	if err != nil {
		fmt.Println(err)
		Alerts = "Account Not Generated"
	}
	fmt.Println(string(respBody))
	// Parse the JSON data into the struct
	var fireblocksData models.CreateVaultAccountResponse
	if err := json.Unmarshal([]byte(respBody), &fireblocksData); err != nil {
		fmt.Println(err)
	}
	///////////////////////////////////

	fmt.Println(fireblocksData.ID)
	if fireblocksData.ID != "" {

		Voltid := fireblocksData.ID
		//LoginID := LoginMerchantID.(uint)
		result := database.DB.Db.Table("client_master").Save(&models.UpdateVolt{Client_id: 137, Volt_id: Voltid})

		if result.Error != nil {
			fmt.Println("ERROR in QUERY")
			Alerts = "Account Not Generated - 2"
		}
	}
	s.Set("Alerts", Alerts)
	if err := s.Save(); err != nil {
		panic(err)
	}
	return c.Redirect("/vault")
}

func IndexView(c *fiber.Ctx) error {

	s, _ := store.Get(c)

	// For check session
	keys := s.Keys()
	fmt.Println("Keys = > ", keys)

	// Get value
	LoginMerchantID := s.Get("LoginMerchantID")
	if LoginMerchantID == nil {
		return c.Redirect("/login")
	}

	userProfileData, _ := GetUserSessionData(c)

	return c.Render("index", fiber.Map{
		"Title":          "Dashboard",
		"Subtitle":       "Home",
		"CurrentSession": userProfileData.LoginMerchantName,
		"Sessions":       userProfileData.Sessions,
	})
}

// Create new Fact View handler
func LogOut(c *fiber.Ctx) error {
	s, err := store.Get(c)
	if err != nil {
		panic(err)
	}

	s.Delete("LoginMerchantID")

	// Destroy session
	if err := s.Destroy(); err != nil {
		panic(err)
	}

	return c.Redirect("/login")
}

func GetUserSessionData(c *fiber.Ctx) (*models.UserSession, error) {
	// Get current session

	s, err := store.Get(c)

	if err != nil {
		//U := &models.UserSession{Session: "Error"}
		//return U, nil
		//function.CheckSession()
	}

	// Get value
	LoginMerchantName := s.Get("LoginMerchantName").(string)
	LoginMerchantID := s.Get("LoginMerchantID").(uint)
	LoginMerchantEmail := s.Get("LoginMerchantEmail").(string)
	LoginMerchantStatus := s.Get("LoginMerchantStatus").(int)
	LoginIP := s.Get("LoginIP").(string)
	LoginTime := s.Get("LoginTime").(string)
	LoginAgent := s.Get("LoginAgent").(string)
	// If there is a valid session
	if len(s.Keys()) > 0 {

		// Get profile info
		U := &models.UserSession{
			LoginMerchantName:   LoginMerchantName,
			LoginMerchantID:     LoginMerchantID,
			LoginMerchantEmail:  LoginMerchantEmail,
			LoginMerchantStatus: LoginMerchantStatus,
			Session:             "Test",
		}

		// Append session
		U.Sessions = append(
			U.Sessions,
			models.UserSessionOther{
				LoginIP:    LoginIP,
				LoginTime:  LoginTime,
				LoginAgent: LoginAgent,
			},
		)
		//fmt.Println(U)
		return U, nil
	}

	return nil, nil
}
