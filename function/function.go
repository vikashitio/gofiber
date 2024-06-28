package function

import (
	"fmt"
	"log"
	"math/rand"
	"net"
	"net/smtp"
	"os"
	"template/models"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/session"
)

var store = session.New()

type MyStatus struct {
	Status string
}

// Get User Status by numeric value
func GetStatus(Status int) (MyStatus, error) {
	myStatus := ""

	if Status == 1 {
		myStatus = "Active"

	} else if Status == 2 {
		myStatus = "Inactive"
	} else if Status == 3 {
		myStatus = "New"
	} else {
		myStatus = "Deleted"

	}

	//fmt.Println(myStatus)
	var data = MyStatus{
		Status: myStatus,
	}
	return data, nil
}

// Function for send email
func SendEmail(subject, HTMLbody string) error {
	// sender data
	var Email = "vikashg@itio.in"

	// smtp - Details
	var fromEmail = os.Getenv("SMTPusername")
	var SMTPpassword = os.Getenv("SMTPpassword")
	var EntityName = os.Getenv("SMTPsendername")
	host := os.Getenv("SMTPhost")
	port := os.Getenv("SMTPport")
	address := host + ":" + port

	to := []string{Email}
	// Set up authentication information.
	auth := smtp.PlainAuth("", fromEmail, SMTPpassword, host)
	msg := []byte(
		"From: " + EntityName + ": <" + fromEmail + ">\r\n" +
			"To: " + Email + "\r\n" +
			"Subject: " + subject + "\r\n" +
			"MIME: MIME-version: 1.0\r\n" +
			"Content-Type: text/html; charset=\"UTF-8\";\r\n" +
			"\r\n" +
			HTMLbody)
	err := smtp.SendMail(address, auth, fromEmail, to, msg)
	if err != nil {
		return err
	}
	//fmt.Println("Check for sent email!")
	return nil
}

// Function for generate random password
func PasswordGenerator(passwordLength int) string {
	// Character sets for generating passwords
	lowerCase := "abcdefghijklmnopqrstuvwxyz" // lowercase
	upperCase := "ABCDEFGHIJKLMNOPQRSTUVWXYZ" // uppercase
	numbers := "0123456789"                   // numbers
	specialChar := "!@#$%^&*()_-+={}[/?]"     // special characters

	// Variable for storing password
	password := ""

	// Initialize the random number generator
	source := rand.NewSource(time.Now().UnixNano())
	rng := rand.New(source)

	// Generate password character by character
	for n := 0; n < passwordLength; n++ {
		// Generate a random number to choose a character set
		randNum := rng.Intn(4)

		switch randNum {
		case 0:
			randCharNum := rng.Intn(len(lowerCase))
			password += string(lowerCase[randCharNum])
		case 1:
			randCharNum := rng.Intn(len(upperCase))
			password += string(upperCase[randCharNum])
		case 2:
			randCharNum := rng.Intn(len(numbers))
			password += string(numbers[randCharNum])
		case 3:
			randCharNum := rng.Intn(len(specialChar))
			password += string(specialChar[randCharNum])
		}
	}

	return password
}

// Function for get Login IP
func GetLocalIP() net.IP {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	localAddress := conn.LocalAddr().(*net.UDPAddr)
	//fmt.Println(localAddress)
	return localAddress.IP
}

func GetLoginSession(c *fiber.Ctx) (*models.UserSession, error) {
	// Get current session
	s, err := store.Get(c)
	if err != nil {
		panic(err)
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

func CheckSession(c *fiber.Ctx) error {
	fmt.Println("Login Expired")
	s, _ := store.Get(c)
	// Get value
	LoginMerchantID := s.Get("LoginMerchantID")
	if LoginMerchantID == nil {
		return c.Redirect("/login")
	}

	return nil
}
