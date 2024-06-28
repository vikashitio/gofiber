package main

import (
	"fmt"
	"template/database"
	"template/fireblocks"
	"template/handlers"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/session"
	"github.com/gofiber/template/html/v2"
	"github.com/joho/godotenv"
)

var store = session.New()

func init() {

	// Init sessions store
	//handlers.InitSessionsStore()
}

func main() {
	database.ConnectDb()
	//store := session.New()

	if err := godotenv.Load(".env"); err != nil {
		fmt.Printf("ENV not Found")
		return
	}

	engine := html.New("./views", ".html")

	app := fiber.New(fiber.Config{
		Views:       engine,
		ViewsLayout: "layouts/main",
	})

	setUpRoutes(app)

	//app.Static("/", "./public")
	app.Static("/views", "./views")

	app.Listen(":3000")
}

func setUpRoutes(app *fiber.App) {

	//With Session Opening
	app.Get("/", handlers.IndexView)
	app.Get("/profile", handlers.ProfileView)
	app.Post("/profilePost", handlers.ProfilePost)
	app.Get("/login-history", handlers.Loginhistory)
	app.Get("/vault", handlers.VoltView)
	app.Get("/wallet/:VID/:WID", handlers.WalletView)
	app.Get("/generate-new-wallet-address/:VID/", handlers.CreateVaultWalletView)
	app.Post("/generate-new-wallet-address", fireblocks.CreateVaultWallet)
	app.Get("/generate-new-vault", handlers.CreateNewVault)
	app.Get("/fireblocks-users", fireblocks.UsersView)

	//Without Session Open
	app.Get("/login", handlers.LoginView)
	app.Post("/loginPost", handlers.LoginPost)
	app.Get("/registration", handlers.RegistrationView)
	app.Post("/registrationPost", handlers.RegistrationPost)
	app.Get("/logout", handlers.LogOut)

}
