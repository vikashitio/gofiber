package routes

import (
	"fmt"

	"github.com/gofiber/fiber/v2"
)

func setUpRoutes(app *fiber.App) {

	fmt.Println("Call from routes")
	//app.Get("/", handlers.ListFacts)

	//app.Get("/fact", handlers.NewFactView) // Add new route for new view
	//app.Post("/fact", handlers.CreateFact)
}
