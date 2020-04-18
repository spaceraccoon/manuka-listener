package main

import (
	"log"
	"os"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/spaceraccoon/manuka-listener/listeners"
	"github.com/spaceraccoon/manuka-server/models"
)

func main() {
	r := gin.Default()
	r.LoadHTMLGlob("templates/*")
	listenerTypeInt, err := strconv.Atoi(os.Getenv("LISTENER_TYPE"))
	if err != nil {
		log.Fatal("Invalid listener type")
	}

	switch models.ListenerType(listenerTypeInt) {
	case models.LoginListener:
		listeners.LoginRoutes(r)
	case models.SocialListener:
		listeners.SocialRoutes(r)
	default:
		log.Fatal("Environment variable LISTENER_TYPE must be one of login, social")
	}
	r.Run(":8080")
}
