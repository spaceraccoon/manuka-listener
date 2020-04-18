package listeners

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/spaceraccoon/manuka-server/models"
)

// Login struct defines the login form data
type Login struct {
	Username string `form:"username"`
	Password string `form:"password"`
}

// LoginHit struct defines the hit data that is sent to the server
type LoginHit struct {
	ListenerID   int                 `json:"listenerId"`
	ListenerType models.ListenerType `json:"listenerType"`
	IPAddress    string              `json:"ipAddress"`
	Username     string              `json:"username"`
	Password     string              `json:"password"`
	HitType      models.HitType      `json:"hitType"`
}

// LoginRoutes defines the routes for the login listener
func LoginRoutes(r *gin.Engine) {
	r.GET("/", func(c *gin.Context) {
		c.HTML(http.StatusOK, "login.html", gin.H{
			"companyName": os.Getenv("COMPANY_NAME"),
		})
	})
	r.POST("/login", func(c *gin.Context) {
		var login Login
		c.Bind(&login)
		listenerID, err := strconv.Atoi(os.Getenv("LISTENER_ID"))
		if err != nil {
			c.AbortWithStatus(http.StatusInternalServerError)
		}
		listenerTypeInt, err := strconv.Atoi(os.Getenv("LISTENER_TYPE"))
		if err != nil {
			c.AbortWithStatus(http.StatusInternalServerError)
		}
		loginHit := LoginHit{
			ListenerID:   listenerID,
			ListenerType: models.ListenerType(listenerTypeInt),
			IPAddress:    c.ClientIP(),
			Username:     login.Username,
			Password:     login.Password,
			HitType:      models.LoginAttempt,
		}
		loginHitJSON, err := json.Marshal(loginHit)
		if err != nil {
			c.AbortWithStatus(http.StatusInternalServerError)
		}
		_, err = http.Post("http://server:8080/v1/hit", "application/json", bytes.NewBuffer(loginHitJSON))
		if err != nil {
			c.AbortWithStatus(http.StatusInternalServerError)
		}
		c.Redirect(http.StatusMovedPermanently, "/")
		c.Abort()
	})
}
