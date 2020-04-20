package listeners

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/spaceraccoon/manuka-server/models"

	"golang.org/x/net/context"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/gmail/v1"
)

// IntelligenceIndicator struct defines matching templates for social email notifications
type IntelligenceIndicator struct {
	Subject  string         `json:"subject_re"`
	Content  string         `json:"content_re"`
	From     string         `json:"from_email"`
	Event    string         `json:"event"`
	Platform string         `json:"platform"`
	HitType  models.HitType `json:"hitType"`
}

// SocialListenerHit struct defines the hit data that is sent to the server
type SocialListenerHit struct {
	ListenerID   int                 `json:"listenerId"`
	ListenerType models.ListenerType `json:"listenerType"`
	Email        string              `json:"email"`
	HitType      models.HitType      `json:"hitType"`
}

// GmailToken represents the fields returned from a Gmail Oauth token JSON
type GmailToken struct {
	AccessToken  string `json: "access_token"`
	ExpiresIn    int    `json: "expires_in"`
	RefreshToken string `json: "refresh_token"`
	Scope        string `json: "scope"`
	TokenType    string `json: "token_type"`
}

// PushNotification struct describes a simple Google Pub/Sub notification
type PushNotification struct {
	Message      NotificationMessage `json:"message"`
	Subscription string              `json:"subscription"`
}

// NotificationMessage struct describes a simple notification message
type NotificationMessage struct {
	Data        string `json:"data"`
	MessageID   string `json:"messageId"`
	PublishTime string `json:"publishTime"`
}

// EmailNotification describes a simple Gmail notification
type EmailNotification struct {
	EmailAddress string `json:"emailAddress"`
	HistoryID    uint64 `json:"historyId"`
}

var gmailHistoryID uint64 // gmailHistoryID points to latest history ID retrieved
var googleCredentialsFile string = os.Getenv("GOOGLE_CREDENTIALS_FILE")
var googleOauth2TokenFile string = os.Getenv("GOOGLE_OAUTH2_TOKEN_FILE")
var topicFile string = os.Getenv("GOOGLE_TOPIC")

const gmailExpiresIn uint64 = 3600

var intelligenceIndicators []IntelligenceIndicator = []IntelligenceIndicator{
	{
		Subject:  "^.*, please add me to your LinkedIn network$",
		Content:  "^Hi.*, I&#39;d like to join your LinkedIn network\\. LinkedIn.*, I&#39;d like to join your LinkedIn network\\. .*$",
		From:     "invitations@linkedin.com",
		Event:    "attempted_network_connection",
		HitType:  models.LinkedInRequest,
		Platform: "LINKEDIN"},
	{
		Subject:  "^.*, start a conversation with your new connection, .*$",
		Content:  "^See.*connections, experience, and more LinkedIn.*has accepted your invitation\\. Let&#39;s start a conversation\\..*$",
		From:     "invitations@linkedin.com",
		Event:    "successful_network_connection",
		HitType:  models.LinkedInMessage,
		Platform: "LINKEDIN"},
	{
		Subject:  "^.*wants to be friends on Facebook$",
		Content:  "^.*wants to be friends with you on Facebook\\..*Confirm request Facebook.*wants to be friends with you on Facebook.*Confirm request See all requests.*$",
		From:     "notification@facebookmail.com",
		Event:    "attempted_network_connection",
		HitType:  models.FacebookRequest,
		Platform: "FACEBOOK"},
}

// convertStrEnvToInt converts the envStr to an int
func convertStrEnvToInt(envStr string) int {
	id, err := strconv.Atoi(os.Getenv(envStr))
	if err != nil {
		log.Fatalf("Unable to retrieve listener-related environment variable: %v", err)
	}
	return id
}

// getTokenFromWeb prompts for OAuth flow
func getTokenFromWeb(config *oauth2.Config) *oauth2.Token {
	authURL := config.AuthCodeURL("state-token", oauth2.AccessTypeOffline)
	fmt.Printf("Go to the following link in your browser then type the "+
		"authorization code: \n%v\n", authURL)

	var authCode string
	if _, err := fmt.Scan(&authCode); err != nil {
		log.Fatalf("Unable to read authorization code: %v", err)
	}

	tok, err := config.Exchange(context.TODO(), authCode)
	if err != nil {
		log.Fatalf("Unable to retrieve token from web: %v", err)
	}
	return tok
}

// tokenFromFile extracts a oauth2 token from file and adds Expiry
func tokenFromFile(file string) (*oauth2.Token, error) {
	f, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, err
	}

	token := &oauth2.Token{}
	err = json.Unmarshal([]byte(f), &token)
	if err != nil {
		return nil, err
	}

	if token.Expiry.IsZero() {
		gmailToken := &GmailToken{}
		err = json.Unmarshal([]byte(f), &gmailToken)
		if err != nil {
			return nil, err
		}
		token.Expiry = time.Now().Add(time.Second * time.Duration(gmailExpiresIn))
		saveToken(file, token)
	}
	return token, err
}

// saveToken saves new token file
func saveToken(path string, token *oauth2.Token) {
	fmt.Printf("Saving token file to: %s\n", path)
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		log.Fatalf("Unable to save oauth token: %v", err)
	}
	defer f.Close()
	json.NewEncoder(f).Encode(token)
}

// extractEmail extracts the email from the emailLine
func extractEmail(emailLine string) string {
	re := regexp.MustCompile(`([a-zA-Z0-9._-]+@[a-zA-Z0-9._-]+\.[a-zA-Z0-9_-]+)`)
	return re.FindAllString(emailLine, 1)[0]
}

// matchFormat checks if textBody matches the regex
func matchFormat(textBody string, regularExpressionFormat string) bool {
	r, _ := regexp.Compile(regularExpressionFormat)
	return r.MatchString(textBody)
}

// extractHeader extracts the relevant email header value
func extractHeader(headers []*gmail.MessagePartHeader, header string) string {
	result := ""
	for _, messagePartHeader := range headers {
		if messagePartHeader.Name == header {
			result = messagePartHeader.Value
			break
		}
	}
	return result
}

// parseEmail checks if email matches indicator format and modifies socialListenerHit accordingly
func parseEmail(emailMessage *gmail.Message, socialListenerHit *SocialListenerHit) error {
	subject := extractHeader(emailMessage.Payload.Headers, "Subject")
	email := extractEmail(extractHeader(emailMessage.Payload.Headers, "To"))
	fromEmail := extractEmail(extractHeader(emailMessage.Payload.Headers, "From"))
	content := emailMessage.Snippet
	for _, indicator := range intelligenceIndicators {
		if matchFormat(subject, indicator.Subject) && fromEmail == indicator.From && matchFormat(content, indicator.Content) {
			socialListenerHit.Email = email
			socialListenerHit.HitType = indicator.HitType
			return nil
		}
	}
	return errors.New("Email does not contain intelligence")
}

// getClientWithRefresh gets a Gmail service client that refreshes if saved token is expired
func getClientWithRefresh() (*http.Client, error) {
	b, err := ioutil.ReadFile(googleCredentialsFile)
	if err != nil {
		log.Fatalf("Unable to read client secret file: %v", err)
	}

	config, err := google.ConfigFromJSON(b, gmail.GmailReadonlyScope)
	if err != nil {
		log.Fatalf("Unable to parse client secret file to config: %v", err)
	}

	oldToken, err := tokenFromFile(googleOauth2TokenFile)
	if err != nil {
		log.Fatalf("Failed to retrieve token from file: %v", err)
		token := getTokenFromWeb(config)
		saveToken(googleOauth2TokenFile, token)
	}

	tokenSource := config.TokenSource(oauth2.NoContext, oldToken)
	newToken, err := tokenSource.Token() // renews token
	if err != nil {
		log.Fatalf("Unable to generate new token: %v", err)
	}

	if newToken.AccessToken != oldToken.AccessToken {
		newToken.Expiry = time.Now().Add(time.Second * time.Duration(gmailExpiresIn))
		saveToken(googleOauth2TokenFile, newToken)
		log.Println("Saved new token:", newToken.AccessToken) // save new access and refresh token
	}

	client := oauth2.NewClient(oauth2.NoContext, tokenSource)

	return client, nil
}

// initGmailGmailService initializes Gmail client service
func initGmailService() (*gmail.Service, error) {
	client, err := getClientWithRefresh()
	if err != nil {
		log.Fatalf("Unable to create client: %v", err)
		return nil, err
	}

	gmailService, err := gmail.New(client)
	if err != nil {
		log.Fatalf("Unable to create Gmail client: %v", err)
		return nil, err
	}

	return gmailService, nil
}

// initGmailWatch initializes Gmail client service and authorizes with OAuth credentials
func initGmailWatch() {
	gmailService, err := initGmailService()
	if err != nil {
		log.Fatalf("Unable to create Gmail service: %v", err)
	}

	topicBytes, err := ioutil.ReadFile(topicFile)
	if err != nil {
		log.Fatalf("Unable to read from topicFile: %v", err)
	}
	topic := strings.Split(string(topicBytes), "\n")[0]
	watchRequest := gmail.WatchRequest{
		LabelIds:  []string{"INBOX"},
		TopicName: topic,
	}
	r, err := gmailService.Users.Watch("me", &watchRequest).Do()
	if err != nil {
		log.Fatalf("Unable to retrieve watch: %v", err)
	}
	gmailHistoryID = r.HistoryId

	fmt.Printf("Successfully started watch with expiration %d and history ID %d\n", r.Expiration, r.HistoryId)
}

// SocialRoutes defines the routes for the social listener
func SocialRoutes(r *gin.Engine) {
	user := "me"

	// Initialize Gmail watch
	initGmailWatch()

	r.POST("/notifications", func(c *gin.Context) {
		var n PushNotification
		c.BindJSON(&n)
		fmt.Printf("Received push notification %s at %s\n", n.Message.MessageID, n.Message.PublishTime)

		// Try to decode received message
		decoded, err := base64.StdEncoding.DecodeString(n.Message.Data)
		if err != nil {
			log.Fatalf("Failed to decode message: %v", err)
			c.JSON(http.StatusBadRequest, gin.H{"error": err})
			return
		}

		emailNotification := EmailNotification{}
		json.Unmarshal([]byte(decoded), &emailNotification)

		gmailService, err := initGmailService()
		if err != nil {
			log.Fatalf("Unable to create Gmail service: %v", err)
		}

		// Retrieve user history starting from previous history ID
		r, err := gmailService.Users.History.List(user).StartHistoryId(gmailHistoryID).Do()
		if err != nil {
			log.Fatalf("Unable to retrieve history: %v", err)
		}

		// For each history item, check if a message was added and extract attachment if it exists
		for _, h := range r.History {
			for _, m := range h.MessagesAdded {
				messageResponse, err := gmailService.Users.Messages.Get(user, m.Message.Id).Do()
				if err != nil {
					// Does not work when email sent from same acct
					// Require stricter checking of message origin
					fmt.Printf("Unable to retrieve message: %v", err)
					continue
				}
				socialListenerHit := SocialListenerHit{
					ListenerID:   convertStrEnvToInt("LISTENER_ID"),
					ListenerType: models.ListenerType(convertStrEnvToInt("LISTENER_TYPE")),
				}
				err = parseEmail(messageResponse, &socialListenerHit)
				if err != nil {
					fmt.Printf("Failed to analyze email %s: %v", messageResponse.Id, err)
					continue
				}
				socialListenerHitJSON, err := json.Marshal(socialListenerHit)
				if err != nil {
					fmt.Printf("Unable to convert to json object: %v", err)
					continue
				}
				_, err = http.Post("http://server:8080/v1/hit", "application/json", bytes.NewBuffer(socialListenerHitJSON))
				if err != nil {
					log.Fatalf("Unable to send to backend server: %v", err)
				}
			}
		}

		// Update history ID
		gmailHistoryID = emailNotification.HistoryID

		c.Status(http.StatusOK)
	})
}
