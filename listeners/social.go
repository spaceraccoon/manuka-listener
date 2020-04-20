package listeners

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
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

type SimpleAcknowledgementReponse struct {
	Message string `json:"message"`
}

type IntelligenceIndicators struct {
	Subject  string         `json:"subject_re"`
	Content  string         `json:"content_re"`
	From     string         `json:"from_email"`
	Event    string         `json:"event"`
	Platform string         `json:"platform"`
	HitType  models.HitType `json:"hitType"`
}

type IndicatorOfInterest struct {
	ListenerID   int                 `json:"listener_id"`
	ListenerType models.ListenerType `json:"listener_type"`
	HitType      models.HitType      `json:"hit_type"`
	Email        string              `json:"email"`
	Sha256_hash  string              `json:"sha256_hash"`
}

type SocialListenerHit struct {
	ListenerID   int                 `json:"listenerId"`
	ListenerType models.ListenerType `json:"listenerType"`
	IPAddress    string              `json:"ipAddress"`
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

var GmailHistoryID uint64 // GmailHistoryID points to latest history ID retrieved
var intelligenceIndicators []IntelligenceIndicators
var companyName string = os.Getenv("COMPANY_NAME")
var googleCredentialsFile string = os.Getenv("GOOGLE_CREDENTIALS_FILE")
var googleOauth2TokenFile string = os.Getenv("GOOGLE_OAUTH2_TOKEN_FILE")
var listenerID int = convertStrToInt("LISTENER_ID")
var listenerType int = convertStrToInt("LISTENER_TYPE")
var topicFile string = os.Getenv("GOOGLE_TOPIC")

const gmailExpiresIn uint64 = 3600

func convertStrToInt(envStr string) int {
	id, err := strconv.Atoi(os.Getenv(envStr))
	if err != nil {
		log.Fatalf("Unable to retrieve listener-related environment variable: %v", err)
	}
	return id
}

func init() {
	intelligenceIndicators = []IntelligenceIndicators{
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
}


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

func saveToken(path string, token *oauth2.Token) {
	fmt.Printf("Saving credential file to: %s\n", path)
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		log.Fatalf("Unable to cache oauth token: %v", err)
	}
	defer f.Close()
	json.NewEncoder(f).Encode(token)
}

func extractEmail(emailLine string) string {
	re := regexp.MustCompile(`([a-zA-Z0-9._-]+@[a-zA-Z0-9._-]+\.[a-zA-Z0-9_-]+)`)
	return re.FindAllString(emailLine, 1)[0]
}

func matchFormat(textBody string, regularExpressionFormat string) bool {
	r, _ := regexp.Compile(regularExpressionFormat)
	return r.MatchString(textBody)
}

func convertEpochMS(epochMS int64) time.Time {
	return time.Unix(0, epochMS*int64(time.Millisecond))
}

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

func generateSha256Hash(platform string, target string, event string, subject string, snippet string) string {
	plaintext := []string{platform, target, event, subject, snippet}
	data := []byte(strings.Join(plaintext, ":"))
	hash := sha256.Sum256(data)
	encodedStr := hex.EncodeToString(hash[:])
	return encodedStr
}

func analyzeEmail(emailMessage *gmail.Message) (IndicatorOfInterest, error) {
	subject := extractHeader(emailMessage.Payload.Headers, "Subject")
	email := extractEmail(extractHeader(emailMessage.Payload.Headers, "To"))
	fromEmail := extractEmail(extractHeader(emailMessage.Payload.Headers, "From"))
	content := emailMessage.Snippet
	for _, indicator := range intelligenceIndicators {
		if matchFormat(subject, indicator.Subject) && fromEmail == indicator.From && matchFormat(content, indicator.Content) {
			return IndicatorOfInterest{ListenerID: listenerID, ListenerType: models.ListenerType(listenerType), HitType: indicator.HitType, Email: email, Sha256_hash: generateSha256Hash(indicator.Platform, email, indicator.Event, subject, content)}, nil
		}
	}
	return IndicatorOfInterest{ListenerID: 0, ListenerType: 0, HitType: 0, Email: "", Sha256_hash: ""}, errors.New("Email does not contain intelligence")
}

// Get a Gmail service client that refreshes if saved token is expired
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

// InitGmailWatch initializes Gmail client service and authorizes with OAuth credentials
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
	GmailHistoryID = r.HistoryId

	fmt.Printf("Successfully started watch with expiration %d and history ID %d\n", r.Expiration, r.HistoryId)
}

// LoginRoutes defines the routes for the login listener
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
		r, err := gmailService.Users.History.List(user).StartHistoryId(GmailHistoryID).Do()
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
					log.Fatalf("Unable to retrieve message: %v", err)
				}
				indicator, analysisError := analyzeEmail(messageResponse)
				if analysisError != nil {
					fmt.Printf("Message %s does not contain Intelligence\n", messageResponse.Id)
					continue
				}
				jsonObj, jsonConversionErr := json.Marshal(&indicator)
				if jsonConversionErr != nil {
					fmt.Println(jsonConversionErr)
				}
				loginHit := SocialListenerHit{
					ListenerID:   listenerID,
					ListenerType: models.ListenerType(listenerType),
					IPAddress:    c.ClientIP(),
					Email:        indicator.Email,
					HitType:      indicator.HitType,
				}
				loginHitJSON, err := json.Marshal(loginHit)
				if err != nil {
					log.Fatalf("Unable to convert to json object: %v", err)
				}
				_, err = http.Post("http://server:8080/v1/hit", "application/json", bytes.NewBuffer(loginHitJSON))
				if err != nil {
					log.Fatalf("Unable to send to backend server: %v", err)
				}
				fmt.Println(string(jsonObj))
			}
		}

		// Update history ID
		GmailHistoryID = emailNotification.HistoryID

		response := SimpleAcknowledgementReponse{Message: "OK"}
		c.JSON(http.StatusOK, response)
	})
}
