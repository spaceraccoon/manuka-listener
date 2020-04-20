package listeners

import (
	"bytes"
	"crypto/sha256"
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

type MessagesCache struct {
	Ids    map[string]bool     `json:"ids"`
	Hashes map[string][]string `json:"hashes"`
}

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

type ListenerHit struct {
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

func readMessagesCache(outputFile string) MessagesCache {
	resultCache := MessagesCache{}
	file, fileReadError := ioutil.ReadFile(outputFile)
	if fileReadError != nil {
		resultCache = MessagesCache{Ids: make(map[string]bool), Hashes: make(map[string][]string)}
	} else {
		readJsonError := json.Unmarshal([]byte(file), &resultCache)
		if readJsonError != nil {
			resultCache = MessagesCache{Ids: make(map[string]bool), Hashes: make(map[string][]string)}
		}
	}
	return resultCache
}

func dumpMessagesCache(messagesCache MessagesCache, outputFile string) {
	streamArr, marshalError := json.Marshal(messagesCache)
	if marshalError != nil {
		fmt.Println(marshalError)
	} else {
		ioutil.WriteFile(outputFile, streamArr, 0644)
	}
}

var intelligenceIndicators []IntelligenceIndicators
var messagesCacheFile string = os.Getenv("MESSAGES_CACHE_FILE")
var companyName string = os.Getenv("COMPANY_NAME")
var googleCredentialsFile string = os.Getenv("GOOGLE_CREDENTIALS_FILE")
var googleOauth2TokenFile string = os.Getenv("GOOGLE_OAUTH2_TOKEN_FILE")
var listenerID int = convertStrToInt("LISTENER_ID")
var listenerType int = convertStrToInt("LISTENER_TYPE")

// GmailHistoryID points to latest history ID retrieved
var GmailHistoryID uint64

const gmailExpiresIn uint64 = 3

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
	// // b, err := ioutil.ReadFile("/run/secrets/credentials.json")

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

// LoginRoutes defines the routes for the login listener
func SocialRoutes(r *gin.Engine) {

	user := "me"

	r.GET("/", func(c *gin.Context) {
		c.HTML(http.StatusOK, "login.html", gin.H{
			"companyName": companyName,
		})
	})
	r.GET("/harvest", func(c *gin.Context) {
		srv, err := initGmailService()
		r, err := srv.Users.Messages.List(user).Do()
		if err != nil {
			log.Fatalf("Unable to retrieve emails: %v", err)
		}
		if len(r.Messages) > 0 {
			messagesCache := readMessagesCache(messagesCacheFile)
			for _, message := range r.Messages {
				cachedId := messagesCache.Ids[message.Id]
				if cachedId == false {
					messagesCache.Ids[message.Id] = true
					messageResponse, messageResponseError := srv.Users.Messages.Get(user, message.Id).Do()
					if messageResponseError != nil {
						log.Fatalf("Unable to retrieve message: %v", messageResponseError)
					}
					indicator, analysisError := analyzeEmail(messageResponse)
					if analysisError != nil {
						fmt.Printf("Message %s does not contain Intelligence\n", message.Id)
						continue
					}
					jsonObj, jsonConversionErr := json.Marshal(&indicator)
					if jsonConversionErr != nil {
						fmt.Println(jsonConversionErr)
					}
					hashes := messagesCache.Hashes[indicator.Sha256_hash]
					// Do something here to send the intelligence object to a endpoint
					// To discuss with the team on the action taken if a similar intelligence is found
					if len(hashes) > 0 {
						fmt.Println("Similar hash value found")
					} else {
						// Since its unique, send back to backend
						loginHit := ListenerHit{
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
					}
					messagesCache.Hashes[indicator.Sha256_hash] = append(hashes, message.Id)
					fmt.Println(string(jsonObj))
				}
			}
			dumpMessagesCache(messagesCache, messagesCacheFile)
		} else {
			// if no email found, do not continue any further
			fmt.Println("No emails found.")
		}
		response := SimpleAcknowledgementReponse{Message: "OK"}
		c.JSON(http.StatusOK, response)
	})
	r.GET("/cache", func(c *gin.Context) {
		messagesCache := readMessagesCache(messagesCacheFile)
		c.JSON(http.StatusOK, messagesCache)
	})
	r.GET("/clear_cache", func(c *gin.Context) {
		err := os.Remove(messagesCacheFile)
		response := SimpleAcknowledgementReponse{Message: "OK"}
		if err != nil {
			log.Fatalf("Unable to clear messages cache: %v", err)
			response.Message = "FAILED"
		}
		c.JSON(http.StatusOK, response)
	})
}
