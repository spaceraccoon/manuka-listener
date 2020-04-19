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
	Error   string `json:"error"`
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

type OAuth2Code struct {
	OAuth2Code string `form:"oauth2_code"`
}

var intelligenceIndicators []IntelligenceIndicators
var messagesCacheFile string = os.Getenv("MESSAGES_CACHE_FILE")
var companyName string = os.Getenv("COMPANY_NAME")
var googleCredentialsFile string = os.Getenv("GOOGLE_CREDENTIALS_FILE")
var googleOauth2TokenFile string = os.Getenv("GOOGLE_OAUTH2_TOKEN_FILE")
var listenerID int = convertStrToInt("LISTENER_ID")
var listenerType int = convertStrToInt("LISTENER_TYPE")
var user string = "me"

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

func getClient(config *oauth2.Config) (*http.Client, error) {
	tok, err := tokenFromFile(googleOauth2TokenFile)
	if err != nil {
		log.Fatalf("Unable to retrieve cached oauth2 token: %v", err)
	}
	return config.Client(context.Background(), tok), err
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
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	tok := &oauth2.Token{}
	err = json.NewDecoder(f).Decode(tok)
	return tok, err
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

func initGmailService() (*gmail.Service, error) {
	b, err := ioutil.ReadFile(googleCredentialsFile)
	if err != nil {
		log.Fatalf("Unable to read client secret file: %v", err)
	}
	config, err := google.ConfigFromJSON(b, gmail.GmailReadonlyScope)
	if err != nil {
		log.Fatalf("Unable to parse client secret file to config: %v", err)
	}
	client, err := getClient(config)
	if err != nil {
		log.Fatalf("Unable to set configurations for Gmail API client: %v", err)
	}
	srv, err := gmail.New(client)
	if err != nil {
		log.Fatalf("Unable to initialise Gmail client: %v", err)
	}
	return srv, err
}

func SocialRoutes(r *gin.Engine) {
	r.GET("/init_oauth2", func(c *gin.Context) {
		response := SimpleAcknowledgementReponse{Message: "FAILED", Error: "N.A"}
		b, err := ioutil.ReadFile(googleCredentialsFile)
		if err != nil {
			log.Fatalf("Unable to read client secret file: %v", err)
			response.Error = err.Error()
			c.AbortWithStatusJSON(http.StatusInternalServerError, response)
			return
		}
		config, err := google.ConfigFromJSON(b, gmail.GmailReadonlyScope)
		if err != nil {
			log.Fatalf("Unable to parse client secret file to config: %v", err)
			response.Error = err.Error()
			c.AbortWithStatusJSON(http.StatusInternalServerError, response)
			return
		}
		authURL := config.AuthCodeURL("state-token", oauth2.AccessTypeOffline)
		c.HTML(http.StatusOK, "oauth2.html", gin.H{
			"oauth2Link": authURL,
		})
		return
	})
	r.POST("/init_oauth2", func(c *gin.Context) {
		response := SimpleAcknowledgementReponse{Message: "FAILED", Error: "N.A"}
		var oAuth2CodeJSON OAuth2Code
		c.Bind(&oAuth2CodeJSON)
		b, err := ioutil.ReadFile(googleCredentialsFile)
		if err != nil {
			log.Fatalf("Unable to read client secret file: %v", err)
			response.Error = err.Error()
			c.AbortWithStatusJSON(http.StatusInternalServerError, response)
			return
		}
		config, err := google.ConfigFromJSON(b, gmail.GmailReadonlyScope)
		if err != nil {
			log.Fatalf("Unable to parse client secret file to config: %v", err)
			response.Error = err.Error()
			c.AbortWithStatusJSON(http.StatusInternalServerError, response)
			return
		}
		oAuth2Token, err := config.Exchange(context.TODO(), oAuth2CodeJSON.OAuth2Code)
		if err != nil {
			log.Fatalf("Unable to retrieve token from web: %v", err)
			response.Error = err.Error()
			c.AbortWithStatusJSON(http.StatusInternalServerError, response)
			return
		}
		saveToken(googleOauth2TokenFile, oAuth2Token)
		response.Message = "OK"
		c.JSON(http.StatusOK, response)
		return
	})
	r.GET("/harvest", func(c *gin.Context) {
		response := SimpleAcknowledgementReponse{Message: "FAILED", Error: "N.A"}
		srv, err := initGmailService()
		r, err := srv.Users.Messages.List(user).Do()
		if err != nil {
			log.Fatalf("Unable to retrieve emails: %v", err)
			response.Error = err.Error()
			c.AbortWithStatusJSON(http.StatusInternalServerError, response)
			return
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
		response.Message = "OK"
		c.JSON(http.StatusOK, response)
		return
	})
	r.GET("/cache", func(c *gin.Context) {
		messagesCache := readMessagesCache(messagesCacheFile)
		c.JSON(http.StatusOK, messagesCache)
		return
	})
	r.GET("/clear_cache", func(c *gin.Context) {
		response := SimpleAcknowledgementReponse{Message: "OK", Error: "N.A"}
		if _, err := os.Stat(messagesCacheFile); err == nil {
			err := os.Remove(messagesCacheFile)
			if err != nil {
				log.Fatalf("Unable to clear messages cache: %v", err)
				response.Message = "FAILED"
				response.Error = err.Error()
				c.AbortWithStatusJSON(http.StatusInternalServerError, response)
				return
			}
		} else {
			log.Fatalf("Messages cache file does not exists: %v", err)
			response.Message = "FAILED"
			response.Error = err.Error()
			c.AbortWithStatusJSON(http.StatusInternalServerError, response)
			return
		}
		c.JSON(http.StatusOK, response)
		return
	})
	r.GET("/clear_oauth2_token", func(c *gin.Context) {
		response := SimpleAcknowledgementReponse{Message: "OK", Error: "N.A"}
		if _, err := os.Stat(googleOauth2TokenFile); err == nil {
			err := os.Remove(googleOauth2TokenFile)
			if err != nil {
				log.Fatalf("Unable to clear OAuth2 token cache file: %v", err)
				response.Message = "FAILED"
				response.Error = err.Error()
				c.AbortWithStatusJSON(http.StatusInternalServerError, response)
				return
			}
		} else {
			log.Fatalf("OAuth2 token cache file does not exists: %v", err)
			response.Message = "FAILED"
			response.Error = err.Error()
			c.AbortWithStatusJSON(http.StatusInternalServerError, response)
			return
		}
		c.JSON(http.StatusOK, response)
		return
	})
}
