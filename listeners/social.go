package listeners

import (
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
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"golang.org/x/net/context"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/gmail/v1"
)

type MessagesCache struct {
	Ids    map[string]bool     `json:"ids"`
	Hashes map[string][]string `json:"hashes"`
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

type IntelligenceIndicators struct {
	Subject  string `json:"subject_re"`
	Content  string `json:"content_re"`
	From     string `json:"from_email"`
	Event    string `json:"event"`
	Platform string `json:"platform"`
}

type IndicatorOfInterest struct {
	Listener_id int    `json:"listener_id"`
	Source_id   int    `json:"source_id"`
	Description string `json:"description"`
	Email       string `json:"email"`
	Sha256_hash string `json:"sha256_hash"`
}

var intelligenceIndicators []IntelligenceIndicators

func init() {
	intelligenceIndicators = []IntelligenceIndicators{
		IntelligenceIndicators{
			Subject:  "^.*, please add me to your LinkedIn network$",
			Content:  "^Hi.*, I&#39;d like to join your LinkedIn network\\. LinkedIn.*, I&#39;d like to join your LinkedIn network\\. .*$",
			From:     "invitations@linkedin.com",
			Event:    "attempted_network_connection",
			Platform: "LINKEDIN"},
		IntelligenceIndicators{
			Subject:  "^.*, start a conversation with your new connection, .*$",
			Content:  "^See.*connections, experience, and more LinkedIn.*has accepted your invitation\\. Let&#39;s start a conversation\\..*$",
			From:     "invitations@linkedin.com",
			Event:    "successful_network_connection",
			Platform: "LINKEDIN"},
		IntelligenceIndicators{
			Subject:  "^.*wants to be friends on Facebook$",
			Content:  "^.*wants to be friends with you on Facebook\\..*Confirm request Facebook.*wants to be friends with you on Facebook.*Confirm request See all requests.*$",
			From:     "notification@facebookmail.com",
			Event:    "attempted_network_connection",
			Platform: "FACEBOOK"},
	}
}

func getClient(config *oauth2.Config) *http.Client {
	tokFile := "token.json"
	tok, err := tokenFromFile(tokFile)
	if err != nil {
		tok = getTokenFromWeb(config)
		saveToken(tokFile, tok)
	}
	return config.Client(context.Background(), tok)
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
			return IndicatorOfInterest{Listener_id: 1, Source_id: 1, Description: indicator.Event, Email: email, Sha256_hash: generateSha256Hash(indicator.Platform, email, indicator.Event, subject, content)}, nil
		}
	}
	return IndicatorOfInterest{Listener_id: 1, Source_id: 1, Description: "N.A", Email: email, Sha256_hash: ""}, errors.New("Email does not contain intelligence")
}

func harvest() MessagesCache {
	b, err := ioutil.ReadFile("/run/secrets/credentials.json")
	if err != nil {
		log.Fatalf("Unable to read client secret file: %v", err)
	}

	config, err := google.ConfigFromJSON(b, gmail.GmailReadonlyScope)
	if err != nil {
		log.Fatalf("Unable to parse client secret file to config: %v", err)
	}
	client := getClient(config)

	srv, err := gmail.New(client)
	if err != nil {
		log.Fatalf("Unable to retrieve Gmail client: %v", err)
	}
	messagsCacheFile := "messages_cache.json"
	messagesCache := readMessagesCache(messagsCacheFile)

	user := "me"
	r, err := srv.Users.Messages.List(user).Do()
	if err != nil {
		log.Fatalf("Unable to retrieve emails: %v", err)
	}
	if len(r.Messages) == 0 {
		fmt.Println("No emails found.")
		return MessagesCache{Ids: make(map[string]bool), Hashes: make(map[string][]string)}
	}
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
				return MessagesCache{Ids: make(map[string]bool), Hashes: make(map[string][]string)}
			}
			hashes := messagesCache.Hashes[indicator.Sha256_hash]
			// Do something here to send the intelligence object to a endpoint
			// To discuss with the team on the action taken if a similar intelligence is found
			if len(hashes) > 0 {
				fmt.Println("Similar hash value found")
			}
			messagesCache.Hashes[indicator.Sha256_hash] = append(hashes, message.Id)
			fmt.Println(string(jsonObj))
		}

	}
	dumpMessagesCache(messagesCache, messagsCacheFile)
	return messagesCache
}

func main() {
	// harvest to run a check with all the emails inside the inbox
	harvest()
	messagesCacheFile := "messages_cache.json"
	r := gin.Default()
	r.GET("/ping", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"message": "pong",
		})
	})
	r.GET("/harvest", func(c *gin.Context) {
		// Consider making this an asynchronious task
		// returns a job id
		messagesCache := harvest()
		c.JSON(http.StatusOK, messagesCache)
	})
	r.GET("/cache", func(c *gin.Context) {
		messagesCache := readMessagesCache(messagesCacheFile)
		c.JSON(http.StatusOK, messagesCache)
	})
	r.Run(":3002")
}
