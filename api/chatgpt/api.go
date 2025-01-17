package chatgpt

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"
	"os"
	"context"

	http "github.com/bogdanfinn/fhttp"
	"github.com/gin-gonic/gin"

	"github.com/linweiyuan/go-chatgpt-api/api"
	"github.com/linweiyuan/go-logger/logger"
	"github.com/go-redis/redis/v8"
)

func CreateConversation(c *gin.Context) {
	var request CreateConversationRequest
	if err := c.BindJSON(&request); err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, api.ReturnMessage(parseJsonErrorMessage))
		return
	}

	if request.ConversationID == nil || *request.ConversationID == "" {
		request.ConversationID = nil
	}

	if len(request.Messages) != 0 {
		message := request.Messages[0]
		if message.Author.Role == "" {
			message.Author.Role = defaultRole
		}

		if message.Metadata == nil {
			message.Metadata = map[string]string{}
		}

		request.Messages[0] = message
	}

	if request.ArkoseToken == "" {
		arkoseToken, err := api.GetArkoseToken()
		if err != nil || arkoseToken == "" {
			c.AbortWithStatusJSON(http.StatusForbidden, api.ReturnMessage(err.Error()))
			return
		}

		request.ArkoseToken = arkoseToken
	}

	resp, done := sendConversationRequest(c, request)
	if done {
		return
	}

	handleConversationResponse(c, resp, request)
}

type RedisData struct {
	ExpireSeconds int64 `json:"expire_seconds"`
	Time          int64 `json:"time"`
}

func sendConversationRequest(c *gin.Context, request CreateConversationRequest) (*http.Response, bool) {
	jsonBytes, _ := json.Marshal(request)
	req, _ := http.NewRequest(http.MethodPost, api.ChatGPTApiUrlPrefix+"/backend-api/conversation", bytes.NewBuffer(jsonBytes))
	req.Header.Set("User-Agent", api.UserAgent)
	req.Header.Set(api.AuthorizationHeader, api.GetAccessToken(c))
	req.Header.Set("Accept", "text/event-stream")
	if api.PUID != "" {
		req.Header.Set("Cookie", "_puid="+api.PUID)
	}
	resp, err := api.Client.Do(req)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, api.ReturnMessage(err.Error()))
		return nil, true
	}

	if resp.StatusCode != http.StatusOK {
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusUnauthorized {
			logger.Error(fmt.Sprintf(api.AccountDeactivatedErrorMessage, c.GetString(api.EmailKey)))
			responseMap := make(map[string]interface{})
			json.NewDecoder(resp.Body).Decode(&responseMap)
			c.AbortWithStatusJSON(resp.StatusCode, responseMap)
			return nil, true
		}

		req, _ := http.NewRequest(http.MethodGet, api.ChatGPTApiUrlPrefix+"/backend-api/models?history_and_training_disabled=false", nil)
		req.Header.Set("User-Agent", api.UserAgent)
		req.Header.Set(api.AuthorizationHeader, api.GetAccessToken(c))
		response, err := api.Client.Do(req)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, api.ReturnMessage(err.Error()))
			return nil, true
		}

		defer response.Body.Close()
		modelAvailable := false
		var getModelsResponse GetModelsResponse
		json.NewDecoder(response.Body).Decode(&getModelsResponse)
		for _, model := range getModelsResponse.Models {
			if model.Slug == request.Model {
				modelAvailable = true
				break
			}
		}
		if !modelAvailable {
			c.AbortWithStatusJSON(http.StatusForbidden, api.ReturnMessage(noModelPermissionErrorMessage))
			return nil, true
		}

		data, _ := io.ReadAll(resp.Body)
		logger.Warn(string(data))

		responseMap := make(map[string]interface{})
		json.NewDecoder(resp.Body).Decode(&responseMap)
		logger.Warn("sendConversationRequest1")
		c.AbortWithStatusJSON(resp.StatusCode, responseMap)
        logger.Warn("sendConversationRequest2")

        var jsonMap map[string]interface{}
        err2 := json.Unmarshal([]byte(data), &jsonMap)
        if err2 != nil {
            logger.Warn("解码 JSON 数据时发生错误:")
        }
        if detail, ok := jsonMap["detail"].(map[string]interface{}); ok {
            if message, ok := detail["message"].(string); ok {
                fmt.Println("Message:", message)
            }

            if code, ok := detail["code"].(string); ok {
                fmt.Println("Code:", code)
            }

            if clearsIn, ok := detail["clears_in"].(float64); ok {
                fmt.Println("ClearsIn:", int(clearsIn))
                port := os.Getenv("PORT")
                location, err := time.LoadLocation("Asia/Shanghai")
                if err != nil {
                    fmt.Println("加载时区失败:", err)
                    return nil, true
                }
                // 获取当前时间戳（秒）
                currentTime := time.Now().In(location).Unix()
                data := RedisData{
                    ExpireSeconds: int64(clearsIn),
                    Time:          currentTime,
                }
                jsonData, err := json.Marshal(data)
                if err != nil {
                    fmt.Println("JSON序列化时发生错误:", err)
                    return nil, true
                }
                jsonStr := string(jsonData)
                expiration := time.Duration(int(clearsIn)) * time.Second
                SetRedisKeyWithExpiration("chatgpt4:"+port+":exceed", jsonStr, expiration)
            }
        }

		return nil, true
	}

	return resp, false
}

func SetRedisKeyWithExpiration(key, value string, expiration time.Duration) error {
    redisHOST := os.Getenv("REDIS_HOST")
    redisPasswd := os.Getenv("REDIS_PASSWD")
    fmt.Println("Redis:", redisHOST)
	// 创建一个Redis客户端
	client := redis.NewClient(&redis.Options{
		Addr:     redisHOST, // 你的Redis服务器地址和端口
		Password: redisPasswd, // 如果有密码的话
		DB:       0,               // 默认数据库
	})
    fmt.Println("Redis key:", key)
	// 使用上下文设置键和值，以及过期时间
	ctx := context.Background()
	err := client.Set(ctx, key, value, expiration).Err()
	if err != nil {
		return err
	}

	return nil
}


func handleConversationResponse(c *gin.Context, resp *http.Response, request CreateConversationRequest) {
	c.Writer.Header().Set("Content-Type", "text/event-stream; charset=utf-8")

	isMaxTokens := false
	continueParentMessageID := ""
	continueConversationID := ""

	defer resp.Body.Close()
	reader := bufio.NewReader(resp.Body)
	for {
		if c.Request.Context().Err() != nil {
			break
		}

		line, err := reader.ReadString('\n')
		if err != nil {
			break
		}

		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "event") ||
			strings.HasPrefix(line, "data: 20") ||
			strings.HasPrefix(line, `data: {"conversation_id"`) ||
			line == "" {
			continue
		}

		responseJson := line[6:]
		if strings.HasPrefix(responseJson, "[DONE]") && isMaxTokens && request.AutoContinue {
			continue
		}

		// no need to unmarshal every time, but if response content has this "max_tokens", need to further check
		if strings.TrimSpace(responseJson) != "" && strings.Contains(responseJson, responseTypeMaxTokens) {
			var createConversationResponse CreateConversationResponse
			json.Unmarshal([]byte(responseJson), &createConversationResponse)
			message := createConversationResponse.Message
			if message.Metadata.FinishDetails.Type == responseTypeMaxTokens && createConversationResponse.Message.Status == responseStatusFinishedSuccessfully {
				isMaxTokens = true
				continueParentMessageID = message.ID
				continueConversationID = createConversationResponse.ConversationID
			}
		}

		c.Writer.Write([]byte(line + "\n\n"))
		c.Writer.Flush()
	}

	if isMaxTokens && request.AutoContinue {
		continueConversationRequest := CreateConversationRequest{
			ArkoseToken:                request.ArkoseToken,
			HistoryAndTrainingDisabled: request.HistoryAndTrainingDisabled,
			Model:                      request.Model,
			TimezoneOffsetMin:          request.TimezoneOffsetMin,

			Action:          actionContinue,
			ParentMessageID: continueParentMessageID,
			ConversationID:  &continueConversationID,
		}
		resp, done := sendConversationRequest(c, continueConversationRequest)
		if done {
			return
		}

		handleConversationResponse(c, resp, continueConversationRequest)
	}
}
