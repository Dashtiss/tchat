package client

import (
	"errors"
	"fmt"
	"log"
	"strings"
	"tchat/internal/message"
	"tchat/internal/parsing"
	"tchat/internal/protocol"
	"tchat/internal/types"
	"tchat/internal/validation"
	"time"

	"github.com/ProtonMail/gopenpgp/v3/crypto"
	"github.com/ProtonMail/gopenpgp/v3/profile"
)

func ParseFromInput(ctx *clientContext, userID, input string, pubkey *crypto.Key) (protocol.SerializableMessage, error) {
	input = strings.ReplaceAll(input, "\n", "")
	parsedInput := strings.Split(input, " ")
	msgType := parsedInput[0]
	if ctx.currentChannel != nil {
		return parseChannelInput(ctx, userID, input, msgType, pubkey)
	}
	switch msgType {
	case "/exit":
		return protocol.DisconnectMessage{}, nil
	case "/channel":
		if len(parsedInput) < 2 {
			return nil, errors.New("insufficient arguments")
		}
		if parsedInput[1] == "list" {
			return protocol.NewChannelsMessage(userID, message.TypeChannelsGet, nil), nil
		}
		if parsedInput[1] == "join" {
			if len(parsedInput) < 3 {
				return nil, errors.New("no channel name was provided")
			}
			channelName := parsedInput[2]
			return protocol.NewChannelsMessage(userID, message.TypeChannelsJoin, []byte(channelName)), nil
		}
		if parsedInput[1] == "create" {
			if len(parsedInput) < 3 {
				return nil, errors.New("no channel name was provided")
			}
			channelName := parsedInput[2]
			ch := types.Channel{}
			ch.Name = channelName

			return protocol.NewChannelsMessage(userID, message.TypeChannelsCreate, parsing.MustJSON(ch)), nil
		}

		return nil, errors.New("invalid arguments")
	default:
		return nil, validation.ErrMessageTypeNotImplemented
	}
}

func parseChannelInput(ctx *clientContext, userID, input string, msgType string, pubkey *crypto.Key) (protocol.SerializableMessage, error) {
	switch msgType {
	case "/message":
		msgWithoutPrefix := strings.TrimPrefix(input, "/message ")

		pgp := crypto.PGPWithProfile(profile.RFC9580())

		recipients, err := crypto.NewKeyRing(pubkey)
		//err = recipients.AddKey(key)

		if err != nil {
			log.Fatal("Error: ", err.Error())
		}

		encHandle, err := pgp.Encryption().Recipients(recipients).New()

		if err != nil {
			log.Fatal("Error: ", err.Error())
		}

		encMsg, err := encHandle.Encrypt([]byte(msgWithoutPrefix))

		if err != nil {
			log.Fatal("Error: ", err.Error())
		}

		armoredMsg, err := encMsg.Armor()

		if err != nil {
			log.Fatal("Error: ", err.Error())
		}

		b := types.Message{
			UserID:      userID,
			Channel:     ctx.currentChannel.Name,
			DisplayName: userID,
			Content:     armoredMsg,
			CreatedAt:   time.Now(),
		}.MustJSON()

		return protocol.NewChannelsMessage(userID, message.TypeChannelNewMessage, b), nil
	case "/leave":
		return protocol.NewChannelsMessage(userID, message.TypeChannelLeave, nil), nil
	}
	return nil, fmt.Errorf("%s: %s", validation.ErrInvalidMessageType, msgType)

}
