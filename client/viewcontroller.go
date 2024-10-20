package client

import (
	"encoding/json"
	"fmt"
	"log"
	"tchat/internal/message"
	"tchat/internal/protocol"
	"tchat/internal/types"
	"time"

	"github.com/ProtonMail/gopenpgp/v3/crypto"
	"github.com/ProtonMail/gopenpgp/v3/profile"
)

type viewController struct {
	onChannelJoinCh chan types.Channel
	onChannelQuitCh chan struct{}
	renderTextCh    chan []string

	ctx *clientContext
}

func newViewController(ctx *clientContext, renderTextCh chan []string, onChannelJoinCh chan types.Channel, onChannelQuit chan struct{}) *viewController {
	return &viewController{
		ctx:             ctx,
		renderTextCh:    renderTextCh,
		onChannelJoinCh: onChannelJoinCh,
		onChannelQuitCh: onChannelQuit,
	}
}

func (r *viewController) onNewMessage(b []byte, key *crypto.Key) {
	copyB := make([]byte, len(b))
	copy(copyB, b)
	msg, err := message.RawFromBytes(copyB)
	if err != nil {
		r.renderTextCh <- []string{fmt.Errorf("could not unmarshal response: %s", err.Error()).Error()}
		return
	}
	msgType := message.Type(msg["type"].(string))
	if !msgType.IsValid() {
		r.renderTextCh <- []string{fmt.Sprintf("invalid message type received: %s", msgType)}
	}
	if msgType.IsChannelMsg() {
		r.renderChannelMessage(msgType, b, key)
	}
}

func (r *viewController) renderChannelMessage(msgType message.Type, b []byte, key *crypto.Key) {
	switch msgType {
	case message.TypeChannelsGetResponse:
		c := protocol.ChannelsMessage{}
		if err := json.Unmarshal(b, &c); err != nil {
			log.Fatalf("could not unmarshal response: %s", err.Error())
		}
		var channels []types.Channel
		_ = json.Unmarshal(c.Payload, &channels)
		r.renderTextCh <- []string{"#### Channels ####", fmt.Sprintf("- %d channels found -", len(channels))}
		for _, ch := range channels {
			r.renderTextCh <- []string{fmt.Sprintf("\t* %s (%d online)", ch.Name, ch.CurrentUsers)}
		}
	case message.TypeChannelsJoinResponse:
		c := protocol.ChannelsMessage{}
		if err := json.Unmarshal(b, &c); err != nil {
			r.renderTextCh <- []string{fmt.Sprintf("could not unmarshal response: %s", err.Error())}
		}
		channel := types.Channel{}
		_ = json.Unmarshal(c.Payload, &channel)
		if err := r.ctx.SetChannel(&channel); err != nil {
			log.Fatalf("user tried to join a channel while being in a channel already")
		}
		r.onChannelJoinCh <- channel
		r.renderTextCh <- []string{fmt.Sprintf("#### Joined Channel %s - There are currently %d users online ####", channel.Name, channel.CurrentUsers)}
		r.renderTextCh <- []string{"#### Type /leave to leave the channel ####"}
		r.renderTextCh <- []string{"#### Type /channels to see all available channels ####"}
		r.renderTextCh <- []string{"#### Type /users to see all users in the channel ####"}
		r.renderTextCh <- []string{"#### Type /msg <user> <message> to send a private message ####"}
		r.renderTextCh <- []string{"----------------------------------------------------------", fmt.Sprintf("Channel Message: %s", channel.WelcomeMessage)}
	case message.TypeChannelNewMessage:
		c := protocol.ChannelsMessage{}
		if err := json.Unmarshal(b, &c); err != nil {
			r.renderTextCh <- []string{fmt.Sprintf("could not unmarshal response: %s", string(b))}
		}
		msg := types.Message{}
		_ = json.Unmarshal(c.Payload, &msg)

		pgp := crypto.PGPWithProfile(profile.RFC9580())

		if crypto.IsPGPMessage(msg.Content) {
			decHandle, err := pgp.Decryption().DecryptionKey(key).New()
			if err != nil {
				log.Fatal("Error: ", err.Error())
			}
			decrypted, err := decHandle.Decrypt([]byte(msg.Content), crypto.Armor)
			if err != nil {
				log.Fatal("Error: ", err.Error())
			}

			msg.Content = decrypted.String()

		}

		r.renderTextCh <- []string{fmt.Sprintf("%s %s:    %s", getTimeString(msg.CreatedAt), msg.UserID, msg.Content)}
	case message.TypeChannelsCreateResponse:
		r.renderTextCh <- []string{"channel created successfully. You're the admin and you can join it with /channel join <channelname> and then follow the instructions to configure it"}
	case message.TypeChannelsLeaveResponse:
		_ = r.ctx.RemoveChannel()
		r.renderTextCh <- []string{"Good Bye"}
		r.renderTextCh <- []string{"Good Bye 123"}
		r.onChannelQuitCh <- struct{}{}
	case message.TypeChannelUserDisconnectedMessage:
		c := protocol.ChannelsMessage{}
		if err := json.Unmarshal(b, &c); err != nil {
			r.renderTextCh <- []string{fmt.Sprintf("could not unmarshal response: %s", err.Error())}
		}
		userID := string(c.Payload)
		r.renderTextCh <- []string{fmt.Sprintf("%s left the channel.", userID)}
	default:
		r.renderTextCh <- []string{fmt.Sprintf("unexpected message type: %s", msgType)}
	}
}

func getTimeString(t time.Time) string {
	return t.Format("2006-01-02 15:04:05")
}
