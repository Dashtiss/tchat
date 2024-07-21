package serverdata

import (
	"fmt"
	"log"
	"net"
	"slices"
	"sync"
	message2 "tchat/internal/message"
	"tchat/internal/protocol"
	"tchat/internal/types"
	"time"
)

type ChannelRepository struct {
	mutex        sync.Mutex
	channelList  []*types.Channel
	channelConns map[string][]net.Conn
}

func NewChannelRepository() *ChannelRepository {
	return &ChannelRepository{
		mutex:        sync.Mutex{},
		channelConns: make(map[string][]net.Conn),
		channelList: []*types.Channel{
			{
				Name:           "general",
				Owner:          "system",
				CreatedAt:      time.Now(),
				CurrentUsers:   0,
				TotalMessages:  0,
				WelcomeMessage: "Welcome to the Jungle",
			},
		},
	}
}

func (cr *ChannelRepository) GetAll() []types.Channel {
	chL := make([]types.Channel, len(cr.channelList))
	for i, c := range cr.channelList {
		chL[i] = *c
	}

	return chL
}

func (cr *ChannelRepository) CreateChannel(c types.Channel) error {
	cr.mutex.Lock()
	defer cr.mutex.Unlock()

	if slices.ContainsFunc(cr.channelList, func(channel *types.Channel) bool {
		return channel.Name == c.Name
	}) {
		return fmt.Errorf("channel with name %s exists already", c.Name)
	}
	cr.channelList = append(cr.channelList, &c)

	return nil
}

func (cr *ChannelRepository) OnNewUser(channelName, userID string, conn net.Conn) (*types.Channel, error) {

	for i, ch := range cr.channelList {
		if ch.Name == channelName {
			cr.mutex.Lock()
			cr.channelList[i].CurrentUsers++
			cr.channelConns[channelName] = append(cr.channelConns[channelName], conn)
			cr.mutex.Unlock()
			return ch, nil
		}
	}

	return nil, fmt.Errorf("channel with name %s not found", channelName)
}

func (cr *ChannelRepository) NewMessage(channelName string, msg types.Message) error {
	channelFound := false
	for _, ch := range cr.channelList {
		if ch.Name == channelName {
			cr.mutex.Lock()
			ch.TotalMessages++
			cr.mutex.Unlock()
			channelFound = true
		}
	}

	if !channelFound {
		return fmt.Errorf("channel with name %s not found", channelName)
	}

	wg := sync.WaitGroup{}
	wg.Add(len(cr.channelConns[channelName]))
	for _, conn := range cr.channelConns[channelName] {
		go func(wg *sync.WaitGroup) {
			if err := message2.Transmit(conn,
				protocol.NewChannelsMessage(msg.UserID, message2.TypeChannelNewMessage, msg.MustJSON()).Bytes()); err != nil {
				cr.mutex.Lock()
				log.Printf("conn %s not reachable, removing from channel %s", conn.RemoteAddr(), channelName)
				allCons := cr.channelConns[channelName]
				for i, c := range allCons {
					if c == conn {
						cr.channelConns[channelName] = append(allCons[:i], allCons[i+1:]...)
					}
				}
				cr.mutex.Unlock()
			}
			wg.Done()
		}(&wg)
	}

	wg.Wait()

	return nil
}
