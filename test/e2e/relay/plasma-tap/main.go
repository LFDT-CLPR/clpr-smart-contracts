// plasmatap: passive libp2p gossipsub listener for the Plasma consensus network.
// Connects to public bootstrap observers, subscribes to gossip topics and dumps
// every received message payload (raw bytes) to OUT/<unixnano>_<topic>.bin.
package main

import (
	"context"
	"crypto/rand"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/libp2p/go-libp2p"
	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/p2p/muxer/yamux"
	"github.com/libp2p/go-libp2p/p2p/security/noise"
	"github.com/libp2p/go-libp2p/p2p/transport/tcp"
	ma "github.com/multiformats/go-multiaddr"
)

func main() {
	out := flag.String("out", "captures", "output dir")
	peers := flag.String("peers", "", "comma separated multiaddrs")
	topics := flag.String("topics", "consensus-block,validator-records", "topics")
	dur := flag.Duration("dur", 5*time.Minute, "run duration")
	flag.Parse()
	os.MkdirAll(*out, 0o755)

	priv, _, err := crypto.GenerateSecp256k1Key(rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	h, err := libp2p.New(
		libp2p.Identity(priv),
		libp2p.Transport(tcp.NewTCPTransport),
		libp2p.Security(noise.ID, noise.New),
		libp2p.Muxer(yamux.ID, yamux.DefaultTransport),
		libp2p.ListenAddrStrings("/ip4/0.0.0.0/tcp/0"),
	)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("self %s", h.ID())
	ctx, cancel := context.WithTimeout(context.Background(), *dur)
	defer cancel()

	ps, err := pubsub.NewGossipSub(ctx, h, pubsub.WithMessageSignaturePolicy(pubsub.LaxNoSign))
	if err != nil {
		log.Fatal(err)
	}
	for _, s := range strings.Split(*peers, ",") {
		if s == "" {
			continue
		}
		ai, err := peer.AddrInfoFromP2pAddr(ma.StringCast(s))
		if err != nil {
			log.Printf("bad addr %s: %v", s, err)
			continue
		}
		c, cc := context.WithTimeout(ctx, 20*time.Second)
		if err := h.Connect(c, *ai); err != nil {
			log.Printf("connect %s: %v", ai.ID, err)
		} else {
			protos, _ := h.Peerstore().GetProtocols(ai.ID)
			log.Printf("connected %s protos=%v", ai.ID, protos)
		}
		cc()
	}
	n := 0
	for _, t := range strings.Split(*topics, ",") {
		topic, err := ps.Join(t)
		if err != nil {
			log.Fatal(err)
		}
		sub, err := topic.Subscribe()
		if err != nil {
			log.Fatal(err)
		}
		go func(t string, sub *pubsub.Subscription) {
			for {
				m, err := sub.Next(ctx)
				if err != nil {
					return
				}
				n++
				fn := filepath.Join(*out, fmt.Sprintf("%d_%s.bin", time.Now().UnixNano(), t))
				os.WriteFile(fn, m.Data, 0o644)
				log.Printf("msg topic=%s from=%s recv=%s len=%d", t, m.GetFrom(), m.ReceivedFrom, len(m.Data))
			}
		}(t, sub)
	}
	tk := time.NewTicker(15 * time.Second)
	for {
		select {
		case <-ctx.Done():
			log.Printf("done, %d messages", n)
			return
		case <-tk.C:
			log.Printf("peers=%d topicpeers(consensus-block)=%d msgs=%d", len(h.Network().Peers()), len(ps.ListPeers("consensus-block")), n)
		}
	}
}
