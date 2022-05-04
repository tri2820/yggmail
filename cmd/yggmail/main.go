/*
 *  Copyright (c) 2021 Neil Alexander
 *
 *  This Source Code Form is subject to the terms of the Mozilla Public
 *  License, v. 2.0. If a copy of the MPL was not distributed with this
 *  file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package main

import (
	"bufio"
	"crypto/ed25519"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"time"

	// "github.com/fatih/color"

	// "github.com/neilalexander/yggmail/internal/config"

	// "github.com/neilalexander/yggmail/internal/smtpsender"
	"github.com/fatih/color"
	"github.com/neilalexander/yggmail/internal/transport"
)

type peerAddrList []string

func (i *peerAddrList) String() string {
	return strings.Join(*i, ", ")
}

func (i *peerAddrList) Set(value string) error {
	*i = append(*i, value)
	return nil
}

func server(c net.Conn) {
	fmt.Printf("Serving %s\n", c.RemoteAddr().String())

	err := c.(*net.TCPConn).SetKeepAlive(true)
	if err != nil {
		fmt.Println(err)
		return
	}

	err = c.(*net.TCPConn).SetKeepAlivePeriod(5 * time.Second)
	if err != nil {
		fmt.Println(err)
		return
	}

	for {
		// Receive
		netData, err := bufio.NewReader(c).ReadString('\n')
		if err != nil {
			fmt.Println(err)
			return
		}
		fmt.Printf(">> %s", netData)
		// Send
		result := time.Now().String() + "\n"
		c.Write([]byte(string(result)))
	}
}

func client(c net.Conn) {
	for {
		// Send
		reader := bufio.NewReader(os.Stdin)
		fmt.Print(">> ")
		text, _ := reader.ReadString('\n')
		fmt.Fprintf(c, text+"\n")
		// Receive
		message, _ := bufio.NewReader(c).ReadString('\n')
		fmt.Printf("<< %s", message)
	}
}

func main() {
	rawlog := log.New(color.Output, "", 0)
	green := color.New(color.FgGreen).SprintfFunc()
	log := log.New(rawlog.Writer(), fmt.Sprintf("[  %s  ] ", green("Yggmail")), log.LstdFlags|log.Lmsgprefix)

	var peerAddrs peerAddrList
	secret := flag.String("sk", "", "IMAP listen address")
	ping := flag.String("ping", "", "Send ping to address")
	multicast := flag.Bool("multicast", false, "Connect to Yggdrasil peers on your LAN")
	flag.Var(&peerAddrs, "peer", "Connect to a specific Yggdrasil static peer (this option can be given more than once)")
	flag.Parse()

	if flag.NFlag() == 0 {
		fmt.Println("Yggmail must be started with either one or more Yggdrasil peers")
		fmt.Println("specified, multicast enabled, or both.")
		fmt.Println()
		fmt.Println("Available options:")
		fmt.Println()
		flag.PrintDefaults()
		os.Exit(0)
	}

	// "secret" -> sk -> pk
	sk := make(ed25519.PrivateKey, ed25519.PrivateKeySize)
	if *secret == "" {
		_, sk, _ = ed25519.GenerateKey(nil)
	} else {
		skBytes, err := hex.DecodeString(*secret)
		if err != nil {
			panic(err)
		}
		copy(sk, skBytes)
	}

	pk := sk.Public().(ed25519.PublicKey)
	log.Printf("Yggdrasil address: %s\n", hex.EncodeToString(pk))
	log.Printf("Secret key: %s\n", hex.EncodeToString(sk))

	switch {

	case (multicast == nil || !*multicast) && len(peerAddrs) == 0:
		log.Printf("You must specify either -peer, -multicast or both!")
		os.Exit(0)
	}

	transport, err := transport.NewYggdrasilTransport(rawlog, sk, pk, peerAddrs, *multicast)
	if err != nil {
		panic(err)
	}

	if *ping == "" {
		// Server
		l := transport.Listener()
		defer l.Close()
		for {
			c, err := l.Accept()
			if err != nil {
				fmt.Println(err)
				return
			}
			go server(c)
		}
	} else {
		// Client
		log.Println("Client code running")
		c, err := transport.Dial(*ping)
		if err != nil {
			panic(err)
		}
		client(c)
	}
}
