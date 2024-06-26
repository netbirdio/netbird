package server

import (
	"github.com/mitchellh/hashstructure/v2"
	log "github.com/sirupsen/logrus"
)

func updateAccountPeers(account *Account) {
	//start := time.Now()
	//defer func() {
	//	duration := time.Since(start)
	//	log.Printf("Finished execution of updateAccountPeers, took %v\n", duration)
	//}()

	peers := account.GetPeers()

	approvedPeersMap := make(map[string]struct{}, len(peers))
	for _, peer := range peers {
		approvedPeersMap[peer.ID] = struct{}{}
	}

	for _, peer := range peers {
		//if !am.peersUpdateManager.HasChannel(peer.ID) {
		//	log.Tracef("peer %s doesn't have a channel, skipping network map update", peer.ID)
		//	continue
		//}

		_ = account.GetPeerNetworkMap(peer.ID, "netbird.io", approvedPeersMap)

		//remotePeerNetworkMap := account.GetPeerNetworkMap(peer.ID, am.dnsDomain, approvedPeersMap)
		//postureChecks := am.getPeerPostureChecks(account, peer)
		//update := toSyncResponse(nil, peer, nil, remotePeerNetworkMap, am.GetDNSDomain(), postureChecks)
		//am.peersUpdateManager.SendUpdate(peer.ID, &UpdateMessage{Update: update})
	}
}

func updateAccountPeersWithHash(account *Account) {
	//start := time.Now()
	var skipUpdate int
	defer func() {
		//duration := time.Since(start)
		//log.Printf("Finished execution of updateAccountPeers, took %v\n", duration.Nanoseconds())
		//log.Println("not updated peers: ", skipUpdate)
	}()

	peers := account.GetPeers()
	approvedPeersMap := make(map[string]struct{}, len(peers))
	for _, peer := range peers {
		approvedPeersMap[peer.ID] = struct{}{}
	}

	for _, peer := range peers {
		//if !am.peersUpdateManager.HasChannel(peer.ID) {
		//	log.Tracef("peer %s doesn't have a channel, skipping network map update", peer.ID)
		//	continue
		//}

		remotePeerNetworkMap := account.GetPeerNetworkMap(peer.ID, "netbird.io", approvedPeersMap)
		//log.Println("firewall rules: ", len(remotePeerNetworkMap.FirewallRules))
		hashStr, err := hashstructure.Hash(remotePeerNetworkMap, hashstructure.FormatV2, &hashstructure.HashOptions{
			ZeroNil:         true,
			IgnoreZeroValue: true,
			SlicesAsSets:    true,
			UseStringer:     true,
		})
		if err != nil {
			log.Errorf("failed to generate network map hash: %v", err)
		} else {
			if peer.NetworkMapHash == hashStr {
				//log.Debugf("not sending network map update to peer: %s as there is nothing new", peer.ID)
				skipUpdate++
				continue
			}
			peer.NetworkMapHash = hashStr
		}

		//postureChecks := am.getPeerPostureChecks(account, peer)
		//update := toSyncResponse(nil, peer, nil, remotePeerNetworkMap, am.GetDNSDomain(), postureChecks)
		//am.peersUpdateManager.SendUpdate(peer.ID, &UpdateMessage{Update: update})update
	}
}
