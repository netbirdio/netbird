//go:build internal_benchmark
// +build internal_benchmark

package server

func BenchmarkTest_GetAccountWithclaims(b *testing.B) {
	claims := jwtclaims.AuthorizationClaims{
		Domain:         "example.com",
		UserId:         "pvt-domain-user",
		DomainCategory: types.PrivateCategory,
	}

	publicClaims := jwtclaims.AuthorizationClaims{
		Domain:         "test.com",
		UserId:         "public-domain-user",
		DomainCategory: types.PublicCategory,
	}

	am, err := createManager(b)
	if err != nil {
		b.Fatal(err)
		return
	}
	id, err := am.getAccountIDWithAuthorizationClaims(context.Background(), claims)
	if err != nil {
		b.Fatal(err)
	}

	pid, err := am.getAccountIDWithAuthorizationClaims(context.Background(), publicClaims)
	if err != nil {
		b.Fatal(err)
	}

	users := genUsers("priv", 100)

	acc, err := am.Store.GetAccount(context.Background(), id)
	if err != nil {
		b.Fatal(err)
	}
	acc.Users = users

	err = am.Store.SaveAccount(context.Background(), acc)
	if err != nil {
		b.Fatal(err)
	}

	userP := genUsers("pub", 100)

	pacc, err := am.Store.GetAccount(context.Background(), pid)
	if err != nil {
		b.Fatal(err)
	}

	pacc.Users = userP

	err = am.Store.SaveAccount(context.Background(), pacc)
	if err != nil {
		b.Fatal(err)
	}

	b.Run("public without account ID", func(b *testing.B) {
		// b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := am.getAccountIDWithAuthorizationClaims(context.Background(), publicClaims)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("private without account ID", func(b *testing.B) {
		// b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := am.getAccountIDWithAuthorizationClaims(context.Background(), claims)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("private with account ID", func(b *testing.B) {
		claims.AccountId = id
		// b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := am.getAccountIDWithAuthorizationClaims(context.Background(), claims)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

}

func genUsers(p string, n int) map[string]*types.User {
	users := map[string]*types.User{}
	now := time.Now()
	for i := 0; i < n; i++ {
		users[fmt.Sprintf("%s-%d", p, i)] = &types.User{
			Id:         fmt.Sprintf("%s-%d", p, i),
			Role:       types.UserRoleAdmin,
			LastLogin:  util.ToPtr(now),
			CreatedAt:  now,
			Issued:     "api",
			AutoGroups: []string{"one", "two", "three", "four", "five", "six", "seven", "eight", "nine", "ten"},
		}
	}
	return users
}

func BenchmarkSyncAndMarkPeer(b *testing.B) {
	b.Setenv("NB_GET_ACCOUNT_BUFFER_INTERVAL", "0")

	benchCases := []struct {
		name   string
		peers  int
		groups int
		// We need different expectations for CI/CD and local runs because of the different performance characteristics
		minMsPerOpLocal float64
		maxMsPerOpLocal float64
		minMsPerOpCICD  float64
		maxMsPerOpCICD  float64
	}{
		{"Small", 50, 5, 1, 5, 3, 24},
		{"Medium", 500, 100, 7, 22, 10, 135},
		{"Large", 5000, 200, 65, 110, 60, 320},
		{"Small single", 50, 10, 1, 4, 3, 80},
		{"Medium single", 500, 10, 7, 13, 10, 43},
		{"Large 5", 5000, 15, 65, 80, 60, 220},
	}

	log.SetOutput(io.Discard)
	defer log.SetOutput(os.Stderr)
	for _, bc := range benchCases {
		b.Run(bc.name, func(b *testing.B) {
			manager, accountID, _, err := setupTestAccountManager(b, bc.peers, bc.groups)
			if err != nil {
				b.Fatalf("Failed to setup test account manager: %v", err)
			}
			ctx := context.Background()
			account, err := manager.Store.GetAccount(ctx, accountID)
			if err != nil {
				b.Fatalf("Failed to get account: %v", err)
			}
			peerChannels := make(map[string]chan *UpdateMessage)
			for peerID := range account.Peers {
				peerChannels[peerID] = make(chan *UpdateMessage, channelBufferSize)
			}
			manager.peersUpdateManager.peerChannels = peerChannels

			b.ResetTimer()
			start := time.Now()
			for i := 0; i < b.N; i++ {
				_, _, _, err := manager.SyncAndMarkPeer(context.Background(), account.Id, account.Peers["peer-1"].Key, nbpeer.PeerSystemMeta{Hostname: strconv.Itoa(i)}, net.IP{1, 1, 1, 1})
				assert.NoError(b, err)
			}

			duration := time.Since(start)
			msPerOp := float64(duration.Nanoseconds()) / float64(b.N) / 1e6
			b.ReportMetric(msPerOp, "ms/op")

			minExpected := bc.minMsPerOpLocal
			maxExpected := bc.maxMsPerOpLocal
			if os.Getenv("CI") == "true" {
				minExpected = bc.minMsPerOpCICD
				maxExpected = bc.maxMsPerOpCICD
			}

			if msPerOp < minExpected {
				b.Fatalf("Benchmark %s failed: too fast (%.2f ms/op, minimum %.2f ms/op)", bc.name, msPerOp, minExpected)
			}

			if msPerOp > (maxExpected * 1.1) {
				b.Fatalf("Benchmark %s failed: too slow (%.2f ms/op, maximum %.2f ms/op)", bc.name, msPerOp, maxExpected)
			}
		})
	}
}

func BenchmarkLoginPeer_ExistingPeer(b *testing.B) {
	b.Setenv("NB_GET_ACCOUNT_BUFFER_INTERVAL", "0")
	benchCases := []struct {
		name   string
		peers  int
		groups int
		// We need different expectations for CI/CD and local runs because of the different performance characteristics
		minMsPerOpLocal float64
		maxMsPerOpLocal float64
		minMsPerOpCICD  float64
		maxMsPerOpCICD  float64
	}{
		{"Small", 50, 5, 2, 10, 3, 35},
		{"Medium", 500, 100, 5, 40, 20, 140},
		{"Large", 5000, 200, 60, 100, 120, 320},
		{"Small single", 50, 10, 2, 10, 5, 40},
		{"Medium single", 500, 10, 5, 40, 10, 60},
		{"Large 5", 5000, 15, 60, 100, 60, 180},
	}

	log.SetOutput(io.Discard)
	defer log.SetOutput(os.Stderr)
	for _, bc := range benchCases {
		b.Run(bc.name, func(b *testing.B) {
			manager, accountID, _, err := setupTestAccountManager(b, bc.peers, bc.groups)
			if err != nil {
				b.Fatalf("Failed to setup test account manager: %v", err)
			}
			ctx := context.Background()
			account, err := manager.Store.GetAccount(ctx, accountID)
			if err != nil {
				b.Fatalf("Failed to get account: %v", err)
			}
			peerChannels := make(map[string]chan *UpdateMessage)
			for peerID := range account.Peers {
				peerChannels[peerID] = make(chan *UpdateMessage, channelBufferSize)
			}
			manager.peersUpdateManager.peerChannels = peerChannels

			b.ResetTimer()
			start := time.Now()
			for i := 0; i < b.N; i++ {
				_, _, _, err := manager.LoginPeer(context.Background(), PeerLogin{
					WireGuardPubKey: account.Peers["peer-1"].Key,
					SSHKey:          "someKey",
					Meta:            nbpeer.PeerSystemMeta{Hostname: strconv.Itoa(i)},
					UserID:          "regular_user",
					SetupKey:        "",
					ConnectionIP:    net.IP{1, 1, 1, 1},
				})
				assert.NoError(b, err)
			}

			duration := time.Since(start)
			msPerOp := float64(duration.Nanoseconds()) / float64(b.N) / 1e6
			b.ReportMetric(msPerOp, "ms/op")

			minExpected := bc.minMsPerOpLocal
			maxExpected := bc.maxMsPerOpLocal
			if os.Getenv("CI") == "true" {
				minExpected = bc.minMsPerOpCICD
				maxExpected = bc.maxMsPerOpCICD
			}

			if msPerOp < minExpected {
				b.Fatalf("Benchmark %s failed: too fast (%.2f ms/op, minimum %.2f ms/op)", bc.name, msPerOp, minExpected)
			}

			if msPerOp > (maxExpected * 1.1) {
				b.Fatalf("Benchmark %s failed: too slow (%.2f ms/op, maximum %.2f ms/op)", bc.name, msPerOp, maxExpected)
			}
		})
	}
}

func BenchmarkLoginPeer_NewPeer(b *testing.B) {
	b.Setenv("NB_GET_ACCOUNT_BUFFER_INTERVAL", "0")
	benchCases := []struct {
		name   string
		peers  int
		groups int
		// We need different expectations for CI/CD and local runs because of the different performance characteristics
		minMsPerOpLocal float64
		maxMsPerOpLocal float64
		minMsPerOpCICD  float64
		maxMsPerOpCICD  float64
	}{
		{"Small", 50, 5, 7, 20, 10, 80},
		{"Medium", 500, 100, 5, 40, 30, 140},
		{"Large", 5000, 200, 80, 120, 140, 390},
		{"Small single", 50, 10, 7, 20, 10, 80},
		{"Medium single", 500, 10, 5, 40, 20, 85},
		{"Large 5", 5000, 15, 80, 120, 80, 200},
	}

	log.SetOutput(io.Discard)
	defer log.SetOutput(os.Stderr)
	for _, bc := range benchCases {
		b.Run(bc.name, func(b *testing.B) {
			manager, accountID, _, err := setupTestAccountManager(b, bc.peers, bc.groups)
			if err != nil {
				b.Fatalf("Failed to setup test account manager: %v", err)
			}
			ctx := context.Background()
			account, err := manager.Store.GetAccount(ctx, accountID)
			if err != nil {
				b.Fatalf("Failed to get account: %v", err)
			}
			peerChannels := make(map[string]chan *UpdateMessage)
			for peerID := range account.Peers {
				peerChannels[peerID] = make(chan *UpdateMessage, channelBufferSize)
			}
			manager.peersUpdateManager.peerChannels = peerChannels

			b.ResetTimer()
			start := time.Now()
			for i := 0; i < b.N; i++ {
				_, _, _, err := manager.LoginPeer(context.Background(), PeerLogin{
					WireGuardPubKey: "some-new-key" + strconv.Itoa(i),
					SSHKey:          "someKey",
					Meta:            nbpeer.PeerSystemMeta{Hostname: strconv.Itoa(i)},
					UserID:          "regular_user",
					SetupKey:        "",
					ConnectionIP:    net.IP{1, 1, 1, 1},
				})
				assert.NoError(b, err)
			}

			duration := time.Since(start)
			msPerOp := float64(duration.Nanoseconds()) / float64(b.N) / 1e6
			b.ReportMetric(msPerOp, "ms/op")

			minExpected := bc.minMsPerOpLocal
			maxExpected := bc.maxMsPerOpLocal
			if os.Getenv("CI") == "true" {
				minExpected = bc.minMsPerOpCICD
				maxExpected = bc.maxMsPerOpCICD
			}

			if msPerOp < minExpected {
				b.Fatalf("Benchmark %s failed: too fast (%.2f ms/op, minimum %.2f ms/op)", bc.name, msPerOp, minExpected)
			}

			if msPerOp > (maxExpected * 1.1) {
				b.Fatalf("Benchmark %s failed: too slow (%.2f ms/op, maximum %.2f ms/op)", bc.name, msPerOp, maxExpected)
			}
		})
	}
}
