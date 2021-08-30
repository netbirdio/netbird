package server

//func validateMAC(message, messageMAC, key []byte, t *testing.T) bool {
//      mac := hmac.New(sha1.New, key)
//
//      _, err := mac.Write(message)
//      if err != nil {
//              t.Error(err)
//      }
//
//      expectedMAC := mac.Sum(nil)
//
//      return hmac.Equal(messageMAC, expectedMAC)
//}
