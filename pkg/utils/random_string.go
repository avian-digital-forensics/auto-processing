package utils

import (
	"math/rand"
	"strings"
	"time"
)

const idCharacters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"

func GenerateId(length int) string {
	rand.Seed(time.Now().UnixNano())
	stringBuilder := strings.Builder{}
	stringBuilder.Grow(length)
	for i := 0; i < length; i++ {
		stringBuilder.WriteByte(idCharacters[rand.Intn(len(idCharacters))])
	}
	return stringBuilder.String()
}
