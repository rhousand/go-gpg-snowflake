package main

import (
	"context"
	"log"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
)

type KMS struct {
	client *kms.Client
}

func NewKMS() *KMS {
	// SECURITY FIX: Check AWS config loading error
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		log.Fatal("Failed to load AWS config:", err)
	}
	return &KMS{client: kms.NewFromConfig(cfg)}
}

func (k *KMS) GenerateDataKey(ctx context.Context, keyID string) (*kms.GenerateDataKeyOutput, error) {
	// SECURITY FIX: Add timeout if not already present
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
	}

	return k.client.GenerateDataKey(ctx, &kms.GenerateDataKeyInput{
		KeyId:   &keyID,
		KeySpec: "AES_256",
	})
}
