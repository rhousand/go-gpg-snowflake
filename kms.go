package main

import (
	"context"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
)

type KMS struct {
	client *kms.Client
}

func NewKMS() *KMS {
	cfg, _ := config.LoadDefaultConfig(context.TODO())
	return &KMS{client: kms.NewFromConfig(cfg)}
}

func (k *KMS) GenerateDataKey(ctx context.Context, keyID string) (*kms.GenerateDataKeyOutput, error) {
	return k.client.GenerateDataKey(ctx, &kms.GenerateDataKeyInput{
		KeyId:   &keyID,
		KeySpec: "AES_256",
	})
}
