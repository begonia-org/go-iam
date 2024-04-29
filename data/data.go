package data

import (
	"context"
	"fmt"

	api "github.com/begonia-org/go-iam/api/v1"
	"github.com/mitchellh/mapstructure"
	"github.com/spark-lence/tiga"
	"go.mongodb.org/mongo-driver/bson"
)

type Data interface {
	Insert()
	Select(ctx context.Context, principal string, action, resource string) ([]*api.Policy, error)
	Update()
	Delete()
}
type DataImpl struct {
	mongo *tiga.MongodbDao
}

func NewDataImpl(mongo *tiga.MongodbDao) *DataImpl {
	return &DataImpl{
		mongo: mongo,
	}
}
func (d *DataImpl) DecodePolicy(book interface{}, tag string) *api.Policy {
	var item api.Policy
	cfg := &mapstructure.DecoderConfig{
		Metadata: nil,
		Result:   &item,
		TagName:  tag,
	}
	decoder, _ := mapstructure.NewDecoder(cfg)
	decoder.Decode(book)
	return &item
}
func (d *DataImpl) Select(ctx context.Context, principal string, action string) ([]*api.Policy, error) {
	filter := bson.M{"action": action, "principal": principal}

	policiesMap, err := d.mongo.Find(ctx, "policy", filter, nil)
	if err != nil {
		return nil, err
	}
	if len(policiesMap) == 0 {
		return nil, fmt.Errorf("no policy found")
	}
	policies := make([]*api.Policy, 0, len(policiesMap))
	for _, policyMap := range policiesMap {
		policy := d.DecodePolicy(policyMap, "json")
		policies = append(policies, policy)
	}
	return policies, nil
}
