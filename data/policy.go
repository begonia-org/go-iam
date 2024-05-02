package data

import (
	"context"
	"fmt"

	"github.com/begonia-org/go-iam/biz"
	api "github.com/begonia-org/go-sdk/api/iam/v1"
	"github.com/gobwas/glob"
	"github.com/mitchellh/mapstructure"
	"github.com/spark-lence/tiga"
	"go.mongodb.org/mongo-driver/bson"
)

type PolicyRepoImpl struct {
	mongo *tiga.MongodbDao
	snk   *tiga.Snowflake
}

func NewPolicyRepoImpl(mongo *tiga.MongodbDao, snk *tiga.Snowflake) biz.PolicyRepo {
	return &PolicyRepoImpl{
		mongo: mongo,
		snk:   snk,
	}
}

func (d *PolicyRepoImpl) DecodePolicy(book interface{}, tag string) *api.Policy {
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
func (d *PolicyRepoImpl) Select(ctx context.Context, principal string, action string) ([]*api.Policy, error) {
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
func (d *PolicyRepoImpl) Get(ctx context.Context, uniqueKey string) (*api.Policy, error) {
	policiesMap, err := d.mongo.Find(ctx, "policy", bson.M{"unique_key": uniqueKey}, nil)
	if err != nil {
		return nil, fmt.Errorf("find policy error: %w", err)
	}
	if len(policiesMap) == 0 {
		return nil, fmt.Errorf("no policy found")
	}
	return d.DecodePolicy(policiesMap[0], "json"), nil
}
func (d *PolicyRepoImpl) Update(ctx context.Context, policy *api.Policy, mask []string) error {
	updateFields := bson.M{}
	for _, field := range mask {
		// 使用反射来获取 policy 中相应字段的值
		fieldDesc := policy.ProtoReflect().Descriptor().Fields().ByJSONName(field)
		// 将字段添加到更新文档中
		updateFields[field] = policy.ProtoReflect().Get(fieldDesc).Interface()
	}
	if len(updateFields) == 0 {
		return fmt.Errorf("no field to update")
	}
	// 构建更新语句，只更新指定的字段
	return d.mongo.Upsert(ctx, "policy", bson.M{"unique_key": policy.UniqueKey}, bson.M{"$set": updateFields})
}
func (d *PolicyRepoImpl) Insert(ctx context.Context, policy *api.Policy) (string, error) {
	policiesMap, err := d.mongo.Find(ctx, "policy", bson.M{"action": bson.M{"$in": policy.Actions}, "principal": policy.Principal}, nil)
	if err != nil {
		return "", fmt.Errorf("find policy error: %w", err)
	}
	for _, policyMap := range policiesMap {
		p := d.DecodePolicy(policyMap, "json")
		// policies = append(policies, p)
		if d.MatchResource(p.Resource, policy.Resource) {
			return "", d.mongo.Upsert(ctx, "policy", bson.M{"unique_key": p.UniqueKey}, bson.M{"$set": bson.M{"actions": policy.Actions}})
		}
	}
	policy.UniqueKey = d.snk.GenerateIDString()
	return policy.UniqueKey, d.mongo.Insert(ctx, "policy", policy)
}
func (d *PolicyRepoImpl) MatchResource(resourceRegx, target string) bool {
	g := glob.MustCompile(resourceRegx)
	return g.Match(target)
}
