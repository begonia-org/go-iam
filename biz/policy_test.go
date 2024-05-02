package biz_test

import (
	"context"
	"testing"

	api "github.com/begonia-org/go-sdk/api/iam/v1"
	"github.com/begonia-org/go-iam/data"
	c "github.com/smartystreets/goconvey/convey"
	"github.com/spark-lence/tiga"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo/integration/mtest"
)

func TestCreate(t *testing.T) {
	c.Convey("TestCreate", t, func() {
		mt := mtest.New(t, mtest.NewOptions().ClientType(mtest.Mock).DatabaseName("test").CreateClient(true).CreateCollection(true))
		snk, _ := tiga.NewSnowflake(1)
		mt.RunOpts("instert", mtest.NewOptions().ClientType(mtest.Mock).DatabaseName("test").CreateClient(true).CreateCollection(true).CollectionName("policy"), func(_mt *mtest.T) {
			mt = _mt
			mt.AddMockResponses(mtest.CreateCursorResponse(1, "test.policy", mtest.FirstBatch))
			mt.AddMockResponses(mtest.CreateSuccessResponse())
			mt.AddMockResponses(mtest.CreateSuccessResponse())
			mt.AddMockResponses(mtest.CreateSuccessResponse())
            mt.AddMockResponses(mtest.CreateCursorResponse(1, "test.policy", mtest.FirstBatch,bson.D{
                {Key: "_id",Value: "12345678"},
                {Key: "principal",Value: "tester01"},
                {Key: "actions",Value: []string{"begonia:file:get","begonia:file:put"}},
                {Key: "resource",Value: "begonia:file:/tester/*"},
                {Key: "effect",Value: "ALLOW"},
                {Key: "conditions",Value: []interface{}{}},
            }))


		})
		repo := data.NewPolicyRepoImpl(tiga.NewMongoMocker(mt.DB, nil), snk)
		_, err := repo.Insert(context.TODO(), &api.Policy{
			Principal: "tester01",
			Actions: []string{
				"begonia:file:get",
				"begonia:file:put",
			},
			Resource:   "begonia:file:/tester/*",
			Effect:     api.Effect_ALLOW,
			Conditions: []*api.Condition{},
		})
		c.So(err, c.ShouldBeNil)

		policies, err := repo.Select(context.TODO(), "tester01", "begonia:file:get")
		c.So(err, c.ShouldBeNil)
		c.So(len(policies), c.ShouldEqual, 1)

	})

}
