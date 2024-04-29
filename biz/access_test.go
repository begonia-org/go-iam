package biz

import (
    "context"
    "testing"
    "time"

    "github.com/agiledragon/gomonkey/v2"
    api "github.com/begonia-org/go-access-control/api/v1"
    "github.com/gobwas/glob"
    c "github.com/smartystreets/goconvey/convey"
)

func TestCheck(t *testing.T) {
    c.Convey("TestCheck", t, func() {
        policies := []*api.Policy{
            {
                Principal: "tester01",
                Actions: []string{
                    "begonia:file:get",
                },
                Resource: "begonia:file:/test/*",
                Effect:   api.Effect_ALLOW,
                Conditions: []*api.Condition{
                    {
                        Kv: map[string]*api.ConditionKV{
                            api.ConditionOperator_name[int32(api.ConditionOperator_StringEquals)]: {
                                Key:   "begonia:file:owner",
                                Value: []string{"tester01", "tester02"},
                            },
                            api.ConditionOperator_name[int32(api.ConditionOperator_IpAddress)]: {
                                Key:   "begonia:remote:ip",
                                Value: []string{"192.168.3.1/24"},
                            },
                        },
                    },
                },
            },
        }
        patcher := gomonkey.ApplyFuncReturn((*policyUsecase).GetPolicy, policies, nil)
        defer patcher.Reset()
        // snk, _ := tiga.NewSnowflake(1)
        // repo := data.NewPolicyRepoImpl(nil, snk)
        abac := NewABAC(&policyUsecase{}, nil)
        patcher.ApplyFunc((*policyUsecase).MatchResource, func(useCase *policyUsecase, resourceRegx, target string) bool {
            g := glob.MustCompile(resourceRegx)
            return g.Match(target)
        })
        access := &api.AccessContext{
            Principal: "tester01",
            Action:    "begonia:file:get",
            Resource:  []string{"begonia:file:/test/1"},
            Context:   map[string]string{"begonia:file:owner": "tester01"},
            Env: &api.AccessEnv{
                Ip: "192.168.3.34",
            },
        }
        ok, err := abac.Check(context.TODO(), access)
        c.So(ok, c.ShouldBeTrue)
        c.So(err, c.ShouldBeNil)
        access.Resource = []string{"begonia:file:/test3/2"}
        access.Fail = nil
        _, err = abac.Check(context.TODO(), access)
        c.So(err, c.ShouldNotBeNil)
        c.So(err.Error(),c.ShouldContainSubstring,"no resource match")

    })
}
func TestCheckCondition(t *testing.T) {
    c.Convey("TestCheckCondition", t, func() {
        abac := NewABAC(nil, nil)
        cond := &api.Condition{
            Kv: map[string]*api.ConditionKV{
                api.ConditionOperator_name[int32(api.ConditionOperator_StringEquals)]: {
                    Key:   "begonia:file:owner",
                    Value: []string{"tester01", "tester02"},
                },
                api.ConditionOperator_name[int32(api.ConditionOperator_IpAddress)]: {
                    Key:   "begonia:remote:ip",
                    Value: []string{"192.168.3.1/24"},
                },
                api.ConditionOperator_name[int32(api.ConditionOperator_NumericGreaterThanEquals)]: {
                    Key:   "begonia:owner:id",
                    Value: []string{"100"},
                },
                api.ConditionOperator_name[int32(api.ConditionOperator_DateGreaterThan)]: {
                    Key:   "begonia:user:created_at",
                    Value: []string{time.Now().Add(time.Hour * -24).Format(time.RFC3339)},
                },
            },
        }
        accessCtx := &api.AccessContext{
            Principal: "tester01",
            Action:    "begonia:file:get",
            Context:   map[string]string{"begonia:file:owner": "tester01", "begonia:owner:id": "100", "begonia:user:created_at": time.Now().Format(time.RFC3339)},
            Env: &api.AccessEnv{
                Ip:      "192.168.3.41",
                Referer: "http://www.begonia.org",
            },
        }
        ok, err := abac.checkCondition(context.TODO(), cond, accessCtx)
        c.So(err, c.ShouldBeNil)
        c.So(ok, c.ShouldBeTrue)
        accessCtx.Principal = "tester03"
        accessCtx.Context = map[string]string{"begonia:file:owner": "tester03", "begonia:owner:id": "100", "begonia:user:created_at": time.Now().Format(time.RFC3339)}
        ok, err = abac.checkCondition(context.TODO(), cond, accessCtx)
        c.So(err, c.ShouldBeNil)
        c.So(ok, c.ShouldBeFalse)
        accessCtx.Context = map[string]string{"begonia:file:owner": "tester01", "begonia:owner:id": "100", "begonia:user:created_at": time.Now().Format(time.RFC3339)}
        accessCtx.Env.Ip = "192.168.4.23"
        ok, err = abac.checkCondition(context.TODO(), cond, accessCtx)
        c.So(err, c.ShouldBeNil)
        c.So(ok, c.ShouldBeFalse)
        accessCtx.Context = map[string]string{"begonia:file:owner": "tester01", "begonia:owner:id": "90", "begonia:user:created_at": time.Now().Format(time.RFC3339)}
        accessCtx.Env.Ip = "192.168.3.41"
        ok, err = abac.checkCondition(context.TODO(), cond, accessCtx)
        c.So(err, c.ShouldBeNil)
        c.So(ok, c.ShouldBeFalse)

    })
}
func TestMatchResource(t *testing.T){
    c.Convey("TestMatchResource",t,func(){
        g:=glob.MustCompile("begonia:file:*")
        ok:=g.Match("begonia:file:/test/1")
        c.So(ok,c.ShouldBeTrue)
    })
}