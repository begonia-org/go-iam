package service

import (
	"context"

	"github.com/begonia-org/go-iam/biz"
	api "github.com/begonia-org/go-sdk/api/iam/v1"
	"github.com/begonia-org/go-sdk/logger"
)

type ABACService struct {
	api.UnimplementedABACServiceServer
	abac   *biz.ABAC
	policy *biz.PolicyUsecase
	log    logger.Logger
}

func NewABACService(abac *biz.ABAC, policy *biz.PolicyUsecase, log logger.Logger) *ABACService {
	return &ABACService{
		abac:   abac,
		policy: policy,
		log:    log,
	}
}

func (s *ABACService) Auth(ctx context.Context, req *api.AccessContext) (*api.AccessResponse, error) {
	ok, err := s.abac.ApplyAuthorization(ctx, req)
	if err != nil {
		return &api.AccessResponse{
			Pass:    false,
			Fail:    req.Fail,
			Message: err.Error(),
		}, err
	}
	return &api.AccessResponse{Pass: ok, Fail: req.Fail}, nil
}

func (s *ABACService) PolicyPut(ctx context.Context, req *api.PutPlicyRequest) (*api.PutPolicyResponse, error) {
	policyReq := &api.Policy{
		Principal:  req.Principal,
		Actions:    req.Actions,
		Resource:   req.Resource,
		Effect:     req.Effect,
		Conditions: req.Conditions,
	}
	id, err := s.policy.CreatePolicy(ctx, policyReq)
	if err != nil {
		return nil, err
	}
	return &api.PutPolicyResponse{UniqueKey: id}, nil
}

func (s *ABACService) PolicyGet(ctx context.Context, req *api.PolicyRequest) (*api.Policy, error) {
	return s.policy.GetPolicyByUniqueKey(ctx, req.UniqueKey)
}
func (s *ABACService) PolicyPatch(ctx context.Context, req *api.PutPlicyRequest) (*api.PatchPolicyResponse, error) {
	policyReq := &api.Policy{
		Principal:  req.Principal,
		Actions:    req.Actions,
		Resource:   req.Resource,
		Effect:     req.Effect,
		Conditions: req.Conditions,
	}
	err := s.policy.UpdatePolicy(ctx, policyReq, req.Mask.Paths)
	if err != nil {
		return nil, err

	}
	return &api.PatchPolicyResponse{}, nil
	// id,err := s.policy.CreatePolicy(ctx, policyReq)
	// if err != nil {
	// 	return nil,err
	// }
	// return &api.PutPolicyResponse{UniqueKey: id},nil
}
