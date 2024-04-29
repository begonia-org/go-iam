package biz

import (
	"context"

	api "github.com/begonia-org/go-access-control/api/v1"
)
type PolicyRepo interface {
	Insert(ctx context.Context, policy *api.Policy) (string,error)
	Select(ctx context.Context, principal string, action string) ([]*api.Policy, error)
	MatchResource(resourceRegx, target string) bool
}

type policyUsecase struct {
	repo PolicyRepo
}

func NewpolicyUsecase(repo PolicyRepo) *policyUsecase {
	return &policyUsecase{
		repo: repo,
	}
}

func (uc *policyUsecase) CreatePolicy(ctx context.Context, policy *api.Policy) (string,error) {
	return uc.repo.Insert(ctx, policy)
}

func (uc *policyUsecase) UpdatePolicy(ctx context.Context, policy *api.Policy) error {
	return nil
}

func (uc *policyUsecase) DeletePolicy(ctx context.Context, policy *api.Policy) error {
	return nil
}

func (uc *policyUsecase) GetPolicy(ctx context.Context,principal string,action string) ([]*api.Policy,error) {
	return uc.repo.Select(ctx, principal, action)
}

func (uc *policyUsecase) ApplyPolicy(ctx context.Context, policy *api.Policy) error {
	return nil
}
func (uc *policyUsecase) MatchResource(resourceRegx, target string) bool {
	return uc.repo.MatchResource(resourceRegx, target)
}