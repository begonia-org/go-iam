package biz

import (
	"context"

	api "github.com/begonia-org/go-sdk/api/iam/v1"
)

type PolicyRepo interface {
	Insert(ctx context.Context, policy *api.Policy) (string, error)
	Select(ctx context.Context, principal string, action string) ([]*api.Policy, error)
	MatchResource(resourceRegx, target string) bool
	Get(ctx context.Context, uniqueKey string) (*api.Policy, error)
	Update(ctx context.Context, policy *api.Policy, mask []string) error
}

type PolicyUsecase struct {
	repo PolicyRepo
}

func NewpolicyUsecase(repo PolicyRepo) *PolicyUsecase {
	return &PolicyUsecase{
		repo: repo,
	}
}

func (uc *PolicyUsecase) CreatePolicy(ctx context.Context, policy *api.Policy) (string, error) {
	return uc.repo.Insert(ctx, policy)
}

func (uc *PolicyUsecase) UpdatePolicy(ctx context.Context, policy *api.Policy, mask []string) error {
	return uc.repo.Update(ctx, policy, mask)
}

func (uc *PolicyUsecase) DeletePolicy(ctx context.Context, policy *api.Policy) error {
	return nil
}

func (uc *PolicyUsecase) GetPolicy(ctx context.Context, principal string, action string) ([]*api.Policy, error) {
	return uc.repo.Select(ctx, principal, action)
}

func (uc *PolicyUsecase) ApplyPolicy(ctx context.Context, policy *api.Policy) error {
	return nil
}
func (uc *PolicyUsecase) MatchResource(resourceRegx, target string) bool {
	return uc.repo.MatchResource(resourceRegx, target)
}

func (uc *PolicyUsecase) GetPolicyByUniqueKey(ctx context.Context, uniqueKey string) (*api.Policy, error) {
	return uc.repo.Get(ctx, uniqueKey)
}
