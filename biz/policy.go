package biz

import (
	"context"

	api "github.com/begonia-org/go-access-control/api/v1"
)
type PolicyRepo interface {
	Insert(ctx context.Context, policy *api.Policy) error
}

type PolicyUsecase struct {
	repo PolicyRepo
}

func NewPolicyUsecase(repo PolicyRepo) *PolicyUsecase {
	return &PolicyUsecase{
		repo: repo,
	}
}

func (uc *PolicyUsecase) CreatePolicy(ctx context.Context, policy *api.Policy) error {
	return uc.repo.Insert(ctx, policy)
}

func (uc *PolicyUsecase) UpdatePolicy(ctx context.Context, policy *api.Policy) error {
	return nil
}

func (uc *PolicyUsecase) DeletePolicy(ctx context.Context, policy *api.Policy) error {
	return nil
}

func (uc *PolicyUsecase) GetPolicy(ctx context.Context, policy *api.Policy) error {
	return nil
}

func (uc *PolicyUsecase) ApplyPolicy(ctx context.Context, policy *api.Policy) error {
	return nil
}