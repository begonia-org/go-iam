package biz

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	api "github.com/begonia-org/go-iam/api/v1"
	"github.com/sirupsen/logrus"
	"golang.org/x/exp/slices"
)

type AccessControl interface{}

type ABAC struct {
	policy *policyUsecase
	log    *logrus.Logger
}

func NewABAC(policy *policyUsecase, logger *logrus.Logger) *ABAC {
	return &ABAC{
		policy: policy,
		log:    logger,
	}
}

func (a *ABAC) ApplyAuthorization(ctx context.Context, accessCtx *api.AccessContext) (bool, error) {
	// get policy
	policies, err := a.policy.GetPolicy(ctx, accessCtx.Principal, accessCtx.Action)
	if err != nil {
		return false, err
	}
	if len(policies) == 0 {
		return false, nil
	}
	if ok, err := a.checkPermission(ctx, policies, accessCtx); !ok || err != nil {
		return false, err
	}
	return true, nil
}
func (a *ABAC) toNumeric(v string) (float64, error) {
	if strings.Contains(v, ".") {

		return strconv.ParseFloat(v, 64)
	}
	intV, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return 0, err

	}
	return float64(intV), nil
}
func (a *ABAC) compareIp(values []string, v string) (bool, error) {
	for _, value := range values {
		if strings.Contains(value, "/") {
			_, subnet, err := net.ParseCIDR(value)
			if err != nil {
				return false, fmt.Errorf("parse %s cidr error of condition", value)
			}
			ip := net.ParseIP(v)
			if ip == nil {
				return false, fmt.Errorf("parse %s ip error", v)
			}

			if subnet.Contains(ip) {
				return true, nil
			} else {
				return false, nil
			}
		} else {
			ip := net.ParseIP(value)
			if ip == nil {
				return false, fmt.Errorf("parse %s ip error of condition", value)
			}
			ip1 := net.ParseIP(v)
			if ip1 == nil {
				return false, fmt.Errorf("parse %s ip error", v)
			}
			if ip.Equal(ip1) {
				return true, nil
			} else {
				return false, nil
			}

		}
	}
	return true, nil
}
func (a *ABAC) compareDatetime(except, actual string, compare func(except, actual time.Time) bool) (bool, error) {
	t, err := time.Parse(time.RFC3339, actual)
	if err != nil {
		a.log.Warnf("parse time error %s", err.Error())
		return false, fmt.Errorf("parse time error %s", err.Error())
	}
	t1, err := time.Parse(time.RFC3339, except)
	if err != nil {
		a.log.Warnf("parse except time error %s", err.Error())
		return false, fmt.Errorf("parse except time error %s", err.Error())
	}
	return compare(t1, t), nil
}
func (a *ABAC) toBool(v string) (bool, error) {
	return strconv.ParseBool(v)
}
func (a *ABAC) compareNumeric(values []string, v string, compare func(except, target float64) bool) (bool, error) {
	value := values[0]
	except, err := a.toNumeric(value)
	if err != nil {
		return false, fmt.Errorf("parse %s error %w", value, err)
	}
	actual, err := a.toNumeric(v)
	if err != nil {
		return false, fmt.Errorf("parse actual %s error %w", v, err)
	}
	return compare(except, actual), nil
}
func (a *ABAC) checkCondition(_ context.Context, condition *api.Condition, access *api.AccessContext) (bool, error) {
	// operator:=
	access.Fail = &api.FailReason{}
	for operator, kv := range condition.Kv {
		if api.ConditionOperator_value[operator] == int32(api.ConditionOperator_OPERATOR_UNSPECIFIED) {
			a.log.Errorf("operator %s not support", operator)
			return false, fmt.Errorf("operator %s not support", operator)
		}
		data := access.Context
		v := data[kv.Key]
		env := access.Env
		access.Fail.Key = kv.Key
		access.Fail.Actual = v
		access.Fail.Except = kv.Value
		access.Fail.Operator = operator
		switch api.ConditionOperator(api.ConditionOperator_value[operator]) {
		case api.ConditionOperator_OPERATOR_UNSPECIFIED:
			return false, fmt.Errorf("operator %s not support", operator)
		case api.ConditionOperator_StringEquals:
			if !slices.Contains(kv.Value, v) {
				access.Fail.Message = fmt.Sprintf("value %s condition %s not match", v, kv.Key)

				return false, nil
			}
		case api.ConditionOperator_StringNotEquals:
			if slices.Contains(kv.Value, v) {
				access.Fail.Message = fmt.Sprintf("value %s condition %s not match", v, kv.Key)
				return false, nil
			}
		case api.ConditionOperator_StringEqualsIgnoreCase:

			if !slices.ContainsFunc(kv.Value, func(s string) bool {
				access.Fail.Message = fmt.Sprintf("value %s condition %s not match", v, kv.Key)
				return strings.EqualFold(s, v)
			}) {
				return false, nil
			}
		case api.ConditionOperator_StringNotEqualsIgnoreCase:

			if slices.ContainsFunc(kv.Value, func(s string) bool {
				access.Fail.Message = fmt.Sprintf("value %s condition %s not match", v, kv.Key)
				return strings.EqualFold(s, v)
			}) {
				return false, nil
			}
		case api.ConditionOperator_StringLike:

			if !slices.ContainsFunc(kv.Value, func(s string) bool {
				access.Fail.Message = fmt.Sprintf("value %s condition %s not match", v, kv.Key)
				return strings.Contains(v, s)
			}) {
				return false, nil
			}
		case api.ConditionOperator_NumericEquals:

			if !slices.Contains(kv.Value, v) {
				access.Fail.Message = fmt.Sprintf("value %s condition %s not match", v, kv.Key)
				return false, nil
			}
		case api.ConditionOperator_NumericNotEquals:
			if slices.Contains(kv.Value, v) {
				access.Fail.Message = fmt.Sprintf("value %s condition %s not match", v, kv.Key)
				return false, nil
			}
		case api.ConditionOperator_NumericLessThan:
			if ok, err := a.compareNumeric(kv.Value, v, func(except, actual float64) bool {
				return actual < except
			}); !ok || err != nil {
				access.Fail.Message = fmt.Sprintf("value %s condition %s not match", v, kv.Key)
				return false, err
			}
		case api.ConditionOperator_NumericLessThanEquals:
			if ok, err := a.compareNumeric(kv.Value, v, func(except, actual float64) bool {
				return actual <= except
			}); !ok || err != nil {
				access.Fail.Message = fmt.Sprintf("value %s condition %s not match", v, kv.Key)
				return false, err
			}
		case api.ConditionOperator_NumericGreaterThan:
			if ok, err := a.compareNumeric(kv.Value, v, func(except, actual float64) bool {
				return actual > except
			}); !ok || err != nil {
				access.Fail.Message = fmt.Sprintf("value %s condition %s not match", v, kv.Key)
				return false, err
			}
		case api.ConditionOperator_NumericGreaterThanEquals:
			if ok, err := a.compareNumeric(kv.Value, v, func(except, actual float64) bool {
				return actual >= except
			}); !ok || err != nil {
				access.Fail.Message = fmt.Sprintf("value %s condition %s not match", v, kv.Key)
				return false, err
			}
		case api.ConditionOperator_BOOL:
			for _, value := range kv.Value {
				b, err := a.toBool(value)
				if err != nil {
					access.Fail.Message = fmt.Sprintf("value %s condition %s not match", v, kv.Key)
					return false, fmt.Errorf("parse %s bool error %w", value, err)
				}
				val, err := a.toBool(v)
				if err != nil {
					access.Fail.Message = fmt.Sprintf("value %s condition %s not match", v, kv.Key)
					return false, fmt.Errorf("parse actual %s bool error %w", v, err)
				}
				if b != val {
					access.Fail.Message = fmt.Sprintf("value %s condition %s not match", v, kv.Key)
					return false, nil
				}
			}
		case api.ConditionOperator_DateEquals:
			if ok, err := a.compareDatetime(kv.Value[0], v, func(except, actual time.Time) bool {
				return except.Equal(actual)
			}); !ok || err != nil {
				access.Fail.Message = fmt.Sprintf("value %s condition %s not match", v, kv.Key)
				return false, nil
			}
		case api.ConditionOperator_DateLessThan:
			if ok, err := a.compareDatetime(kv.Value[0], v, func(except, actual time.Time) bool {
				return actual.Before(except)
			}); !ok || err != nil {
				access.Fail.Message = fmt.Sprintf("value %s condition %s not match", v, kv.Key)
				return false, nil
			}
		case api.ConditionOperator_DateLessThanEquals:
			if ok, err := a.compareDatetime(kv.Value[0], v, func(except, actual time.Time) bool {
				return actual.Before(except) || actual.Equal(except)
			}); !ok || err != nil {
				access.Fail.Message = fmt.Sprintf("value %s condition %s not match", v, kv.Key)
				return false, nil
			}
		case api.ConditionOperator_DateGreaterThan:
			if ok, err := a.compareDatetime(kv.Value[0], v, func(except, actual time.Time) bool {
				return actual.After(except)
			}); !ok || err != nil {
				access.Fail.Message = fmt.Sprintf("value %s condition %s not match", v, kv.Key)
				return false, nil
			}
		case api.ConditionOperator_DateGreaterThanEquals:
			if ok, err := a.compareDatetime(kv.Value[0], v, func(except, actual time.Time) bool {
				return actual.After(except) || actual.Equal(except)
			}); !ok || err != nil {
				access.Fail.Message = fmt.Sprintf("value %s condition %s not match", v, kv.Key)
				return false, nil
			}
		case api.ConditionOperator_IpAddress:
			if ok, err := a.compareIp(kv.Value, env.Ip); !ok || err != nil {
				access.Fail.Message = fmt.Sprintf("value %s condition %s not match", v, kv.Key)
				return false, err
			}

		case api.ConditionOperator_NotIpAddress:
			if ok, err := a.compareIp(kv.Value, env.Ip); ok || err != nil {
				access.Fail.Message = fmt.Sprintf("value %s condition %s not match", v, kv.Key)
				return false, err
			}

		}
	}

	return true, nil
}
func (a *ABAC) checkPermission(ctx context.Context, policies []*api.Policy, accessCtx *api.AccessContext) (bool, error) {
	isMatch := false
	for _, policy := range policies {
		for _, r := range accessCtx.Resource {
			if !a.matchResource(policy.Resource, r) {
				continue
			} else {
				isMatch = true
				for _, condition := range policy.Conditions {
					if ok, err := a.checkCondition(ctx, condition, accessCtx); !ok || err != nil {
						return false, err
					}
				}
			}
		}
	}
	if !isMatch {

		return false, fmt.Errorf("no resource match")

	}
	return true, nil
}
func (a *ABAC) matchResource(resourceRegx, target string) bool {
	return a.policy.MatchResource(resourceRegx, target)
}
