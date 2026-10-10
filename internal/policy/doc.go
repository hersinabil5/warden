// Package policy defines the access policy model and its evaluator.
//
// This package must stay free of I/O: evaluation is a pure function of the policy
// and the request context, so it can be exhaustively unit-tested and fuzzed.
// Default deny: no matching allow rule, or any evaluation error, is a deny.
package policy
