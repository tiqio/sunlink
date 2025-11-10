package common

type HostRule int

type MatchFunc func(host string) HostRule

const (
	HostRuleProxy HostRule = iota
	HostRuleDirect
	HostRuleBlock
)
