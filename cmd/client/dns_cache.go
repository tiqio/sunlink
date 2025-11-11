package main

import (
	"github.com/miekg/dns"
	"github.com/tiqio/sunlink/log"
)

func (ci *ClientInstance) DNSCache(name, qtype string, isDirect bool) *dns.Msg {
	var v []byte
	var err error
	if isDirect {
		v, err = ci.directDNSCache.Get([]byte(name + qtype))
	} else {
		v, err = ci.dnsCache.Get([]byte(name + qtype))
	}
	if err != nil || len(v) == 0 {
		return nil
	}

	msg := &dns.Msg{}
	if err := msg.Unpack(v); err != nil {
		return nil
	}

	return msg
}

func (ci *ClientInstance) RenewDNSCache(name, qtype string, isDirect bool) bool {
	if isDirect {
		if err := ci.directDNSCache.Touch([]byte(name+qtype), DefaultDNSCacheSize); err != nil {
			return false
		}
	}
	if err := ci.dnsCache.Touch([]byte(name+qtype), DefaultDNSCacheSize); err != nil {
		return false
	}
	return true
}

func (ci *ClientInstance) SetDNSCache(msg *dns.Msg, noExpire, isDirect bool) error {
	if msg == nil {
		return nil
	}
	if len(msg.Question) == 0 {
		return nil
	}

	q := msg.Question[0]
	if q.Qtype == dns.TypeA || q.Qtype == dns.TypeAAAA {
		v, err := msg.Pack()
		if err != nil {
			return err
		}
		expireSec := DefaultDNSCacheSec
		if noExpire {
			expireSec = 0
		}
		key := []byte(q.Name + dns.TypeToString[q.Qtype])
		if isDirect {
			return ci.directDNSCache.Set(key, v, expireSec)
		}
		return ci.dnsCache.Set(key, v, expireSec)
	}

	return nil
}

func (ci *ClientInstance) SetDNSCacheIfNeeded(udpResp []byte, isDirect bool) *dns.Msg {
	logPrefix := "[DNS_PROXY]"
	if isDirect {
		logPrefix = "[DNS_DIRECT]"
	}
	msg := &dns.Msg{}
	if err := msg.Unpack(udpResp); err == nil && isDNSRequest(msg) {
		log.Info(logPrefix+" got result for", "domain", msg.Question[0].Name, "answer", msg.Answer, "qtype", dns.TypeToString[msg.Question[0].Qtype])
		if err := ci.SetDNSCache(msg, false, isDirect); err != nil {
			log.Warn(logPrefix+" set dns cache", logPrefix, "err", err)
		} else {
			log.Debug(logPrefix+" set cache for", "domain", msg.Question[0].Name, "qtype", dns.TypeToString[msg.Question[0].Qtype])
		}
		return msg
	}
	return nil
}
