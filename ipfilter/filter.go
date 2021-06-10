package ipfilter

import (
	"net"
	"net/http"
	"strings"

	"github.com/tomasen/realip"
	"github.com/yl2chen/cidranger"
)

var (
	allOnesIPv4Mask = net.CIDRMask(net.IPv4len*8, net.IPv4len*8)
	allOnesIPv6Mask = net.CIDRMask(net.IPv6len*8, net.IPv6len*8)
)

type IPFilter struct {
	allowRanger cidranger.Ranger
	blockRanger cidranger.Ranger
	conf        *FilterConf
}

type FilterConf struct {
	Allow        []string
	Block        []string
	DefaultBlock bool
}

// Filter ...
func Filter() func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			if defaultIpFilter != nil {
				if !defaultIpFilter.allow(realip.FromRequest(req)) {
					w.WriteHeader(http.StatusForbidden)
					return
				}
			}
			next.ServeHTTP(w, req)
		})
	}
}

var defaultIpFilter *IPFilter

func InitDefaultFilter(conf *FilterConf) {
	rangerFromIPCIDRs := func(IPList []string) cidranger.Ranger {
		ranger := cidranger.NewPCTrieRanger()
		for _, ipcidr := range IPList {
			ip := net.ParseIP(ipcidr)
			if ip != nil {
				mask := allOnesIPv4Mask
				if strings.Count(ipcidr, ":") >= 2 {
					mask = allOnesIPv6Mask
				}
				ipNet := net.IPNet{IP: ip, Mask: mask}
				ranger.Insert(cidranger.NewBasicRangerEntry(ipNet))
				continue
			}
			_, ipNet, err := net.ParseCIDR(ipcidr)
			if err != nil {
				continue
			}
			ranger.Insert(cidranger.NewBasicRangerEntry(*ipNet))
		}
		return ranger
	}
	defaultIpFilter = &IPFilter{
		allowRanger: rangerFromIPCIDRs(conf.Allow),
		blockRanger: rangerFromIPCIDRs(conf.Block),
		conf:        conf,
	}
}

func (f *IPFilter) allow(ipstr string) bool {
	defaultResult := !f.conf.DefaultBlock
	ip := net.ParseIP(ipstr)
	if ip == nil {
		return defaultResult
	}
	allowed, err := f.allowRanger.Contains(ip)
	if err != nil {
		return defaultResult
	}
	blocked, err := f.blockRanger.Contains(ip)
	if err != nil {
		return defaultResult
	}
	switch {
	case allowed && blocked:
		return defaultResult
	case allowed:
		return true
	case blocked:
		return false
	default:
		return defaultResult
	}
}
