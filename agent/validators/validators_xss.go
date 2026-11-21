package validators

import (
	"context"
	"net/http"
	"strings"
)

// RunXSS 验证 XSS 类（v1=反射+上下文机械断言，执行确认留给浏览器步骤）：
//  1. 反射探针——注入带唯一标记的 SVG/onload payload，断言响应含「未转义」的
//     payload 关键片段（<svg 原样出现、&lt;svg 不算）且与标记同现（排除静态误配）；
//  2. CSP 核查——严格 CSP（script-src/default-src 且无 unsafe-inline）时
//     verdict 降为 warn：反射确认但执行大概率被拦。
//
// verdict：原始反射+宽松 CSP → pass；原始反射+严格 CSP → warn；
// 仅转义反射（&lt;svg）→ fail（带「已转义」结论）；无反射 → fail。
func RunXSS(ctx context.Context, client *http.Client, targetURL, param, token string) *Result {
	marker := "px" + token // 探针标记（payload 内嵌 token，排除响应里恰好同串的误配）
	payloads := []string{
		"\"><svg/onload=alert(1)>" + marker + "<",
		"'-alert(1)-'" + marker,
		"<img src=x onerror=alert(1)>" + marker,
	}
	var probes []ProbeResult
	rawReflection := false
	escapedReflection := false
	strict := false

	for _, v := range payloads {
		for _, u := range probeURLs(targetURL, param, []string{v}) {
			body, hdr, _, err := probeGet(ctx, client, u)
			name := "reflection_raw"
			if err != nil {
				probes = append(probes, ProbeResult{Name: name, Injected: v, Detail: "请求失败: " + err.Error()})
				continue
			}
			if strings.Contains(body, marker) {
				if strings.Contains(body, "<svg/onload=alert(1)>") || strings.Contains(body, "<img src=x onerror=alert(1)>") {
					rawReflection = true
					csp := hdr.Get("Content-Security-Policy")
					strict = strictCSP(csp)
					probes = append(probes, ProbeResult{
						Name: name, Injected: v, Hit: !strict,
						Detail: verdictText(!strict,
							"payload 未转义原样反射（含 "+marker+" 标记）；CSP "+cspNote(strict, csp),
							"payload 未转义原样反射（含 "+marker+" 标记），但 CSP 严格（"+csp+"）——内联执行大概率被拦，verdict 降为 warn",
						),
					})
				} else {
					escapedReflection = true
					probes = append(probes, ProbeResult{
						Name: name, Injected: v, Hit: false,
						Detail: "标记有反射但 payload 已被 HTML 转义（&lt;svg 等）——不可执行",
					})
				}
			} else {
				probes = append(probes, ProbeResult{Name: name, Injected: v, Detail: "标记无反射"})
			}
		}
	}

	switch {
	case rawReflection && !strict:
		return joinProbes("xss", token, probes, "反射+上下文机验通过；执行级确认建议用浏览器 MCP 运行该 payload（v1 validator 不含 headless 执行断言）。")
	case rawReflection && strict:
		r := joinProbes("xss", token, probes, "")
		r.Verdict = VerdictWarn
		r.Marker = "" // warn 不发 pass 标记
		r.Note = "反射确认但 CSP 严格：执行存疑，用浏览器 MCP 实测后人工定级。"
		return r
	case escapedReflection:
		r := joinProbes("xss", token, probes, "")
		r.Note = "参数有回显但已转义——本组探针无法确认 XSS。"
		return r
	}
	return joinProbes("xss", token, probes, "")
}

func cspNote(strict bool, csp string) string {
	if strict {
		return "严格"
	}
	if csp == "" {
		return "缺失（无 CSP 限制）"
	}
	return "宽松"
}
