---
title: JRDesk 접속 알림 모니터 (hbbs/hbbr → n8n → Hermes Telegram + Obsidian)
date: 2026-11-16
tags: [jrdesk, rustdesk, n8n, 보안, 운영]
status: 배포 대기(승인 필요)
---
# JRDesk 접속 알림 모니터

## 구조
```
rustdesk-hbbs/hbbr (docker logs)
   └─ jrdesk-log-shipper.py (VPS 호스트, systemd)  ── 이벤트 추출·중복제거
        └─ POST + X-JRDesk-Secret → n8n Webhook /webhook/jrdesk-events
             ├─ 즉시: Hermes Telegram 봇 알림
             └─ 매일 00:05 KST: 전날 로그 → Google Drive(Obsidian_Patrick) 노트 1개
```

## 감지 이벤트
| 유형 | 의미 | 출처 로그 |
|---|---|---|
| 🔴 invalid_key | 내 서버 키 없는 클라이언트의 사용 시도(스캔·외부인) | hbbs/hbbr WARN |
| 🟡 connect_attempt | IP X → 현장 PC ID Y 연결 요청 | hbbs DEBUG (RUST_LOG 필요) |
| 🟢 relay_start / ⚪ relay_end | 중계 세션 시작·종료(지속시간) | hbbr INFO |

**한계:** 연결은 종단간 암호화라 서버는 비밀번호·OTP 성공/실패를 모름. 비밀번호 통과 시점은 PC가 직접 텔레그램으로 "2FA code + source IP"를 보냄(JRDesk 2FA 봇). P2P로 붙은 세션은 시작 요청까지만 보임.

## 배포 절차 (승인 후 실행)
1. **hbbs 설정 변경** (Docker 매니저 → rustdesk-server yaml)
   - hbbs에 `environment: [RUST_LOG=info,hbbs::rendezvous_server=debug]`
   - hbbs·hbbr에 로그 용량 제한 `logging: {driver: json-file, options: {max-size: "10m", max-file: "3"}}`
   - 재배포 (키 유지, 수 초 끊김)
2. **수집기 설치** (hPanel 웹 콘솔, root)
   ```bash
   mkdir -p /opt/jrdesk-monitor
   curl -fsSL https://raw.githubusercontent.com/halasu/jrdesk/master/tools/monitor/jrdesk-log-shipper.py -o /opt/jrdesk-monitor/jrdesk-log-shipper.py
   curl -fsSL https://raw.githubusercontent.com/halasu/jrdesk/master/tools/monitor/jrdesk-monitor.service -o /etc/systemd/system/jrdesk-monitor.service
   python3 /opt/jrdesk-monitor/jrdesk-log-shipper.py --selftest
   # /etc/jrdesk-monitor.env 작성 (N8N_WEBHOOK_URL, N8N_SECRET=$(openssl rand -hex 24)), chmod 600
   DRY_RUN=1 timeout 20 python3 /opt/jrdesk-monitor/jrdesk-log-shipper.py   # 이벤트 출력 확인
   systemctl daemon-reload && systemctl enable --now jrdesk-monitor
   ```
3. **n8n**: `n8n-jrdesk-events.json` 가져오기 → SECRET·Hermes 봇 자격증명·chat ID·Drive 폴더 ID 설정 → 활성화
4. **검증**: 공식 RustDesk(키 없음)로 접속 → 🔴 알림 / JRDesk로 접속 → 🟡·🟢·⚪ 알림 / 다음날 00:05 노트 생성

## 복구
`systemctl disable --now jrdesk-monitor` → `/opt/jrdesk-monitor`, `/etc/jrdesk-monitor.env`, 서비스 파일 삭제 → yaml에서 environment/logging 제거 후 재배포 → n8n 워크플로 비활성화.
