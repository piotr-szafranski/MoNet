#!/usr/bin/env bash
# Autopilot nocny: w pętli uruchamia Claude Code w trybie nieinteraktywnym (claude -p), zawsze dla JEDNEGO
# zadania z TASKS.md. Stan jest w gicie i w TASKS.md, więc przerwanie sesji niczego nie psuje.
# Uruchomienie (w screen):  screen -S asi-autopilot  →  ./scripts/autopilot.sh  →  Ctrl+A D
# Zatrzymanie: touch STOP_AUTOPILOT  (albo Ctrl+C w screenie)
set -u
cd "$(dirname "$0")/.."
LOG=logs/autopilot.log
mkdir -p logs
END_HOUR=${END_HOUR:-7}          # o tej godzinie autopilot kończy pracę
MAX_RUNS=${MAX_RUNS:-40}
runs=0

allowed=(
  "Read" "Edit" "Write" "Glob" "Grep"
  "Bash(go:*)" "Bash(source ./env.sh*)" "Bash(gofmt:*)"
  "Bash(npm:*)" "Bash(npx vite:*)" "Bash(node:*)"
  "Bash(git status*)" "Bash(git diff*)" "Bash(git log*)" "Bash(git add:*)" "Bash(git commit:*)" "Bash(git show*)"
  "Bash(docker-compose -p asi*)" "Bash(docker logs:*)" "Bash(docker ps*)" "Bash(docker exec asi-lab-sim wget*)"
  "Bash(curl -s*http://127.0.0.1:8095*)" "Bash(python3 -I scripts/*)" "Bash(python3 -I -m json.tool*)"
  "Bash(ls:*)" "Bash(cat:*)" "Bash(head:*)" "Bash(tail:*)" "Bash(grep:*)" "Bash(wc:*)" "Bash(date*)" "Bash(mkdir:*)"
  "Bash(sed -n*)" "Bash(find .*)" "Bash(git checkout -- *)"
)

log() { echo "[$(date '+%F %T')] $*" | tee -a "$LOG"; }

while true; do
  [ -f STOP_AUTOPILOT ] && { log "STOP_AUTOPILOT: koniec"; break; }
  h=$(date +%H); h=$((10#$h))
  if [ "$h" -ge "$END_HOUR" ] && [ "$h" -lt 12 ]; then log "godzina $h: koniec okna autopilota"; break; fi
  if ! grep -q '^- \[ \]' TASKS.md; then log "wszystkie zadania zrobione"; break; fi
  [ "$runs" -ge "$MAX_RUNS" ] && { log "limit uruchomień $MAX_RUNS"; break; }
  runs=$((runs + 1))
  task=$(grep -m1 '^- \[ \]' TASKS.md)
  log "uruchomienie $runs: $task"
  out=$(timeout 75m claude -p "$(cat AUTOPILOT.md)" --permission-mode acceptEdits --allowedTools "${allowed[@]}" 2>&1)
  code=$?
  echo "$out" | tail -40 >> "$LOG"
  if echo "$out" | grep -qiE 'usage limit|rate limit|limit reached|resets at|429'; then
    log "limit użycia: czekam 20 min"
    sleep 1200
  elif [ $code -ne 0 ]; then
    log "kod wyjścia $code: krótka pauza"
    sleep 60
  fi
  # zabezpieczenie przed zapętleniem na jednym zadaniu
  if [ "$(grep -m1 '^- \[ \]' TASKS.md)" = "$task" ]; then
    n=$(grep -c "PRÓBA: ${task:6:40}" "$LOG" 2>/dev/null || true)
    echo "PRÓBA: ${task:6:40}" >> "$LOG"
    if [ "${n:-0}" -ge 2 ]; then
      log "zadanie nie posunęło się po 3 próbach → BLOCKED"
      python3 - "$task" <<'EOF'
import sys
t = sys.argv[1]
s = open("TASKS.md", encoding="utf-8").read()
s = s.replace(t, t.replace("- [ ]", "- [!] BLOCKED (autopilot):", 1), 1)
open("TASKS.md", "w", encoding="utf-8").write(s)
EOF
    fi
  fi
done
log "autopilot zakończony po $runs uruchomieniach"
