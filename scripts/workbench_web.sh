#!/usr/bin/env bash
# CTF2 工作台 WebUI 启停脚本：bash scripts/workbench_web.sh [start|restart|stop]
cd "$(dirname "$0")/.." || exit 1
PY=/home/kali/miniconda3/envs/agentscope/bin/python
case "${1:-restart}" in
  start|restart)
    pkill -f "python workbench_ctf2_web.py" 2>/dev/null
    for w in $(seq 1 15); do
      ss -tlnp 2>/dev/null | grep -q ":8081 " || break
      sleep 1
    done
    nohup "$PY" workbench_ctf2_web.py --host 0.0.0.0 --port 8081 > /tmp/workbench_web.log 2>&1 &
    disown
    for i in $(seq 1 15); do
      sleep 1
      code=$(curl -s -m 2 -o /dev/null -w "%{http_code}" http://127.0.0.1:8081/api/state 2>/dev/null)
      if [ "$code" = "200" ]; then echo "ready (第${i}s)"; exit 0; fi
    done
    echo "start failed"; tail -5 /tmp/workbench_web.log; exit 1
    ;;
  stop)
    pkill -f "python workbench_ctf2_web.py" 2>/dev/null
    echo stopped
    ;;
esac
