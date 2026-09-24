#!/usr/bin/env bash
set -euo pipefail

# Script quản lý WebUI Turb GPT Free Register
#
# Cách dùng:
#   ./webui.sh start      Khởi chạy WebUI
#   ./webui.sh stop       Đóng WebUI
#   ./webui.sh restart    Khởi động lại WebUI
#   ./webui.sh status     Xem trạng thái
#   ./webui.sh logs       Xem nhật ký realtime
#
# Biến môi trường tuỳ chọn:
#   HOST=127.0.0.1
#   PORT=5000
#   OPEN_BROWSER=1
#   VERBOSE=1
#   AUTH_CODE=xxx
#   EXTRA_ARGS="..."

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

RUN_DIR="$ROOT_DIR/run"
LOG_DIR="$ROOT_DIR/logs"
PID_FILE="$RUN_DIR/webui.pid"
LOG_FILE="$LOG_DIR/webui.log"

HOST="${HOST:-127.0.0.1}"
PORT="${PORT:-5000}"
OPEN_BROWSER="${OPEN_BROWSER:-0}"
VERBOSE="${VERBOSE:-0}"
AUTH_CODE="${AUTH_CODE:-}"
EXTRA_ARGS="${EXTRA_ARGS:-}"

mkdir -p "$RUN_DIR" "$LOG_DIR"

usage() {
  cat <<EOF
Cách dùng: $0 <command>

commands:
  start      Khởi chạy WebUI
  stop       Đóng WebUI
  restart    Khởi động lại WebUI
  status     Xem trạng thái chạy
  logs       Xem nhật ký realtime

Biến môi trường:
  HOST=127.0.0.1 PORT=5000 OPEN_BROWSER=1 VERBOSE=1 AUTH_CODE=xxx EXTRA_ARGS="..."

Ví dụ:
  ./webui.sh start
  PORT=8000 OPEN_BROWSER=1 ./webui.sh start
  HOST=0.0.0.0 PORT=5000 ./webui.sh restart
EOF
}

is_running() {
  local pid="${1:-}"
  [[ -n "$pid" ]] && kill -0 "$pid" >/dev/null 2>&1
}

read_pid() {
  [[ -f "$PID_FILE" ]] && cat "$PID_FILE" 2>/dev/null || true
}

find_pids_by_port() {
  pgrep -f "python.*web\.py.*--port[ =]${PORT}" 2>/dev/null || true
}

get_python() {
  local venv_python="$ROOT_DIR/.venv/bin/python"
  if [[ -x "$venv_python" ]] && "$venv_python" -c 'import sys; print(sys.executable)' >/dev/null 2>&1; then
    echo "$venv_python"
  elif [[ -e "$venv_python" ]]; then
    echo "Phát hiện .venv tồn tại, nhưng Python trong môi trường ảo đã hỏng." >&2
    echo "Hãy tạo lại môi trường ảo và cài dependency:" >&2
    echo "  rm -rf .venv && python3 -m venv .venv" >&2
    echo "  .venv/bin/python -m pip install -r requirements.txt" >&2
    return 1
  elif command -v python3 >/dev/null 2>&1; then
    local system_python
    system_python="$(command -v python3)"
    if "$system_python" -c 'import flask' >/dev/null 2>&1; then
      echo "$system_python"
    else
      echo "Không tìm thấy môi trường Python dùng được: Python hệ thống thiếu Flask, hãy tạo .venv và cài requirements.txt" >&2
      return 1
    fi
  else
    echo "Không tìm thấy Python: hãy tạo .venv hoặc cài python3" >&2
    return 1
  fi
}

collect_running_pids() {
  local pids=()
  local pid
  pid="$(read_pid)"
  if is_running "$pid"; then
    pids+=("$pid")
  fi

  while IFS= read -r pid; do
    [[ -n "$pid" ]] && pids+=("$pid")
  done < <(find_pids_by_port)

  local unique=()
  local seen x
  for pid in "${pids[@]:-}"; do
    [[ -z "$pid" || "$pid" == "$$" ]] && continue
    seen=0
    for x in "${unique[@]:-}"; do
      [[ "$x" == "$pid" ]] && seen=1 && break
    done
    [[ "$seen" == "0" ]] && unique+=("$pid")
  done

  printf '%s\n' "${unique[@]:-}"
}

cmd_start() {
  local old_pid py pid
  old_pid="$(read_pid)"
  if is_running "$old_pid"; then
    echo "WebUI đang chạy: PID=${old_pid}, địa chỉ: http://${HOST}:${PORT}"
    return 0
  fi
  rm -f "$PID_FILE"

  py="$(get_python)"

  local args=("web.py" "--host" "$HOST" "--port" "$PORT")
  if [[ "$OPEN_BROWSER" == "1" || "$OPEN_BROWSER" == "true" ]]; then
    args+=("--open-browser")
  fi
  if [[ "$VERBOSE" == "1" || "$VERBOSE" == "true" ]]; then
    args+=("--verbose")
  fi
  if [[ -n "$AUTH_CODE" ]]; then
    args+=("--auth-code" "$AUTH_CODE")
  fi
  if [[ -n "$EXTRA_ARGS" ]]; then
    # shellcheck disable=SC2206
    local extra_parts=($EXTRA_ARGS)
    args+=("${extra_parts[@]}")
  fi

  echo "Khởi chạy WebUI: http://${HOST}:${PORT}"
  echo "File nhật ký: $LOG_FILE"
  nohup "$py" "${args[@]}" >> "$LOG_FILE" 2>&1 &
  pid=$!
  echo "$pid" > "$PID_FILE"

  sleep 1
  if is_running "$pid"; then
    echo "Khởi chạy thành công: PID=$pid"
  else
    echo "Khởi chạy thất bại, xem nhật ký: $LOG_FILE" >&2
    rm -f "$PID_FILE"
    return 1
  fi
}

cmd_stop() {
  local pids=()
  local pid
  while IFS= read -r pid; do
    [[ -n "$pid" ]] && pids+=("$pid")
  done < <(collect_running_pids)

  if [[ "${#pids[@]}" -eq 0 ]]; then
    echo "WebUI chưa chạy"
    rm -f "$PID_FILE"
    return 0
  fi

  echo "Đang đóng WebUI: PID=${pids[*]}"
  for pid in "${pids[@]}"; do
    kill "$pid" >/dev/null 2>&1 || true
  done

  local alive
  for _ in {1..15}; do
    alive=0
    for pid in "${pids[@]}"; do
      if is_running "$pid"; then
        alive=1
        break
      fi
    done
    [[ "$alive" == "0" ]] && break
    sleep 1
  done

  for pid in "${pids[@]}"; do
    if is_running "$pid"; then
      echo "Tiến trình chưa thoát, buộc kết thúc: PID=$pid"
      kill -9 "$pid" >/dev/null 2>&1 || true
    fi
  done

  rm -f "$PID_FILE"
  echo "Đã đóng WebUI"
}

cmd_restart() {
  cmd_stop
  sleep 1
  cmd_start
}

cmd_status() {
  local pids=()
  local pid
  while IFS= read -r pid; do
    [[ -n "$pid" ]] && pids+=("$pid")
  done < <(collect_running_pids)

  if [[ "${#pids[@]}" -eq 0 ]]; then
    echo "WebUI chưa chạy"
    return 1
  fi

  echo "WebUI đang chạy: PID=${pids[*]}"
  echo "Địa chỉ: http://${HOST}:${PORT}"
  echo "Nhật ký: $LOG_FILE"
}

cmd_logs() {
  touch "$LOG_FILE"
  tail -n 120 -f "$LOG_FILE"
}

cmd="${1:-}"
case "$cmd" in
  start) cmd_start ;;
  stop) cmd_stop ;;
  restart) cmd_restart ;;
  status) cmd_status ;;
  logs|log) cmd_logs ;;
  -h|--help|help|"") usage ;;
  *)
    echo "Lệnh không rõ: $cmd" >&2
    usage >&2
    exit 2
    ;;
esac
