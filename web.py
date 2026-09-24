# -*- coding: utf-8 -*-
"""
Điểm vào khởi chạy WebUI.

Cách dùng:
    python web.py                 # Mặc định http://127.0.0.1:5000, chỉ truy cập local, không tự mở trình duyệt
    python web.py --open-browser  # Tự mở trình duyệt sau khi khởi chạy
    python web.py --port 8000     # Đổi cổng
    python web.py --host 0.0.0.0  # Cho phép truy cập LAN (công cụ nhạy cảm, tự đánh giá)

Song song hoàn toàn với CLI (python main.py), không ảnh hưởng lẫn nhau.
"""
import argparse
import logging
import os
import tempfile
import webbrowser
from pathlib import Path
from threading import Timer

from webui.app import create_app
from webui.auth import is_generated_code


def _acquire_single_instance(port: int):
    """Giữ khoá file liên tiến trình, tránh nhiều instance WebUI trên cùng cổng."""
    lock_path = Path(tempfile.gettempdir()) / f"turb-gpt-free-register-web-{int(port)}.lock"
    handle = lock_path.open("a+", encoding="utf-8")
    handle.seek(0, os.SEEK_END)
    if handle.tell() == 0:
        handle.write("0")
        handle.flush()
    handle.seek(0)
    try:
        if os.name == "nt":
            import msvcrt
            msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except (OSError, IOError) as exc:
        handle.close()
        raise RuntimeError(f"WebUI cổng {port} đang chạy") from exc
    handle.seek(0)
    handle.truncate()
    handle.write(str(os.getpid()))
    handle.flush()
    return handle


def _release_single_instance(handle) -> None:
    if handle is None:
        return
    try:
        handle.seek(0)
        if os.name == "nt":
            import msvcrt
            msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
    except (OSError, IOError):
        pass
    handle.close()


def _setup_logging(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Bảng điều khiển WebUI đăng ký GPT")
    parser.add_argument("--host", default="127.0.0.1", help="Địa chỉ bind, mặc định chỉ local 127.0.0.1")
    parser.add_argument("--port", type=int, default=5000, help="Cổng, mặc định 5000")
    parser.add_argument("--open-browser", action="store_true", help="Tự mở trình duyệt sau khi khởi chạy")
    parser.add_argument("--auth-code", default=None, help="Mã uỷ quyền WebUI; cũng có thể cấu hình .env: WEBUI_AUTH_CODE=...")
    parser.add_argument("--verbose", action="store_true", help="Nhật ký chi tiết")
    args = parser.parse_args()

    _setup_logging(args.verbose)
    logger = logging.getLogger(__name__)

    if args.auth_code:
        os.environ["WEBUI_AUTH_CODE"] = args.auth_code

    try:
        instance_lock = _acquire_single_instance(args.port)
    except RuntimeError as exc:
        logger.error(str(exc))
        raise SystemExit(2) from exc

    app = create_app(auth_code=args.auth_code)
    url = f"http://{'127.0.0.1' if args.host in ('0.0.0.0', '::') else args.host}:{args.port}"
    logger.info(f"WebUI đã khởi chạy: {url}")
    if is_generated_code():
        from webui.auth import expected_auth_code
        logger.warning("Chưa cấu hình WEBUI_AUTH_CODE/AUTH_CODE, đã tạo mã uỷ quyền tạm cho lần này: %s", expected_auth_code())
    if args.host in ("0.0.0.0", "::"):
        logger.warning("Đã bind mọi giao diện mạng, thiết bị khác trong LAN có thể truy cập. Đây là công cụ nhạy cảm, hãy xác nhận mạng tin cậy.")

    # Mặc định không tự mở trình duyệt; truyền --open-browser khi cần
    if args.open_browser:
        Timer(1.0, lambda: webbrowser.open(url)).start()

    # debug=False: tránh reloader hai process làm trùng thread pool/timer
    try:
        app.run(host=args.host, port=args.port, debug=False, threaded=True)
    finally:
        _release_single_instance(instance_lock)


if __name__ == "__main__":
    main()
