# Fork research (VI)

- **origin** = fork của bạn: https://github.com/6c696e68/turb-gpt-free-register
- **upstream** = nguồn: https://github.com/myfanhua/turb-gpt-free-register
- Branch làm việc: `feat/vi-research` (việt hoá)

## Lấy code mới từ upstream

```bash
cd /Volumes/SSD/Developments/TOOL/turb-gpt-free-register
git fetch upstream
git checkout main
git merge upstream/main   # hoặc: git rebase upstream/main
git push origin main

# đem thay đổi mới vào branch VI
git checkout feat/vi-research
git rebase main           # hoặc merge main
# giải conflict (thường ở file đã dịch), rồi:
git push origin feat/vi-research
```

## Chạy local

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
cp -n .env.example .env
# WEBUI_AUTH_CODE=research-local
./webui.sh start   # http://127.0.0.1:5000
```
