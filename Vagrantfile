# Vagrantfile — 3-Tier + DNS + 백업 자동 전송
#   103 lb-external
#   104 webwas1 (Web + WAS)
#   105 webwas2 (Web + WAS)
#   106 lb-internal
#   107 dbdns        (DB + Redis + CoreDNS + Key 생성 + 백업 + 108으로 push)
#   108 dbdns-backup (DB + Redis + CoreDNS + Key 수신)
Vagrant.configure("2") do |config|
  config.vm.box = "ubuntu/jammy64"
  config.vm.box_version = "20241002.0.0"

  # ---------------------------------------------------------------
  # 공통: Docker 설치
  # ---------------------------------------------------------------
  def docker_install
    <<-'SHELL'
set -euxo pipefail
apt-get update
apt-get install -y ca-certificates curl gnupg lsb-release
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu jammy stable" > /etc/apt/sources.list.d/docker.list
apt-get update
apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin
usermod -aG docker vagrant || true
systemctl enable --now docker
SHELL
  end

  # ---------------------------------------------------------------
  # External LB (103): nginx → 104/105 로드밸런싱
  # ---------------------------------------------------------------
  def provision_lb_external
    <<-'SHELL'
set -euxo pipefail
mkdir -p /opt/lb-external/conf.d

# 외부 LB Nginx 가상호스트 생성(80 → 104/105:80)
cat >/opt/lb-external/conf.d/default.conf <<'NGINX'
upstream web_pool {
    server 192.168.56.104:80 max_fails=3 fail_timeout=5s;
    server 192.168.56.105:80 max_fails=3 fail_timeout=5s;
}
server {
    listen 80;
    server_name lb-external.3tier.test _;
    keepalive_timeout 0;
    add_header X-Proxy external always;
    add_header X-Upstream $upstream_addr always;

    location /healthz { return 200 'ok'; add_header Content-Type text/plain; }

    location / {
        proxy_http_version 1.0;
        proxy_set_header Connection "";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_read_timeout 30s;
        proxy_pass http://web_pool;
    }
}
NGINX

docker rm -f lb-external || true
docker run -d --name lb-external \
  -p 80:80 \
  -v /opt/lb-external/conf.d:/etc/nginx/conf.d:ro \
  --dns 192.168.56.107 --dns 192.168.56.108 --dns 8.8.8.8 \
  --restart unless-stopped nginx:1.25
SHELL
  end

  # ---------------------------------------------------------------
  # Internal LB (106): nginx → 각 호스트의 WAS(8081)
  # ---------------------------------------------------------------
  def provision_lb_internal
    <<-'SHELL'
set -euxo pipefail
mkdir -p /opt/lb-internal/conf.d

# 내부 LB Nginx 가상호스트 생성(8080 → 104/105:8081)
cat >/opt/lb-internal/conf.d/default.conf <<'NGINX'
upstream was_pool {
    server 192.168.56.104:8081 max_fails=3 fail_timeout=5s;
    server 192.168.56.105:8081 max_fails=3 fail_timeout=5s;
}
server {
    listen 8080;
    server_name lb-internal.3tier.test _;
    keepalive_timeout 0;
    add_header X-Proxy internal always;
    add_header X-Upstream $upstream_addr always;

    location /healthz { return 200 'ok'; add_header Content-Type text/plain; }

    location / {
        proxy_http_version 1.0;
        proxy_set_header Connection "";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_read_timeout 30s;
        proxy_pass http://was_pool;
    }
}
NGINX

docker rm -f lb-internal || true
docker run -d --name lb-internal \
  -p 8080:8080 \
  -v /opt/lb-internal/conf.d:/etc/nginx/conf.d:ro \
  --dns 192.168.56.107 --dns 192.168.56.108 --dns 8.8.8.8 \
  --restart unless-stopped nginx:1.25
SHELL
  end

  # ---------------------------------------------------------------
  # Web + WAS (104 / 105)
  # ---------------------------------------------------------------
  def provision_webwas(node_name)
    <<-SHELL
set -euxo pipefail

# 이 VM의 표시용 이름/호스트 IP 수집
NODE_NAME="#{node_name}"
HOST_IP=$(ip -4 addr | grep -oE '192\\.168\\.56\\.[0-9]+' | head -n1 || true)

# ---------- Static Web ----------
mkdir -p /opt/web-static
cat >/opt/web-static/_node.json <<JSON
{"node":"${NODE_NAME}","host_ip":"${HOST_IP}"}
JSON

# 홈페이지 생성
cat >/opt/web-static/index.html <<'HTML'
<!doctype html>
<html lang="ko">
<head>
  <meta charset="utf-8"/>
  <title>3-Tier Demo (Static Web)</title>
  <link rel="stylesheet" href="/styles.css"/>
</head>
<body>
  <div class="wrap">
    <div class="nav">
      <div class="crumb">External LB → Web(Static) → Internal LB → WAS(PHP) → DB/Redis</div>
      <a class="btn" href="/signup.html">회원가입</a>
    </div>

    <div class="box">
      <h3>현재 Web 노드</h3>
      <ul>
        <li>VM: <b id="webNodeName"></b> (<code id="webNodeIp"></code>)</li>
        <li>Web Hostname: <code id="webHostname"></code></li>
        <li>Web 컨테이너 IP: <code id="webContainerIp"></code></li>
      </ul>
    </div>

    <div id="loginBox" class="box">
      <h2>로그인</h2>
      <input id="username" placeholder="아이디" />
      <input id="password" type="password" placeholder="비밀번호" />
      <button id="btnLogin">Login</button>
    </div>

    <div id="userBox" class="box" style="display:none;">
      <h2><span id="hello"></span></h2>
      <p>세션 ID: <code id="sid"></code></p>
      <div class="subbox">
        <h3>요청을 처리한 WAS</h3>
        <ul>
          <li>VM: <b id="wasVmName"></b> (<code id="wasVmIp"></code>)</li>
          <li>WAS Hostname: <code id="wasHostname"></code></li>
          <li>WAS 컨테이너 IP: <code id="wasContainerIp"></code></li>
        </ul>
      </div>
      <button id="btnLogout">Logout</button>
    </div>
  </div>
  <script src="/app.js"></script>
</body>
</html>
HTML

# 회원가입 페이지 생성
cat >/opt/web-static/signup.html <<'HTML'
<!doctype html>
<html lang="ko">
<head>
  <meta charset="utf-8"/>
  <title>회원가입 - 3-Tier Demo</title>
  <link rel="stylesheet" href="/styles.css"/>
</head>
<body>
  <div class="wrap">
    <div class="nav">
      <div class="crumb">회원가입</div>
      <a class="btn" href="/">로그인으로</a>
    </div>

    <div class="box">
      <h2>회원가입</h2>
      <input id="su_username" placeholder="아이디(영문/숫자 3~32자)" />
      <input id="su_password" type="password" placeholder="비밀번호(8자 이상)" />
      <button id="btnSignup">가입하기</button>
      <pre id="su_out" class="out"></pre>
    </div>
  </div>

  <script>
  async function post(url, data){
    const res = await fetch(url, { method:'POST',
      headers:{'Content-Type':'application/x-www-form-urlencoded'},
      body: new URLSearchParams(data) });
    const t = await res.text();
    try{ return {ok:res.ok, json:JSON.parse(t)} }catch{ return {ok:res.ok, text:t} }
  }
  document.getElementById('btnSignup').addEventListener('click', async ()=>{
    const u = document.getElementById('su_username').value.trim();
    const p = document.getElementById('su_password').value;
    if(!u || !p){ alert('아이디/비밀번호를 입력하세요'); return; }
    const r = await post('/api/signup.php', {username:u, password:p});
    const out = document.getElementById('su_out');
    out.textContent = JSON.stringify(r, null, 2);
    if(r.ok && r.json && r.json.ok){ alert('가입 완료! 이제 로그인하세요.'); window.location.href='/'; }
  });
  </script>
</body>
</html>
HTML

# 스타일시트 작성
cat >/opt/web-static/styles.css <<'CSS'
body { font-family: system-ui, sans-serif; margin:40px; }
.wrap { max-width: 720px; margin: 0 auto; }
.nav { display:flex; justify-content:space-between; align-items:center; margin-bottom:10px; }
.crumb { color:#666; }
.box { padding:16px; border:1px solid #ddd; border-radius:12px; margin:16px 0; }
.subbox { margin-top:12px; padding:12px; border:1px dashed #bbb; border-radius:10px; }
input { padding:8px; margin-right:8px; }
button, .btn { display:inline-block; padding:8px 14px; border:1px solid #ddd; border-radius:10px; text-decoration:none; color:#111; cursor:pointer; }
code { background:#f0f0f0; padding:1px 6px; border-radius:6px; }
pre.out { background:#f7f7f7; padding:12px; overflow:auto; }
CSS

# 프론트엔드 JS 작성(AJAX/세션 표시)
cat >/opt/web-static/app.js <<'JS'
async function getJSON(path, opts={}){
  const res = await fetch(path, Object.assign({credentials:'same-origin'}, opts));
  const t = await res.text();
  try { return { ok: res.ok, status: res.status, json: JSON.parse(t) }; }
  catch { return { ok: res.ok, status: res.status, text: t }; }
}
function setText(id, v){ const el=document.getElementById(id); if(el) el.textContent=v??''; }
function show(id, on){ const el=document.getElementById(id); if(el) el.style.display=on?'block':'none'; }

async function initWebIdentity(){
  const meta = await getJSON('/_node.json');
  if (meta.ok && meta.json){ setText('webNodeName', meta.json.node); setText('webNodeIp', meta.json.host_ip); }

  const who = await getJSON('/__whoami_web');
  if (who.ok && who.json){
    setText('webHostname', who.json.web_hostname);
    setText('webContainerIp', who.json.web_ip);
  } else {
    setText('webHostname', '(unknown)'); setText('webContainerIp', '(unknown)');
  }
}

async function refreshSession(){
  const r = await getJSON('/api/session.php');
  if (r.ok && r.json && r.json.logged_in){
    setText('hello', `안녕, ${r.json.user}`);
    setText('sid', r.json.session_id);
    if (r.json.vm){ setText('wasVmName', r.json.vm.name); setText('wasVmIp', r.json.vm.ip); }
    if (r.json.was){ setText('wasHostname', r.json.was.hostname); setText('wasContainerIp', r.json.was.container_ip); }
    show('loginBox', false); show('userBox', true);
  } else {
    show('userBox', false); show('loginBox', true);
  }
}

async function doLogin(){
  const u = document.getElementById('username').value.trim();
  const p = document.getElementById('password').value;
  if(!u || !p){ alert('아이디/비밀번호를 입력하세요'); return; }
  const r = await getJSON('/api/login.php', {
    method:'POST',
    headers:{'Content-Type':'application/x-www-form-urlencoded'},
    body: new URLSearchParams({username:u, password:p})
  });
  if(!(r.ok && r.json && r.json.ok)){ alert(r.json?.error || '로그인 실패'); }
  await refreshSession();
}
async function doLogout(){ await getJSON('/api/logout.php'); await refreshSession(); }

document.getElementById('btnLogin').addEventListener('click', doLogin);
document.getElementById('btnLogout').addEventListener('click', doLogout);
initWebIdentity().then(refreshSession);
JS

# ---------- Web(Nginx) ----------
mkdir -p /opt/web-nginx/conf.d

# 웹 서버 가상호스트 작성(/api/*만 내부 LB로 프록시)
cat >/opt/web-nginx/conf.d/app.conf <<'NGINX'
server {
  listen 80;
  server_name _;
  add_header X-Proxy web always;

  root /usr/share/nginx/html;
  index index.html;

  location /healthz { return 200 'ok'; add_header Content-Type text/plain; }

  location = /_node.json     { add_header Cache-Control "no-store" always; try_files $uri =404; }
  location = /__whoami_web   { default_type application/json; add_header Cache-Control "no-store" always; return 200 '{"web_hostname":"$hostname","web_ip":"$server_addr"}'; }
  location = /index.html     { add_header Cache-Control "no-store" always; }
  location = /app.js         { add_header Cache-Control "no-store" always; }

  location / { try_files $uri $uri/ /index.html; }

  location /api/ {
    proxy_http_version 1.0;
    proxy_set_header Connection "";
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_read_timeout 30s;
    proxy_pass http://192.168.56.106:8080;
  }
}
NGINX

docker rm -f web || true
docker run -d --name web \
  -p 80:80 \
  -v /opt/web-nginx/conf.d:/etc/nginx/conf.d:ro \
  -v /opt/web-static:/usr/share/nginx/html:ro \
  --dns 192.168.56.107 --dns 192.168.56.108 --dns 8.8.8.8 \
  --restart unless-stopped nginx:1.25

# ---------- WAS(PHP-Apache) ----------
mkdir -p /opt/was-php/src/api

# PHP-Apache Dockerfile 작성(확장 모듈 설치 포함)
cat >/opt/was-php/Dockerfile <<'DOCKER'
FROM php:8.2-apache
RUN set -eux; \
    a2enmod rewrite; \
    apt-get update; \
    apt-get install -y --no-install-recommends $PHPIZE_DEPS; \
    docker-php-ext-install pdo_mysql; \
    pecl install redis; \
    docker-php-ext-enable redis; \
    apt-get purge -y --auto-remove -o APT::AutoRemove::RecommendsImportant=false $PHPIZE_DEPS; \
    rm -rf /var/lib/apt/lists/*
COPY php.ini /usr/local/etc/php/conf.d/app.ini
COPY src/ /var/www/html/
DOCKER

# PHP 설정(세션을 redis로)
cat >/opt/was-php/php.ini <<'INI'
date.timezone=Asia/Seoul
expose_php=0
session.cookie_httponly=1
session.use_strict_mode=1
session.save_handler=redis
session.save_path="tcp://redis.3tier.test:6379"
INI

# Apache 리라이트 최소 설정
cat >/opt/was-php/src/.htaccess <<'HT'
RewriteEngine On
RewriteBase /
HT

# 세션 상태 확인 API
cat >/opt/was-php/src/api/session.php <<'PHP'
<?php
header('Content-Type: application/json; charset=utf-8');

$logged_in = false;
$user = null;
$sid = null;

if (isset($_COOKIE[session_name()])) {
  session_start();
  if (!empty($_SESSION['user'])) {
    $logged_in = true;
    $user = $_SESSION['user'];
    $sid = session_id();
  }
}

$vm = [
  'name' => getenv('VM_NAME') ?: null,
  'ip'   => getenv('VM_IP') ?: null,
];

$resp = [
  'logged_in' => $logged_in,
  'user' => $user,
  'session_id' => $logged_in ? $sid : null,
  'vm'  => $vm,
  'was' => $logged_in ? [
    'hostname'     => gethostname(),
    'container_ip' => $_SERVER['SERVER_ADDR'] ?? null,
    'remote_addr'  => $_SERVER['REMOTE_ADDR'] ?? null,
  ] : null
];

echo json_encode($resp);
PHP

# 로그인 API
cat >/opt/was-php/src/api/login.php <<'PHP'
<?php
header('Content-Type: application/json; charset=utf-8');
session_start();

$u = $_POST['username'] ?? '';
$p = $_POST['password'] ?? '';
if ($u === '' || $p === '') {
  http_response_code(400);
  echo json_encode(['ok'=>false, 'error'=>'아이디/비밀번호 필요']); exit;
}

try {
  $dbhost = getenv('DB_HOST'); $dbuser = getenv('DB_USER');
  $dbpass = getenv('DB_PASSWORD'); $dbname = getenv('DB_NAME');
  $pdo = new PDO("mysql:host=$dbhost;dbname=$dbname;charset=utf8mb4",
                 $dbuser, $dbpass, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);

  $stmt = $pdo->prepare("SELECT password_hash FROM appdb.users WHERE username = :u");
  $stmt->execute([':u'=>$u]);
  $row = $stmt->fetch(PDO::FETCH_ASSOC);
  if ($row && password_verify($p, $row['password_hash'])) {
    $_SESSION['user'] = $u;
    echo json_encode(['ok'=>true]); exit;
  }
  http_response_code(401);
  echo json_encode(['ok'=>false,'error'=>'로그인 실패']);
} catch (Throwable $e) {
  http_response_code(500);
  echo json_encode(['ok'=>false,'error'=>'서버 오류']);
}
PHP

# 회원가입 API
cat >/opt/was-php/src/api/signup.php <<'PHP'
<?php
header('Content-Type: application/json; charset=utf-8');

$u = $_POST['username'] ?? '';
$p = $_POST['password'] ?? '';

if (!preg_match('/^[A-Za-z0-9_]{3,32}$/', $u)) {
  http_response_code(400);
  echo json_encode(['ok'=>false,'error'=>'아이디 형식 오류']); exit;
}
if (strlen($p) < 8) {
  http_response_code(400);
  echo json_encode(['ok'=>false,'error'=>'비밀번호는 8자 이상']); exit;
}

try {
  $dbhost = getenv('DB_HOST'); $dbuser = getenv('DB_USER');
  $dbpass = getenv('DB_PASSWORD'); $dbname = getenv('DB_NAME');
  $pdo = new PDO("mysql:host=$dbhost;dbname=$dbname;charset=utf8mb4",
                 $dbuser, $dbpass, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);

  $stmt = $pdo->prepare("SELECT 1 FROM appdb.users WHERE username=:u");
  $stmt->execute([':u'=>$u]);
  if ($stmt->fetch()) { http_response_code(409); echo json_encode(['ok'=>false,'error'=>'이미 존재하는 아이디']); exit; }

  $hash = password_hash($p, PASSWORD_DEFAULT);
  $ins = $pdo->prepare("INSERT INTO appdb.users(username, password_hash) VALUES(:u,:h)");
  $ins->execute([':u'=>$u, ':h'=>$hash]);

  echo json_encode(['ok'=>true,'user'=>$u]);
} catch (Throwable $e) {
  http_response_code(500);
  echo json_encode(['ok'=>false,'error'=>'서버 오류']);
}
PHP

# 로그아웃
cat >/opt/was-php/src/api/logout.php <<'PHP'
<?php
header('Content-Type: application/json; charset=utf-8');
session_start();
session_destroy();
echo json_encode(['ok'=>true]);
PHP

# 헬스체크
cat >/opt/was-php/src/api/healthz.php <<'PHP'
<?php header('Content-Type: text/plain; charset=utf-8'); echo "ok";
PHP

docker build -t was-php:1 /opt/was-php

docker rm -f was || true
docker run -d --name was \
  -p 8081:80 \
  --dns 192.168.56.107 --dns 192.168.56.108 --dns 8.8.8.8 \
  -e DB_HOST=db.3tier.test -e DB_USER=app -e DB_PASSWORD='AppPwd!' -e DB_NAME=appdb \
  -e VM_NAME="${NODE_NAME}" -e VM_IP="${HOST_IP}" \
  --restart unless-stopped was-php:1
SHELL
  end

  # ---------------------------------------------------------------
  # DBDNS Primary (107): DB/Redis/CoreDNS + 키 생성/공유 + 백업 + 108으로 push
  # ---------------------------------------------------------------
  def provision_dbdns
    <<-'SHELL'
set -euxo pipefail

# systemd-resolved의 53 포트 점유 해제
mkdir -p /etc/systemd/resolved.conf.d
cat >/etc/systemd/resolved.conf.d/disable-stub.conf <<'CONF'
[Resolve]
DNSStubListener=no
CONF
systemctl restart systemd-resolved

# MariaDB 데이터/초기 SQL 디렉터리 준비
mkdir -p /opt/mariadb/data /opt/mariadb/init
cat >/opt/mariadb/init/00_init.sql <<'SQL'
CREATE DATABASE IF NOT EXISTS appdb;
CREATE TABLE IF NOT EXISTS appdb.users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(64) NOT NULL UNIQUE,
  password_hash VARCHAR(255) NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
SQL

docker rm -f mariadb || true
docker run -d --name mariadb \
  -e MARIADB_ROOT_PASSWORD='RootPwd!' \
  -e MARIADB_DATABASE=appdb \
  -e MARIADB_USER=app \
  -e MARIADB_PASSWORD='AppPwd!' \
  -p 3306:3306 \
  -v /opt/mariadb/data:/var/lib/mysql \
  -v /opt/mariadb/init:/docker-entrypoint-initdb.d \
  --restart unless-stopped mariadb:10.6

# DB 가동 대기(최대 80초)
for i in $(seq 1 40); do
  if docker exec mariadb mariadb -uroot -pRootPwd! -e "SELECT 1" >/dev/null 2>&1; then
    echo "MariaDB is up"; break
  fi
  sleep 2
done

# Redis
docker rm -f redis || true
docker run -d --name redis -p 6379:6379 --restart unless-stopped redis:7-alpine

# CoreDNS 존파일/코어파일 작성
mkdir -p /opt/coredns
cat >/opt/coredns/3tier.test.zone <<'ZONE'
$TTL 60
@   IN SOA  ns.3tier.test. admin.3tier.test. ( 2025100701 7200 3600 1209600 60 )
    IN NS   ns.3tier.test.
ns          IN A    192.168.56.107
; LBs
lb-external IN A    192.168.56.103
lb-internal IN A    192.168.56.106
; APP
webwas1     IN A    192.168.56.104
webwas2     IN A    192.168.56.105
; DB/Redis (초기=107)
db          IN A    192.168.56.107
redis       IN A    192.168.56.107
ZONE

cat >/opt/coredns/Corefile <<'CORE'
. {
  log
  errors
  cache 10
  forward . 8.8.8.8
}
3tier.test {
  file /etc/coredns/3tier.test.zone
  log
  errors
}
CORE

docker rm -f coredns || true
docker run -d --name coredns \
  -p 53:53/udp -p 53:53/tcp \
  -v /opt/coredns:/etc/coredns \
  --restart unless-stopped \
  coredns/coredns:1.11.1 -conf /etc/coredns/Corefile

# 백업에 필요한 패키지 설치(cron/ssh/scp/nc)
apt-get update
apt-get install -y cron openssh-client rsync netcat-openbsd
systemctl enable --now cron

# 백업 저장 디렉터리 생성(775, root:root)
install -d -m 0775 /opt/backups/mysql
chown root:root /opt/backups/mysql

# vagrant 전용 SSH 키(없으면 생성)
install -m 0700 -d /home/vagrant/.ssh
if [ ! -f /home/vagrant/.ssh/dbrep_ed25519 ]; then
  sudo -u vagrant ssh-keygen -t ed25519 -N "" -f /home/vagrant/.ssh/dbrep_ed25519
fi
chmod 700 /home/vagrant/.ssh
chmod 600 /home/vagrant/.ssh/dbrep_ed25519 /home/vagrant/.ssh/dbrep_ed25519.pub
chown -R vagrant:vagrant /home/vagrant/.ssh

# 공개키를 공유폴더로 복사(108이 가져감)
install -d -m 0755 /vagrant/keys
cp -f /home/vagrant/.ssh/dbrep_ed25519.pub /vagrant/keys/dbrep_ed25519.pub
chmod 0644 /vagrant/keys/dbrep_ed25519.pub

# 백업 스크립트 작성(덤프→gzip→보관→108로 전송)
cat >/usr/local/bin/mariadb_backup.sh <<'BACKUP'
#!/usr/bin/env bash
set -euo pipefail

DOCKER="/usr/bin/docker"
DEST="/opt/backups/mysql"
RETENTION_DAYS="7"
UMASK="027"

TARGET_HOST="192.168.56.108"
TARGET_USER="vagrant"
SSH_KEY="/home/vagrant/.ssh/dbrep_ed25519"
SSH_OPTS="-i ${SSH_KEY} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/home/vagrant/.ssh/known_hosts"

umask "${UMASK}"
mkdir -p "${DEST}"

TS="$(date +%F_%H%M%S)"
OUT="${DEST}/appdb-${TS}.sql.gz"
BN="$(basename "${OUT}")"

${DOCKER} exec mariadb bash -lc 'mariadb-dump -uroot -pRootPwd! --single-transaction --routines --events --triggers appdb' | gzip > "${OUT}"
gzip -t "${OUT}"

find "${DEST}" -type f -name 'appdb-*.sql.gz' -mtime +${RETENTION_DAYS} -print -delete || true
echo "[`date '+%F %T'`] backup ok -> ${OUT}"

if [ -f "${SSH_KEY}" ]; then
  if timeout 3 nc -z ${TARGET_HOST} 22 >/dev/null 2>&1; then
    if scp ${SSH_OPTS} "${OUT}" "${TARGET_USER}@${TARGET_HOST}:~/${BN}"; then
      ssh ${SSH_OPTS} "${TARGET_USER}@${TARGET_HOST}" \
        "sudo install -d -m 0775 /opt/backups/mysql && sudo mv ~/${BN} /opt/backups/mysql/${BN} && sudo chown root:root /opt/backups/mysql/${BN} && sudo chmod 640 /opt/backups/mysql/${BN}"
      echo "[`date '+%F %T'`] pushed ${BN} to ${TARGET_HOST}:/opt/backups/mysql"
    else
      echo "[`date '+%F %T'`] WARN: push to ${TARGET_HOST} failed (scp)"
    fi
  else
    echo "[`date '+%F %T'`] INFO: ${TARGET_HOST}:22 not reachable; skip push"
  fi
else
  echo "[`date '+%F %T'`] INFO: SSH key ${SSH_KEY} not found; skip push"
fi
BACKUP

# 실행권한 부여
chmod +x /usr/local/bin/mariadb_backup.sh

# 크론 일정(매일 03:00) 등록
cat >/etc/cron.d/mariadb_backup <<'CRON'
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
MAILTO=""
0 3 * * * root /usr/local/bin/mariadb_backup.sh >> /var/log/mariadb_backup.log 2>&1
CRON

chmod 0644 /etc/cron.d/mariadb_backup
systemctl restart cron
SHELL
  end

  # ---------------------------------------------------------------
  # DBDNS Backup (108): DB/Redis/CoreDNS + 107 공개키 등록(authorized_keys)
  # ---------------------------------------------------------------
  def provision_dbdns_backup
    <<-'SHELL'
set -euxo pipefail

# systemd-resolved의 53 포트 점유 해제
mkdir -p /etc/systemd/resolved.conf.d
cat >/etc/systemd/resolved.conf.d/disable-stub.conf <<'CONF'
[Resolve]
DNSStubListener=no
CONF
systemctl restart systemd-resolved

# MariaDB 데이터/초기 SQL 디렉터리 준비
mkdir -p /opt/mariadb/data /opt/mariadb/init
cat >/opt/mariadb/init/00_init.sql <<'SQL'
CREATE DATABASE IF NOT EXISTS appdb;
CREATE TABLE IF NOT EXISTS appdb.users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(64) NOT NULL UNIQUE,
  password_hash VARCHAR(255) NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
SQL

docker rm -f mariadb || true
docker run -d --name mariadb \
  -e MARIADB_ROOT_PASSWORD='RootPwd!' \
  -e MARIADB_DATABASE=appdb \
  -e MARIADB_USER=app \
  -e MARIADB_PASSWORD='AppPwd!' \
  -p 3306:3306 \
  -v /opt/mariadb/data:/var/lib/mysql \
  -v /opt/mariadb/init:/docker-entrypoint-initdb.d \
  --restart unless-stopped mariadb:10.6

# DB 가동 대기(최대 80초)
for i in $(seq 1 40); do
  if docker exec mariadb mariadb -uroot -pRootPwd! -e "SELECT 1" >/dev/null 2>&1; then
    echo "MariaDB is up"; break
  fi
  sleep 2
done

# Redis
docker rm -f redis || true
docker run -d --name redis -p 6379:6379 --restart unless-stopped redis:7-alpine

# CoreDNS 존파일/코어파일 작성
mkdir -p /opt/coredns
cat >/opt/coredns/3tier.test.zone <<'ZONE'
$TTL 60
@   IN SOA  ns.3tier.test. admin.3tier.test. ( 2025100701 7200 3600 1209600 60 )
    IN NS   ns.3tier.test.
ns          IN A    192.168.56.108
; LBs
lb-external IN A    192.168.56.103
lb-internal IN A    192.168.56.106
; APP
webwas1     IN A    192.168.56.104
webwas2     IN A    192.168.56.105
; DB/Redis (초기=107, 장애 시 108로 수정 후 coredns 재시작)
db          IN A    192.168.56.107
redis       IN A    192.168.56.107
ZONE

cat >/opt/coredns/Corefile <<'CORE'
. {
  log
  errors
  cache 10
  forward . 8.8.8.8
}
3tier.test {
  file /etc/coredns/3tier.test.zone
  log
  errors
}
CORE

docker rm -f coredns || true
docker run -d --name coredns \
  -p 53:53/udp -p 53:53/tcp \
  -v /opt/coredns:/etc/coredns \
  --restart unless-stopped \
  coredns/coredns:1.11.1 -conf /etc/coredns/Corefile

# 크론 설치/활성화 + 백업 로컬 보관 디렉터리 생성
apt-get update
apt-get install -y cron
systemctl enable --now cron
install -d -m 0775 /opt/backups/mysql

# -------- 키 등록 --------
# /vagrant/keys/dbrep_ed25519.pub 생길 때까지 최대 60초 대기
for i in $(seq 1 60); do
  [ -s /vagrant/keys/dbrep_ed25519.pub ] && break || sleep 1
done

if [ -s /vagrant/keys/dbrep_ed25519.pub ]; then
  # vagrant 홈의 .ssh 준비 및 권한 보정
  install -m 0700 -d /home/vagrant/.ssh
  touch /home/vagrant/.ssh/authorized_keys
  chmod 600 /home/vagrant/.ssh/authorized_keys

  # 키의 base64 본문 추출 및 중복 검사 후, from= 옵션을 붙여 한 줄 추가
  KEYBASE=$(awk '{print $2}' /vagrant/keys/dbrep_ed25519.pub | tr -d '\r\n')
  if [ -n "${KEYBASE}" ] && ! grep -qF "${KEYBASE}" /home/vagrant/.ssh/authorized_keys; then
    awk '{sub(/\r$/,"",$0); print "from=\"192.168.56.107\",no-agent-forwarding,no-port-forwarding,no-X11-forwarding,no-pty " $0}' \
      /vagrant/keys/dbrep_ed25519.pub >> /home/vagrant/.ssh/authorized_keys
    chmod 600 /home/vagrant/.ssh/authorized_keys
  fi
  chown -R vagrant:vagrant /home/vagrant/.ssh
else
  echo "WARN: /vagrant/keys/dbrep_ed25519.pub not found; skip key install"
fi
SHELL
  end

  # -------------------- VM들 정의 --------------------
  config.vm.define "lb-external" do |node|
    node.vm.hostname = "lb-external"
    node.vm.network "private_network", ip: "192.168.56.103"
    node.vm.provider "virtualbox" do |vb|
      vb.name = "lab-lb-external"
      vb.memory = 1024
      vb.cpus = 1
    end
    node.vm.provision "shell", inline: docker_install
    node.vm.provision "shell", inline: provision_lb_external
  end

  config.vm.define "webwas1" do |node|
    node.vm.hostname = "webwas1"
    node.vm.network "private_network", ip: "192.168.56.104"
    node.vm.provider "virtualbox" do |vb|
      vb.name = "lab-webwas1"
      vb.memory = 1024
      vb.cpus = 1
    end
    node.vm.provision "shell", inline: docker_install
    node.vm.provision "shell", inline: provision_webwas("webwas1")
  end

  config.vm.define "webwas2" do |node|
    node.vm.hostname = "webwas2"
    node.vm.network "private_network", ip: "192.168.56.105"
    node.vm.provider "virtualbox" do |vb|
      vb.name = "lab-webwas2"
      vb.memory = 1024
      vb.cpus = 1
    end
    node.vm.provision "shell", inline: docker_install
    node.vm.provision "shell", inline: provision_webwas("webwas2")
  end

  config.vm.define "lb-internal" do |node|
    node.vm.hostname = "lb-internal"
    node.vm.network "private_network", ip: "192.168.56.106"
    node.vm.provider "virtualbox" do |vb|
      vb.name = "lab-lb-internal"
      vb.memory = 1024
      vb.cpus = 1
    end
    node.vm.provision "shell", inline: docker_install
    node.vm.provision "shell", inline: provision_lb_internal
  end

  config.vm.define "dbdns" do |node|
    node.vm.hostname = "dbdns"
    node.vm.network "private_network", ip: "192.168.56.107"
    node.vm.provider "virtualbox" do |vb|
      vb.name = "lab-dbdns"
      vb.memory = 1024
      vb.cpus = 1
    end
    node.vm.provision "shell", inline: docker_install
    node.vm.provision "shell", inline: provision_dbdns
  end

  config.vm.define "dbdns-backup" do |node|
    node.vm.hostname = "dbdns-backup"
    node.vm.network "private_network", ip: "192.168.56.108"
    node.vm.provider "virtualbox" do |vb|
      vb.name = "lab-dbdns-backup"
      vb.memory = 1024
      vb.cpus = 1
    end
    node.vm.provision "shell", inline: docker_install
    node.vm.provision "shell", inline: provision_dbdns_backup
  end
end
