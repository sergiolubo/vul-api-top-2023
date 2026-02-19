from fastapi import FastAPI, Request, HTTPException, Header
from fastapi.responses import JSONResponse
import time, os, jwt, requests

app = FastAPI(title="Vuln API - OWASP API Top 10 (2023) demo")

MODE = os.getenv("MODE", "vuln")  # "vuln" o "fixed"
JWT_SECRET = "dev-secret"         # intencionalmente débil para demo

# "Base de datos" en memoria (demo)
ORDERS = {
    "1001": {"order_id": "1001", "user_id": "u1", "items": ["mouse", "teclado"], "total": 180},
    "1002": {"order_id": "1002", "user_id": "u2", "items": ["ssd"], "total": 250},
}
USERS = {
    "u1": {"id": "u1", "email": "u1@demo.com", "role": "user"},
    "u2": {"id": "u2", "email": "u2@demo.com", "role": "user"},
    "admin": {"id": "admin", "email": "admin@demo.com", "role": "admin"},
}

# ---- API2 helpers (demo) ----
FAILED_LOGINS = {}  # key: email:ip -> {"count": int, "blocked_until": epoch}
BLOCK_SECONDS = 30
MAX_ATTEMPTS = 5

# contraseñas DEMO (plaintext solo para laboratorio)
PASSWORDS = {
    "u1": "U1-pass-123!",
    "u2": "U2-pass-123!",
    "admin": "Admin-pass-123!",
}

def now():
    return int(time.time())

def get_user_from_token(auth: str | None):
    # MODE vuln: acepta tokens sin validar adecuadamente (API2 / API8)
    if not auth or not auth.startswith("Bearer "):
        return None
    token = auth.split(" ", 1)[1]
    try:
        if MODE == "vuln":
            # mala práctica: no validar issuer/audience, y aceptar HS256 con secret débil
            payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"], options={"verify_exp": False})
        else:
            payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"], options={"verify_exp": True})
        uid = payload.get("sub")
        return USERS.get(uid)
    except Exception:
        return None

@app.get("/health")
def health():
    return {"ok": True, "mode": MODE}

# ------------------------------------------------------------
# API1: Broken Object Level Authorization (BOLA)
# ------------------------------------------------------------
@app.get("/api/orders/{order_id}")
def get_order(order_id: str, authorization: str | None = Header(default=None)):
    user = get_user_from_token(authorization)
    if not user:
        raise HTTPException(401, "Unauthorized")

    order = ORDERS.get(order_id)
    if not order:
        raise HTTPException(404, "Not found")

    if MODE == "fixed":
        # mitigación: validar propiedad del recurso
        if order["user_id"] != user["id"] and user["role"] != "admin":
            raise HTTPException(403, "Forbidden")
    # vuln: devuelve el pedido aunque no sea del usuario
    return order

# ------------------------------------------------------------
# API2: Broken Authentication
# (login sin rate limit + JWT débil)
# ------------------------------------------------------------
@app.post("/api/auth/login")
async def login(req: Request):
    body = await req.json()
    email = (body.get("email", "") or "").strip().lower()
    password = body.get("password", "") or ""

    # identificador simple de cliente para demo (IP)
    client_ip = req.client.host if req.client else "unknown"
    key = f"{email}:{client_ip}"

    # ---- FIXED: bloqueo temporal ante fuerza bruta ----
    state = FAILED_LOGINS.get(key, {"count": 0, "blocked_until": 0})
    if MODE == "fixed" and state["blocked_until"] > now():
        raise HTTPException(429, f"Temporarily blocked. Try again in {state['blocked_until'] - now()}s")

    # vuln: credenciales triviales para demo y sin rate limit
    if MODE == "fixed" and len(password) < 10:
        raise HTTPException(400, "Weak password rejected (demo)")

    # demo: si el email existe, lo deja pasar con cualquier password (vuln)
    user = next((u for u in USERS.values() if u["email"] == email), None)
    if not user:
        if MODE == "fixed":
            state["count"] += 1
            if state["count"] >= MAX_ATTEMPTS:
                state["blocked_until"] = now() + BLOCK_SECONDS
                state["count"] = 0
            FAILED_LOGINS[key] = state
        raise HTTPException(401, "Invalid credentials")

    if MODE == "vuln":
        pass_ok = True
    else:
        pass_ok = (PASSWORDS.get(user["id"]) == password)

    if not pass_ok:
        state["count"] += 1
        if state["count"] >= MAX_ATTEMPTS:
            state["blocked_until"] = now() + BLOCK_SECONDS
            state["count"] = 0
        FAILED_LOGINS[key] = state
        raise HTTPException(401, "Invalid credentials")

    # login exitoso => reset intentos
    FAILED_LOGINS.pop(key, None)

    # JWT: exp corta en fixed; exp exagerada en vuln
    exp = now() + (120 if MODE == "fixed" else 10**9)
    token = jwt.encode({"sub": user["id"], "exp": exp}, JWT_SECRET, algorithm="HS256")
    return {"access_token": token, "expires_in": exp - now()}

# API2 (extra demo): credenciales en URL (anti-patrón)
@app.get("/api/auth/login_via_url")
def login_via_url(email: str, password: str):
    # Esto es intencionalmente inseguro: credenciales en URL quedan en logs/historial.
    if MODE == "fixed":
        raise HTTPException(410, "Disabled in fixed mode")
    user = next((u for u in USERS.values() if u["email"] == (email or "").strip().lower()), None)
    if not user:
        raise HTTPException(401, "Invalid credentials")
    token = jwt.encode({"sub": user["id"], "exp": now() + 10**9}, JWT_SECRET, algorithm="HS256")
    return {"access_token": token, "warning": "Credentials were sent in URL (BAD PRACTICE)"}

# API2 (extra demo): operación sensible sin re-autenticación vs con re-auth
@app.post("/api/users/{user_id}/change-email")
async def change_email(user_id: str, req: Request, authorization: str | None = Header(default=None)):
    user = get_user_from_token(authorization)
    if not user:
        raise HTTPException(401, "Unauthorized")

    body = await req.json()
    new_email = (body.get("new_email", "") or "").strip().lower()

    if user_id not in USERS:
        raise HTTPException(404, "Not found")

    # vuln: no exige password actual + permite cambiar email de otro usuario (doble falla)
    if MODE == "vuln":
        USERS[user_id]["email"] = new_email
        return {"status": "email_changed", "user_id": user_id, "new_email": new_email, "note": "No re-auth (vuln)"}

    # fixed: exige password actual y sólo el dueño (o admin)
    current_password = body.get("current_password", "") or ""
    if user["id"] != user_id and user["role"] != "admin":
        raise HTTPException(403, "Forbidden")

    # En fixed validamos el password actual contra el email actual del usuario autenticado
    if PASSWORDS.get(user["id"]) != current_password:
        raise HTTPException(401, "Re-auth failed: current_password invalid")

    USERS[user_id]["email"] = new_email
    return {"status": "email_changed", "user_id": user_id, "new_email": new_email, "note": "Re-auth OK (fixed)"}

# ------------------------------------------------------------
# API3: Broken Object Property Level Authorization (BOPLA)
# (mass assignment: el cliente puede setear "role")
# ------------------------------------------------------------
@app.put("/api/users/{user_id}")
async def update_user(user_id: str, req: Request, authorization: str | None = Header(default=None)):
    user = get_user_from_token(authorization)
    if not user:
        raise HTTPException(401, "Unauthorized")

    body = await req.json()

    # vuln: cualquiera actualiza a cualquiera (BOLA) + mass assignment (BOPLA)
    target = USERS.get(user_id)
    if not target:
        raise HTTPException(404, "Not found")

    if MODE == "fixed":
        # mitigación: allowlist + propiedad por rol
        allowed = {"email"}  # NO permitir role
        for k in list(body.keys()):
            if k not in allowed:
                body.pop(k, None)
        if user["id"] != user_id and user["role"] != "admin":
            raise HTTPException(403, "Forbidden")

    # aplica cambios (en vuln permite role="admin")
    target.update(body)
    return {"updated": target}

# ------------------------------------------------------------
# API4: Unrestricted Resource Consumption
# (sin paginación/limit, devuelve "mucho" y simula costo)
# ------------------------------------------------------------
@app.get("/api/reports/export")
def export_report(size: int = 50000):
    if MODE == "fixed":
        if size > 5000:
            raise HTTPException(400, "Limit exceeded (demo)")

    # simula CPU/mem/tiempo
    data = [{"i": i, "value": "x"*50} for i in range(size)]
    return {"rows": len(data)}

# ------------------------------------------------------------
# API5: Broken Function Level Authorization (BFLA)
# (endpoint admin sin control)
# ------------------------------------------------------------
@app.get("/api/admin/users")
def admin_list_users(authorization: str | None = Header(default=None)):
    user = get_user_from_token(authorization)
    if MODE == "fixed":
        if not user or user["role"] != "admin":
            raise HTTPException(403, "Admins only")
    # vuln: cualquiera puede listar
    return {"users": list(USERS.values())}

# ------------------------------------------------------------
# API6: Unrestricted Access to Sensitive Business Flows
# (compras/reservas sin controles anti-bot)
# ------------------------------------------------------------
@app.post("/api/checkout")
async def checkout(req: Request):
    body = await req.json()
    product = body.get("product", "unknown")

    if MODE == "fixed":
        # mitigación mínima demo: freno por "cooldown" (en real sería rate-limit + antifraude)
        time.sleep(0.3)

    return {"status": "purchased", "product": product, "note": "demo flow (no anti-bot in vuln mode)"}

# ------------------------------------------------------------
# API7: SSRF
# (fetch de URL proporcionada por el usuario)
# ------------------------------------------------------------
@app.get("/api/fetch")
def fetch(url: str):
    if MODE == "fixed":
        # mitigación demo: allowlist básica
        if not (url.startswith("https://example.com/") or url.startswith("https://httpbin.org/")):
            raise HTTPException(400, "URL not allowed (demo allowlist)")

    try:
        r = requests.get(url, timeout=2)
        return {"status_code": r.status_code, "len": len(r.text)}
    except Exception as e:
        return {"error": str(e)}

# ------------------------------------------------------------
# API8: Security Misconfiguration
# (errores verbosos / debug)
# ------------------------------------------------------------
@app.get("/api/debug/boom")
def boom():
    try:
        1 / 0
    except Exception as e:
        if MODE == "fixed":
            return JSONResponse({"error": "Internal error"}, status_code=500)
        # vuln: expone detalle interno
        return JSONResponse({"error": str(e), "detail": "stacktrace would be here (demo)"}, status_code=500)

# ------------------------------------------------------------
# API9: Improper Inventory Management
# (versiones viejas activas)
# ------------------------------------------------------------
@app.get("/api/v1/legacy-users")
def legacy_users():
    if MODE == "fixed":
        raise HTTPException(410, "Legacy API retired")
    # vuln: endpoint viejo, sin auth
    return {"legacy": True, "users": list(USERS.values())}

@app.get("/api/v2/users")
def v2_users(authorization: str | None = Header(default=None)):
    user = get_user_from_token(authorization)
    if not user:
        raise HTTPException(401, "Unauthorized")
    return {"v2": True, "users": [{"id": u["id"], "email": u["email"]} for u in USERS.values()]}

# ------------------------------------------------------------
# API10: Unsafe Consumption of APIs
# (confía en un tercero, sin validar, sigue redirecciones/inputs)
# ------------------------------------------------------------
@app.get("/api/thirdparty/profile")
def thirdparty_profile(user: str = "demo"):
    # demo: en vuln confía en respuesta de tercero y la re-expone
    url = f"https://httpbin.org/anything?user={user}"
    if MODE == "fixed":
        # mitigación demo: timeout y validación superficial de tamaño
        r = requests.get(url, timeout=2)
        if len(r.text) > 2000:
            raise HTTPException(400, "Response too large")
        return {"safe_proxy": True, "data": r.json().get("args", {})}
    else:
        r = requests.get(url)  # sin timeout
        return {"proxy": True, "raw": r.text[:3000]}
