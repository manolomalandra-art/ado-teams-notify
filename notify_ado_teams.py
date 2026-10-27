#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
notify_ado_teams.py - Notifica cambios de work items de Azure DevOps
(historias/tasks/bugs nuevos y cambios de estado o columna) a un canal
PRIVADO de Teams usando un webhook de Workflows (adaptive cards).

No requiere licencia premium de Power Automate ni permisos de proceso:
solo un PAT de Azure DevOps con lectura de work items.

Config por variables de entorno:
  ADO_ORG            (default: azbltdo001)
  ADO_PROJECT        (default: Digital Predictive)
  ADO_PAT            PAT de solo lectura (si falta, se pide al ejecutar)
  TEAMS_WEBHOOK_URL  URL del webhook de Workflows. Alternativa: guardarla
                     en el archivo .teams_webhook.txt junto a este script.

Uso:
  python notify_ado_teams.py --test       # solo prueba el webhook (sin PAT)
  python notify_ado_teams.py --dry-run    # muestra las tarjetas sin publicar
  python notify_ado_teams.py              # chequeo normal (diff vs snapshot)
"""

import argparse
import base64
import getpass
import html
import json
import os
import re
import sys
import time
from datetime import datetime, timedelta, timezone
from urllib.request import Request, urlopen, build_opener, HTTPRedirectHandler
from urllib.error import HTTPError, URLError
from urllib.parse import quote

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

ORG = os.environ.get("ADO_ORG", "azbltdo001").strip() or "azbltdo001"
PROJECT = os.environ.get("ADO_PROJECT", "Digital Predictive").strip() or "Digital Predictive"
BASE = "https://dev.azure.com/{}/{}".format(ORG, quote(PROJECT))
API = BASE + "/_apis"
WIQL_URL = API + "/wit/wiql?api-version=7.1"
WIT_URL = API + "/wit/workitems?api-version=7.1"
WI_ITEMS_URL = BASE + "/_workitems/edit/{}"
COMMENTS_URL = API + "/wit/workitems/{}/comments?api-version=7.1-preview.4"

TYPES = ("User Story", "Task", "Bug")
CORE_FIELDS = "System.Id,System.Title,System.State,System.WorkItemType,System.AssignedTo,System.ChangedDate"
OPT_FIELDS = CORE_FIELDS + ",System.ChangedBy,System.BoardColumn,System.History,System.CommentCount," \
    "Microsoft.VSTS.Scheduling.StartDate,Microsoft.VSTS.Scheduling.FinishDate," \
    "Microsoft.VSTS.Scheduling.DueDate"
STATE_FILE = os.environ.get("ADO_STATE_FILE", "").strip() or os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "ado_teams_state.json")
WEBHOOK_FILE = os.environ.get("ADO_WEBHOOK_FILE", "").strip() or os.path.join(
    os.path.dirname(os.path.abspath(__file__)), ".teams_webhook.txt")
LOOKBACK_HOURS_FIRST = 48          # ventana inicial al no haber snapshot
OVERLAP_MIN = 30                   # solape con la ultima corrida
MAX_CARDS = 20

_auth = None


# ------------------------------------------------------------------ HTTP --

def _req(method, url, payload=None, headers=None, timeout=30):
    body = json.dumps(payload).encode("utf-8") if payload is not None else None
    h = {"Content-Type": "application/json"} if body else {}
    if headers:
        h.update(headers)
    if _auth and "dev.azure.com" in url:
        h["Authorization"] = "Basic " + _auth
    req = Request(url, data=body, method=method, headers=h)
    with urlopen(req, timeout=timeout) as resp:
        raw = resp.read().decode("utf-8", "replace")
        ctype = resp.headers.get("Content-Type", "?")
    if not raw.strip():
        return {}
    try:
        return json.loads(raw)
    except ValueError:
        raise RuntimeError(
            "Respuesta no-JSON de {} [Content-Type: {}]\nPrimeros 400 caracteres:\n{}".format(
                url, ctype, raw[:400]))


def ado(method, url, payload=None):
    try:
        return _req(method, url, payload)
    except HTTPError as e:
        detail = e.read().decode("utf-8", "replace")[:400]
        raise RuntimeError("ADO HTTP {} en {}\n{}".format(e.code, url, detail))
    except URLError as e:
        raise RuntimeError("Sin conexion con ADO ({}): {}".format(url, e.reason))


# ------------------------------------------------------------- configuracion --

def get_pat():
    pat = os.environ.get("ADO_PAT", "").strip()
    if not pat:
        pat = getpass.getpass("PAT de Azure DevOps (solo lectura): ").strip()
    if not pat:
        raise SystemExit("PAT vacio.")
    return pat


def get_webhook():
    url = os.environ.get("TEAMS_WEBHOOK_URL", "").strip()
    if not url and os.path.isfile(WEBHOOK_FILE):
        with open(WEBHOOK_FILE, "r", encoding="utf-8-sig") as f:
            url = f.read().strip()
    if not url:
        url = input("URL del webhook de Teams: ").strip()
    if not url.startswith("https://"):
        raise SystemExit("URL de webhook invalida.")
    return url


def set_auth(pat):
    global _auth, _pat_raw
    _auth = base64.b64encode((":" + pat).encode("ascii")).decode("ascii")
    _pat_raw = pat


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _probe(url, with_auth):
    h = {}
    if with_auth and _auth:
        h["Authorization"] = "Basic " + _auth
    opener = build_opener(_NoRedirect)
    req = Request(url, headers=h, method="GET")
    try:
        with opener.open(req, timeout=30) as r:
            raw = r.read(300).decode("utf-8", "replace")
            return "HTTP {} body={!r}".format(r.status, raw[:200])
    except HTTPError as e:
        loc = e.headers.get("Location", "")
        body = ""
        try:
            body = e.read().decode("utf-8", "replace")[:200]
        except Exception:
            pass
        extra = (" -> REDIRECT A: " + loc) if loc else ""
        return "HTTP {}{} body={!r}".format(e.code, extra, body)
    except URLError as e:
        return "URLError: {}".format(e.reason)


def diag_auth():
    print("Basic header armado:", bool(_auth))
    if _pat_raw:
        print("PAT length:", len(_pat_raw))
        print("PAT contiene espacios/saltos de linea:",
              any(c.isspace() for c in _pat_raw))
        print("PAT solo alfanumerico+guiones/bajos:",
              all(c.isalnum() or c in "-_" for c in _pat_raw))
    url = "https://dev.azure.com/{}/_apis/projects?api-version=7.1".format(ORG)
    print("PRUEBA sin auth ->", _probe(url, False))
    print("PRUEBA con auth ->", _probe(url, True))


# ----------------------------------------------------------------- ADO API --

def wiql_since(since_iso):
    query = (
        "SELECT [System.Id] FROM WorkItems "
        "WHERE [System.TeamProject] = '{p}' "
        "AND [System.WorkItemType] IN ({t}) "
        "AND [System.ChangedDate] >= '{s}'"
    ).format(
        p=PROJECT.replace("'", "''"),
        t=", ".join("'{}'".format(t) for t in TYPES),
        s=since_iso,
    )
    res = ado("POST", WIQL_URL, {"query": query})
    return [w["id"] for w in res.get("workItems", [])]


def fetch_items(ids):
    items = []
    fields = OPT_FIELDS
    for i in range(0, len(ids), 100):
        chunk = ids[i:i + 100]
        url = "{}&ids={}&fields={}".format(WIT_URL, ",".join(str(x) for x in chunk), fields)
        try:
            res = ado("GET", url)
        except RuntimeError as e:
            if "ChangedBy" in str(e) or "BoardColumn" in str(e):
                url = "{}&ids={}&fields={}".format(WIT_URL, ",".join(str(x) for x in chunk), CORE_FIELDS)
                res = ado("GET", url)
            else:
                raise
        items.extend(res.get("value", []))
        time.sleep(0.2)
    return items


def fetch_latest_comment(wid):
    try:
        res = ado("GET", COMMENTS_URL.format(wid))
        comments = res.get("comments") or res.get("value") or []
        if not comments:
            return None
        # ordena por creado
        comments_sorted = sorted(comments, key=lambda c: c.get("createdDate") or "", reverse=True)
        c = comments_sorted[0]
        text = c.get("text") or c.get("body") or ""
        author = ""
        who = c.get("createdBy") or c.get("author") or {}
        if isinstance(who, dict):
            author = who.get("displayName") or who.get("uniqueName") or ""
        return {"id": c.get("id") or c.get("commentId"), "text": text, "author": author, "date": c.get("createdDate") or ""}
    except Exception as e:
        print("WARN fetch comment {}: {}".format(wid, e), file=sys.stderr)
        return None


def item_view(it):
    f = it.get("fields", {})
    return {
        "state": str(f.get("System.State", "") or ""),
        "column": str(f.get("System.BoardColumn", "") or ""),
        "title": str(f.get("System.Title", "") or "(sin titulo)"),
        "type": str(f.get("System.WorkItemType", "") or ""),
        "assignee": _text(f.get("System.AssignedTo")),
        "changed_by": _text(f.get("System.ChangedBy")),
        "changed_date": str(f.get("System.ChangedDate", "") or ""),
        "history": str(f.get("System.History", "") or ""),
        "comment_count": int(f.get("System.CommentCount") or 0),
        "start_date": str(f.get("Microsoft.VSTS.Scheduling.StartDate", "") or ""),
        "finish_date": str(f.get("Microsoft.VSTS.Scheduling.FinishDate", "") or ""),
        "due_date": str(f.get("Microsoft.VSTS.Scheduling.DueDate", "") or ""),
    }


def _excerpt(raw, limit=220):
    """HTML -> texto plano recortado para la tarjeta."""
    txt = re.sub(r"<[^>]+>", " ", raw or "")
    txt = html.unescape(txt)
    txt = re.sub(r"\s+", " ", txt).strip()
    if len(txt) > limit:
        txt = txt[:limit].rstrip() + "…"
    return txt


def _text(v):
    if v is None:
        return ""
    if isinstance(v, dict):
        return v.get("displayName") or v.get("uniqueName") or ""
    return str(v)


# ------------------------------------------------------------- snapshot --

def load_state():
    if not os.path.isfile(STATE_FILE):
        return None
    try:
        with open(STATE_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def save_state(state):
    tmp = STATE_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(state, f, ensure_ascii=False, indent=1)
    os.replace(tmp, STATE_FILE)


# ------------------------------------------------------------- tarjetas --

def _fmt_date(iso):
    if not iso:
        return ""
    try:
        dt = datetime.fromisoformat(iso.replace("Z", "+00:00")).astimezone()
        return dt.strftime("%d-%m-%Y %H:%M")
    except Exception:
        return iso


def _fmt_day(iso):
    if not iso:
        return ""
    try:
        dt = datetime.fromisoformat(iso.replace("Z", "+00:00"))
        return dt.strftime("%d-%m-%Y")
    except Exception:
        return iso


def make_card(kind, wid, view, prev=None):
    """kind: new | state | column | comment | dates"""
    titulo = "[#{}]({}) · {}".format(wid, WI_ITEMS_URL.format(wid), view["title"])
    if kind == "new":
        emoji, label = "\U0001f195", "Nueva {}".format(view["type"] or "work item")
    elif kind == "state":
        emoji, label = "\U0001f504", "Cambio de estado"
    elif kind == "comment":
        emoji, label = "\U0001f4ac", "Nuevo comentario"
    elif kind == "dates":
        emoji, label = "\U0001f4c5", "Cambio de fechas"
    else:
        emoji, label = "\U0001f4cb", "Cambio de columna"

    if kind == "comment":
        facts = [
            {"title": "Tipo", "value": view["type"] or "-"},
            {"title": "Comentario", "value": _excerpt(view.get("history", "")) or "(sin texto)"},
            {"title": "Por", "value": view["changed_by"] or "-"},
            {"title": "Cuando", "value": _fmt_date(view["changed_date"])},
        ]
    elif kind == "dates":
        facts = [{"title": "Tipo", "value": view["type"] or "-"}]
        if prev:
            for key, label_f in (("start_date", "Inicio"), ("finish_date", "T\u00e9rmino"), ("due_date", "Vencimiento")):
                if (prev.get(key) or "") != (view.get(key) or ""):
                    facts.append({"title": label_f, "value": "{} \u2192 {}".format(
                        _fmt_day(prev.get(key)) or "-", _fmt_day(view.get(key)) or "-")})
        facts.append({"title": "Responsable", "value": view["assignee"] or "(sin asignar)"})
        if view["changed_by"]:
            facts.append({"title": "Por", "value": view["changed_by"]})
        if view["changed_date"]:
            facts.append({"title": "Cuando", "value": _fmt_date(view["changed_date"])})
    else:
        facts = [{"title": "Tipo", "value": view["type"] or "-"}]

    if kind not in ("comment", "dates"):
        if kind == "state" and prev:
            facts.append({"title": "Estado", "value": "{} → {}".format(prev["state"] or "-", view["state"] or "-")})
        else:
            facts.append({"title": "Estado", "value": view["state"] or "-"})

        if kind == "column" and prev:
            facts.append({"title": "Columna", "value": "{} → {}".format(prev["column"] or "(sin columna)", view["column"] or "-")})
        elif view["column"] and kind == "new":
            facts.append({"title": "Columna", "value": view["column"]})

        if prev and prev["assignee"] != view["assignee"] and (kind == "state" or kind == "column"):
            facts.append({"title": "Responsable", "value": "{} → {}".format(prev["assignee"] or "(sin asignar)", view["assignee"] or "(sin asignar)")})
        else:
            facts.append({"title": "Responsable", "value": view["assignee"] or "(sin asignar)"})

        if view["changed_by"]:
            facts.append({"title": "Por", "value": view["changed_by"]})
        if view["changed_date"]:
            facts.append({"title": "Cuando", "value": _fmt_date(view["changed_date"])})

    return {
        "type": "AdaptiveCard",
        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
        "version": "1.4",
        "body": [
            {
                "type": "ColumnSet",
                "columns": [
                    {"type": "Column", "width": "auto", "items": [
                        {"type": "TextBlock", "text": emoji, "size": "ExtraLarge"}
                    ]},
                    {"type": "Column", "width": "stretch", "items": [
                        {"type": "TextBlock", "text": label, "weight": "Bolder", "size": "Medium", "color": "Accent"},
                        {"type": "TextBlock", "text": "**" + titulo + "**", "wrap": True},
                    ]},
                ],
            },
            {"type": "FactSet", "facts": facts},
        ],
    }


def test_card(msg):
    return {
        "type": "AdaptiveCard",
        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
        "version": "1.4",
        "body": [
            {"type": "TextBlock", "text": "\u2705", "size": "ExtraLarge"},
            {"type": "TextBlock", "text": msg, "weight": "Bolder", "size": "Medium", "color": "Good", "wrap": True},
        ],
    }


def post_cards(webhook, cards):
    for i, card in enumerate(cards):
        if i:
            time.sleep(0.3)
        _req("POST", webhook, card)


# ------------------------------------------------------------------ main --

def main():
    global _auth
    ap = argparse.ArgumentParser(description="Notifica cambios de ADO a un canal privado de Teams")
    ap.add_argument("--test", action="store_true", help="solo envia una tarjeta de prueba al webhook")
    ap.add_argument("--dry-run", action="store_true", help="muestra las tarjetas sin publicar")
    ap.add_argument("--diag-auth", action="store_true", help="diagnostica la autenticacion con ADO")
    args = ap.parse_args()

    if args.diag_auth:
        set_auth(get_pat())
        diag_auth()
        return

    webhook = get_webhook()

    if args.test:
        post_cards(webhook, [test_card("Notificaciones de Azure DevOps conectadas a este canal.")])
        print("OK: tarjeta de prueba enviada al webhook.")
        return

    set_auth(get_pat())
    state = load_state() or {"items": {}, "last_run": None}
    snapshot = state.get("items", {})

    now = datetime.now(timezone.utc)
    if state.get("last_run"):
        last = datetime.fromisoformat(state["last_run"])
        since = (last - timedelta(minutes=OVERLAP_MIN)).strftime("%Y-%m-%d")
    else:
        since = (now - timedelta(hours=LOOKBACK_HOURS_FIRST)).strftime("%Y-%m-%d")

    ids = wiql_since(since)
    items = fetch_items(ids)
    views = {str(it["id"]): item_view(it) for it in items}
    print("Work items cambiados desde {}: {}".format(since, len(views)))

    priming = not snapshot
    cards = []

    if not priming:
        for wid in sorted(views, key=lambda x: int(x)):
            view = views[wid]
            prev = snapshot.get(wid)
            if prev is None:
                cards.append(make_card("new", wid, view))
            elif prev["state"] != view["state"]:
                cards.append(make_card("state", wid, view, prev))
            elif view["column"] and prev["column"] != view["column"]:
                cards.append(make_card("column", wid, view, prev))
            elif "start_date" not in prev:
                pass  # primera corrida con fechas: solo siembra
            elif ((prev.get("start_date") or "") != (view["start_date"] or "")
                  or (prev.get("finish_date") or "") != (view["finish_date"] or "")
                  or (prev.get("due_date") or "") != (view["due_date"] or "")):
                cards.append(make_card("dates", wid, view, prev))
            elif "comment_count" not in prev:
                pass  # siembra
            elif int(prev.get("comment_count") or 0) < view["comment_count"]:
                lc = fetch_latest_comment(wid)
                if lc:
                    v2c = dict(view)
                    v2c["history"] = lc.get("text") or ""
                    v2c["changed_by"] = lc.get("author") or view["changed_by"]
                    v2c["changed_date"] = lc.get("date") or view["changed_date"]
                    cards.append(make_card("comment", wid, v2c, prev))
                else:
                    cards.append(make_card("comment", wid, view, prev))
                continue
            elif "history" not in prev:
                pass  # siembra
            elif (prev.get("history") or "") != view["history"] and view["history"].strip():
                cards.append(make_card("comment", wid, view, prev))

    if len(cards) > MAX_CARDS:
        print("AVISO: {} tarjetas, se publican solo las primeras {}.".format(len(cards), MAX_CARDS))
        cards = cards[:MAX_CARDS]

    if args.dry_run:
        for c in cards:
            print(json.dumps(c, ensure_ascii=False, indent=1))
        print("Dry-run: {} tarjeta(s) no publicadas.".format(len(cards)))
        return

    if priming:
        post_cards(webhook, [test_card(
            "Notificaciones de ADO listas. Monitoreando {} work items (User Story, Task, Bug) del proyecto '{}'.".format(
                len(views), PROJECT))])
        print("Prime: snapshot inicial con {} items.".format(len(views)))
    elif cards:
        post_cards(webhook, cards)
        print("Publicadas {} tarjeta(s).".format(len(cards)))
    else:
        print("Sin cambios relevantes.")

    snapshot.update(views)
    state = {"items": snapshot, "last_run": now.strftime("%Y-%m-%dT%H:%M:%S.000Z")}
    save_state(state)
    print("Snapshot guardado ({} items).".format(len(snapshot)))


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, URLError) as e:
        print("ERROR: {}".format(e), file=sys.stderr)
        raise SystemExit(1)
    except KeyboardInterrupt:
        raise SystemExit(130)
