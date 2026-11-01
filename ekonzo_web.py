#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
EKONZO WEB — gestion des ventes, stocks, dettes et bénéfices
Fonctionne sur ORDINATEUR et TÉLÉPHONE (dans le navigateur). Python 3 seul : rien à installer.

Lancer :        python ekonzo_web.py            (port 8000)
                python ekonzo_web.py 8080       (autre port)
                python ekonzo_web.py --local    (accessible seulement depuis cet appareil)
Patron oublié : python ekonzo_web.py --reset-patron

Ouvrir : http://localhost:8000 sur l'ordinateur,
         http://ADRESSE-IP-DU-PC:8000 sur le téléphone (même Wi-Fi), l'adresse s'affiche au démarrage.
La base ekonzo.db est la même que celle de la version Windows (ekonzo.py).
"""
import hashlib
import hmac
import json
import os
import re
import secrets
import socket
import sqlite3
import sys
import tempfile
import threading
import time
import traceback
from datetime import date, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlparse

DATA = os.environ.get("EKONZO_DATA") or os.path.dirname(os.path.abspath(__file__))   # Android : dossier privé de l'appli
os.makedirs(DATA, exist_ok=True)
DB = os.path.join(DATA, "ekonzo.db")
DEVISE = "FC"
ROLES = ("patron", "vendeur")
MODES = ("Cash", "Mobile Money", "Autre")
KEYS = {"Jour": "date", "Semaine": "strftime('%Y-S%W', date)",
        "Mois": "strftime('%Y-%m', date)", "Année": "strftime('%Y', date)"}
LOCK = threading.RLock()
SESSIONS, ECHECS = {}, {}


# ═════════════════════════ BASE DE DONNÉES ═════════════════════════
def init_db():
    c = sqlite3.connect(DB)
    c.executescript("""
    CREATE TABLE IF NOT EXISTS articles(
        id INTEGER PRIMARY KEY AUTOINCREMENT, nom TEXT UNIQUE NOT NULL,
        prix_achat REAL DEFAULT 0, prix_vente REAL DEFAULT 0,
        stock REAL DEFAULT 0, seuil REAL DEFAULT 5);
    CREATE TABLE IF NOT EXISTS ventes(
        id INTEGER PRIMARY KEY AUTOINCREMENT, date TEXT, article_id INTEGER,
        quantite REAL, prix_vente REAL, prix_achat REAL, client TEXT, paye REAL);
    CREATE TABLE IF NOT EXISTS paiements(
        id INTEGER PRIMARY KEY AUTOINCREMENT, vente_id INTEGER, date TEXT, montant REAL);
    CREATE TABLE IF NOT EXISTS approvisionnements(
        id INTEGER PRIMARY KEY AUTOINCREMENT, date TEXT, article_id INTEGER,
        quantite REAL, prix_achat REAL);
    CREATE TABLE IF NOT EXISTS depenses(
        id INTEGER PRIMARY KEY AUTOINCREMENT, date TEXT, libelle TEXT, montant REAL);
    CREATE TABLE IF NOT EXISTS params(cle TEXT PRIMARY KEY, valeur TEXT);
    CREATE TABLE IF NOT EXISTS utilisateurs(
        id INTEGER PRIMARY KEY AUTOINCREMENT, nom TEXT UNIQUE COLLATE NOCASE NOT NULL,
        role TEXT NOT NULL, sel TEXT NOT NULL, hash TEXT NOT NULL);
    """)
    cols = {r[1] for r in c.execute("PRAGMA table_info(ventes)")}
    for col, ddl in (("facture", "TEXT"), ("mode", "TEXT DEFAULT 'Cash'"), ("vendeur", "TEXT")):
        if col not in cols:
            c.execute(f"ALTER TABLE ventes ADD COLUMN {col} {ddl}")
    c.commit()
    c.close()


def q(sql, args=(), one=False):
    c = sqlite3.connect(DB, timeout=10)
    try:
        rows = c.execute(sql, args).fetchall()
    finally:
        c.close()
    if one:
        return rows[0] if rows else None
    return rows


def run(*ops):
    c = sqlite3.connect(DB, timeout=10)
    try:
        for sql, args in ops:
            c.execute(sql, args)
        c.commit()
    except Exception:
        c.rollback()
        raise
    finally:
        c.close()


def param(cle, defaut=""):
    r = q("SELECT valeur FROM params WHERE cle=?", (cle,), True)
    return r[0] if r else defaut


def set_param(cle, val):
    run(("INSERT OR REPLACE INTO params(cle,valeur) VALUES(?,?)", (cle, val)))


def copie_db(dest):
    src, dst = sqlite3.connect(DB), sqlite3.connect(dest)
    try:
        src.backup(dst)
    finally:
        src.close()
        dst.close()


def auto_backup():
    dossier = os.path.join(os.path.dirname(DB), "sauvegardes")
    os.makedirs(dossier, exist_ok=True)
    f = os.path.join(dossier, f"ekonzo_{date.today():%Y%m%d}.db")
    if not os.path.exists(f):
        copie_db(f)
    anciens = sorted(x for x in os.listdir(dossier) if x.startswith("ekonzo_") and x.endswith(".db"))
    for x in anciens[:-14]:
        os.remove(os.path.join(dossier, x))


# ═════════════════════════ COMPTES ═════════════════════════
ITER = 200_000


def pbkdf2(pw, sel, n=ITER):
    if hasattr(hashlib, "pbkdf2_hmac"):
        return hashlib.pbkdf2_hmac("sha256", pw, sel, n)
    k = (pw if len(pw) <= 64 else hashlib.sha256(pw).digest()).ljust(64, b"\0")   # secours sans OpenSSL
    ih = hashlib.sha256(bytes(c ^ 0x36 for c in k))
    oh = hashlib.sha256(bytes(c ^ 0x5C for c in k))

    def prf(m):
        a = ih.copy()
        a.update(m)
        b = oh.copy()
        b.update(a.digest())
        return b.digest()
    u = prf(sel + b"\x00\x00\x00\x01")
    t = int.from_bytes(u, "big")
    for _ in range(n - 1):
        u = prf(u)
        t ^= int.from_bytes(u, "big")
    return t.to_bytes(32, "big")


def hash_mdp(mdp, sel=None):
    sel = sel or os.urandom(16)
    return sel.hex(), pbkdf2(mdp.encode("utf-8"), sel).hex()


def verifier_mdp(nom, mdp):
    r = q("SELECT nom,role,sel,hash FROM utilisateurs WHERE nom=?", (nom.strip(),), True)
    if not r:
        hash_mdp(mdp)
        return None
    h = hash_mdp(mdp, bytes.fromhex(r[2]))[1]
    return (r[0], r[1]) if hmac.compare_digest(h, r[3]) else None


def creer_utilisateur(nom, mdp, role):
    nom = nom.strip()
    if not nom:
        raise ValueError("Le nom d'utilisateur est obligatoire")
    if len(mdp) < 4:
        raise ValueError("Le mot de passe doit avoir au moins 4 caractères")
    if role not in ROLES:
        raise ValueError("Rôle invalide")
    sel, h = hash_mdp(mdp)
    try:
        run(("INSERT INTO utilisateurs(nom,role,sel,hash) VALUES(?,?,?,?)", (nom, role, sel, h)))
    except sqlite3.IntegrityError:
        raise ValueError("Ce nom d'utilisateur existe déjà")


def changer_mdp(nom, mdp):
    if len(mdp) < 4:
        raise ValueError("Le mot de passe doit avoir au moins 4 caractères")
    sel, h = hash_mdp(mdp)
    run(("UPDATE utilisateurs SET sel=?, hash=? WHERE nom=?", (sel, h, nom)))


def supprimer_utilisateur(nom):
    r = q("SELECT role FROM utilisateurs WHERE nom=?", (nom,), True)
    if not r:
        return
    if r[0] == "patron" and q("SELECT COUNT(*) FROM utilisateurs WHERE role='patron'", one=True)[0] <= 1:
        raise ValueError("Il doit toujours rester au moins un patron")
    run(("DELETE FROM utilisateurs WHERE nom=?", (nom,)))


def nouvelle_session(nom, role):
    t = secrets.token_hex(24)
    SESSIONS[t] = {"nom": nom, "role": role, "exp": time.time() + 12 * 3600, "token": t}
    return {"token": t, "nom": nom, "role": role}


def session(token):
    s = SESSIONS.get(token)
    if s and s["exp"] > time.time():
        s["exp"] = time.time() + 12 * 3600
        return s
    SESSIONS.pop(token, None)
    return None


def revoquer(nom, sauf=None):
    for t in [t for t, s in SESSIONS.items() if s["nom"].lower() == nom.lower() and t != sauf]:
        SESSIONS.pop(t, None)


class Err(Exception):
    def __init__(self, msg, code=400):
        super().__init__(msg)
        self.code = code


def connexion(ip, nom, mdp):
    n, bloque = ECHECS.get(ip, (0, 0))
    if bloque > time.time():
        raise Err("Trop d'essais : réessayez dans une minute", 429)
    r = verifier_mdp(nom, mdp)
    if not r:
        n += 1
        ECHECS[ip] = (0, time.time() + 60) if n >= 5 else (n, 0)
        raise Err("Nom ou mot de passe incorrect", 401)
    ECHECS.pop(ip, None)
    return nouvelle_session(*r)


# ═════════════════════════ CALCULS ═════════════════════════
def fmt(n):
    n = n or 0
    s = f"{n:,.0f}" if abs(n - round(n)) < 0.005 else f"{n:,.2f}"
    return f"{s.replace(',', ' ')} {DEVISE}"


def qte(n):
    return f"{(n or 0):g}"


def num(s, nom="Valeur"):
    try:
        return float(str(s).replace(",", ".").replace(" ", ""))
    except ValueError:
        raise ValueError(f"{nom} invalide")


def nb(v, nom="Valeur"):
    return 0.0 if v is None or str(v).strip() == "" else num(v, nom)


def chk_date(s):
    s = str(s).strip()
    try:
        date.fromisoformat(s)
    except ValueError:
        raise ValueError("Date invalide (format AAAA-MM-JJ)")
    return s


def calcul_panier(lignes, remise=0.0, paye=None):
    sous = sum(l[2] * l[3] for l in lignes)
    remise = min(max(remise, 0.0), sous)
    net = sous - remise
    benef = net - sum(l[2] * l[4] for l in lignes)
    p = net if paye is None else paye
    return {"sous": sous, "remise": remise, "net": net, "benef": benef, "paye": p,
            "dette": max(net - p, 0.0), "rendu": max(p - net, 0.0)}


def enregistrer_vente(lignes, client, mode, remise, paye, d, vendeur=""):
    if not lignes:
        raise ValueError("Le panier est vide")
    t = calcul_panier(lignes, remise, paye)
    if t["dette"] > 0.005 and not client:
        raise ValueError("Indiquez le nom du client pour une vente à crédit")
    besoin = {}
    for aid, _, qt, _, _ in lignes:
        besoin[aid] = besoin.get(aid, 0) + qt
    for aid, qt in besoin.items():
        r = q("SELECT nom,stock FROM articles WHERE id=?", (aid,), True)
        if not r or qt > r[1] + 1e-9:
            raise ValueError(f"Stock insuffisant pour {r[0] if r else 'cet article'} "
                             f"(reste {qte(r[1]) if r else 0})")
    n = q("SELECT COUNT(DISTINCT facture) FROM ventes WHERE date=?", (d,), True)[0] + 1
    facture = f"F{d.replace('-', '')}-{n:03d}"
    ratio = t["net"] / t["sous"] if t["sous"] else 1.0
    pay_ratio = min(t["paye"], t["net"]) / t["net"] if t["net"] > 0 else 1.0
    ops = []
    for aid, _, qt, pu, pa in lignes:
        pv = pu * ratio
        ops.append(("INSERT INTO ventes(date,article_id,quantite,prix_vente,prix_achat,client,paye,facture,mode,vendeur) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?)",
                    (d, aid, qt, pv, pa, client, qt * pv * pay_ratio, facture, mode, vendeur)))
        ops.append(("UPDATE articles SET stock=stock-? WHERE id=?", (qt, aid)))
    run(*ops)
    return facture, t


def payer_client(client, montant, d):
    rows = q("""SELECT id, quantite*prix_vente-paye FROM ventes
                WHERE COALESCE(client,'')=? AND quantite*prix_vente-paye>0.005
                ORDER BY date,id""", (client,))
    reste, ops = montant, []
    for vid, du in rows:
        if reste <= 0.005:
            break
        m = min(du, reste)
        reste -= m
        ops += [("UPDATE ventes SET paye=paye+? WHERE id=?", (m, vid)),
                ("INSERT INTO paiements(vente_id,date,montant) VALUES(?,?,?)", (vid, d, m))]
    if ops:
        run(*ops)


def stats(debut, fin):
    r = q("""SELECT COALESCE(SUM(quantite*prix_vente),0),
                    COALESCE(SUM(quantite*(prix_vente-prix_achat)),0),
                    COALESCE(SUM(paye-COALESCE((SELECT SUM(montant) FROM paiements p
                                                WHERE p.vente_id=ventes.id),0)),0)
             FROM ventes WHERE date BETWEEN ? AND ?""", (debut, fin), True)
    later = q("SELECT COALESCE(SUM(montant),0) FROM paiements WHERE date BETWEEN ? AND ?",
              (debut, fin), True)[0]
    dep = q("SELECT COALESCE(SUM(montant),0) FROM depenses WHERE date BETWEEN ? AND ?",
            (debut, fin), True)[0]
    return r[0], r[1], r[2] + later, dep


def periodes_dashboard(t):
    sem = t - timedelta(days=t.weekday())
    mois = t.replace(day=1)
    an = t.replace(month=1, day=1)
    pm = (mois - timedelta(days=1)).replace(day=1)
    pm_fin = min(pm + (t - mois), mois - timedelta(days=1))

    def an_prec(d):
        try:
            return d.replace(year=d.year - 1)
        except ValueError:
            return d.replace(year=d.year - 1, day=28)
    return [("Aujourd'hui", t, t, t - timedelta(days=1), t - timedelta(days=1)),
            ("Cette semaine", sem, t, sem - timedelta(days=7), t - timedelta(days=7)),
            ("Ce mois", mois, t, pm, pm_fin),
            ("Cette année", an, t, an_prec(an), an_prec(t))]


def recu_texte(facture, d, client, mode, lignes, t):
    global DEVISE
    DEVISE = param("devise", "FC")
    L = 38
    out = [param("boutique", "EKONZO").center(L)]
    if param("tel"):
        out.append(("Tél : " + param("tel")).center(L))
    out += ["-" * L, f"Facture  : {facture}", f"Date     : {d}"]
    if client:
        out.append(f"Client   : {client}")
    out += [f"Paiement : {mode}", "-" * L]
    for _, nom, qt, pu, _ in lignes:
        out.append(nom[:L])
        out.append((f"  {qte(qt)} x {fmt(pu)}").ljust(L - 16) + fmt(qt * pu).rjust(16))
    out.append("-" * L)
    out.append("Sous-total".ljust(L - 16) + fmt(t["sous"]).rjust(16))
    if t["remise"] > 0:
        out.append("Remise".ljust(L - 16) + ("-" + fmt(t["remise"])).rjust(16))
    out.append("NET À PAYER".ljust(L - 16) + fmt(t["net"]).rjust(16))
    out.append("Payé".ljust(L - 16) + fmt(min(t["paye"], t["net"])).rjust(16))
    if t["rendu"] > 0.005:
        out.append("Rendu".ljust(L - 16) + fmt(t["rendu"]).rjust(16))
    if t["dette"] > 0.005:
        out.append("RESTE À PAYER".ljust(L - 16) + fmt(t["dette"]).rjust(16))
    out += ["-" * L, "Merci de votre confiance !".center(L)]
    return "\n".join(out)


def android_save(nom, data, mime="application/octet-stream"):
    """Enregistre un fichier dans Téléchargements/Ekonzo (Android). Retourne None hors Android."""
    try:
        from jnius import autoclass, jarray
    except Exception:
        return None
    try:
        act = autoclass("org.kivy.android.PythonActivity").mActivity
        if autoclass("android.os.Build$VERSION").SDK_INT >= 29:
            cv = autoclass("android.content.ContentValues")()
            cv.put("_display_name", nom)
            cv.put("mime_type", mime)
            cv.put("relative_path", "Download/Ekonzo")
            res = act.getContentResolver()
            uri = res.insert(autoclass("android.provider.MediaStore$Downloads").EXTERNAL_CONTENT_URI, cv)
            out = res.openOutputStream(uri)
            out.write(jarray("b")([b - 256 if b > 127 else b for b in data]))
            out.close()
            return "Téléchargements/Ekonzo/" + nom
        dossier = act.getExternalFilesDir(None).getAbsolutePath()
        with open(os.path.join(dossier, nom), "wb") as fh:
            fh.write(data)
        return os.path.join(dossier, nom)
    except Exception as e:
        raise ValueError(f"Enregistrement impossible : {e}")


def ips():
    r = set()
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("10.255.255.255", 1))
        r.add(s.getsockname()[0])
        s.close()
    except Exception:
        pass
    try:
        r.add(socket.gethostbyname(socket.gethostname()))
    except Exception:
        pass
    return sorted(x for x in r if not x.startswith("127."))


# ═════════════════════════ API ═════════════════════════
class Raw:
    def __init__(self, data, ctype, nom):
        self.data, self.ctype, self.nom = data, ctype, nom


def lire_article(b):
    nom = str(b.get("nom", "")).strip()
    if not nom:
        raise ValueError("Le nom de l'article est obligatoire")
    v = [nb(b.get(k), n) for k, n in (("pa", "Prix d'achat"), ("pv", "Prix de vente"),
                                      ("stock", "Stock"), ("seuil", "Seuil d'alerte"))]
    if any(x < 0 for x in v):
        raise ValueError("Les valeurs ne peuvent pas être négatives")
    return (nom, *v)


def dashboard():
    t = date.today()
    per = []
    for nom, d1, d2, p1, p2 in periodes_dashboard(t):
        ca, bb, enc, dep = stats(d1.isoformat(), d2.isoformat())
        per.append({"nom": nom, "ca": ca, "ca0": stats(p1.isoformat(), p2.isoformat())[0],
                    "bb": bb, "dep": dep, "enc": enc})
    j = stats(t.isoformat(), t.isoformat())
    dettes = q("SELECT COALESCE(SUM(quantite*prix_vente-paye),0) FROM ventes", one=True)[0]
    stock = q("SELECT COALESCE(SUM(stock*prix_achat),0) FROM articles", one=True)[0]
    low = q("SELECT nom,stock,seuil FROM articles WHERE stock<=seuil ORDER BY stock")
    top = q("""SELECT a.nom, SUM(v.quantite), SUM(v.quantite*v.prix_vente),
                      SUM(v.quantite*(v.prix_vente-v.prix_achat))
               FROM ventes v JOIN articles a ON a.id=v.article_id
               WHERE v.date>=? GROUP BY a.id ORDER BY 2 DESC LIMIT 7""", (t.replace(day=1).isoformat(),))
    return {"cards": {"ventes_jour": j[0], "benef_jour": j[1] - j[3], "dettes": dettes,
                      "stock": stock, "alertes": len(low)},
            "periodes": per, "top": top, "low": low}


def analyses(qs):
    k = KEYS.get(qs.get("per", "Jour"))
    if not k:
        raise ValueError("Période invalide")
    c, a = [], []
    for key, op in (("du", ">="), ("au", "<=")):
        if qs.get(key):
            c.append(f"date {op} ?")
            a.append(chk_date(qs[key]))
    cond = " AND ".join(c)
    w = f"WHERE {cond}" if cond else ""
    on = f"AND {cond}" if cond else ""
    ventes = {r[0]: r[1:] for r in q(f"""
        SELECT {k}, COUNT(*), SUM(quantite), SUM(quantite*prix_vente),
               SUM(quantite*(prix_vente-prix_achat)), SUM(paye)
        FROM ventes {w} GROUP BY 1""", a)}
    deps = dict(q(f"SELECT {k}, SUM(montant) FROM depenses {w} GROUP BY 1", a))
    out = []
    for p in sorted(set(ventes) | set(deps), reverse=True)[:60]:
        n, qt, ca, bb, pay = ventes.get(p, (0, 0, 0, 0, 0))
        out.append({"p": p, "n": n, "qt": qt, "ca": ca, "bb": bb, "dep": deps.get(p, 0), "pay": pay})
    arts = q(f"""SELECT a.nom, COALESCE(SUM(v.quantite),0), a.stock,
                        COALESCE(SUM(v.quantite*v.prix_vente),0),
                        COALESCE(SUM(v.quantite*(v.prix_vente-v.prix_achat)),0)
                 FROM articles a LEFT JOIN ventes v ON v.article_id=a.id {on}
                 GROUP BY a.id ORDER BY 2 DESC""", a)
    return {"periodes": out, "articles": [{"nom": r[0], "vendus": r[1], "stock": r[2], "ca": r[3], "b": r[4]}
                                          for r in arts]}


def api(meth, p, qs, b, u, ip):
    P = [unquote(x) for x in p.strip("/").split("/")]
    k = P[1] if len(P) > 1 else ""
    m = (meth, k)
    # ---- public
    if m == ("GET", "etat"):
        return {"premier": q("SELECT COUNT(*) FROM utilisateurs", one=True)[0] == 0,
                "boutique": param("boutique", "EKONZO")}
    if m == ("POST", "setup"):
        with LOCK:
            if q("SELECT COUNT(*) FROM utilisateurs", one=True)[0]:
                raise Err("Le compte patron existe déjà", 403)
            creer_utilisateur(str(b.get("nom", "")), str(b.get("mdp", "")), "patron")
        return nouvelle_session(str(b["nom"]).strip(), "patron")
    if m == ("POST", "login"):
        return connexion(ip, str(b.get("nom", "")), str(b.get("mdp", "")))
    if not u:
        raise Err("Connexion requise", 401)
    pat = u["role"] == "patron"

    def reserve():
        if not pat:
            raise Err("Action réservée au patron", 403)

    # ---- compte
    if m == ("GET", "moi"):
        return {"nom": u["nom"], "role": u["role"], "devise": param("devise", "FC"),
                "boutique": param("boutique", "EKONZO"), "tel": param("tel"),
                "adresses": ips() if pat else []}
    if m == ("POST", "logout"):
        SESSIONS.pop(u["token"], None)
        return {"ok": True}
    if m == ("POST", "mdp"):
        if not verifier_mdp(u["nom"], str(b.get("ancien", ""))):
            raise Err("Mot de passe actuel incorrect")
        changer_mdp(u["nom"], str(b.get("nouveau", "")))
        revoquer(u["nom"], u["token"])
        return {"ok": True}

    # ---- articles
    if k == "articles":
        if meth == "GET":
            rows = q("""SELECT a.id,a.nom,a.prix_achat,a.prix_vente,a.stock,a.seuil,
                               COALESCE((SELECT SUM(quantite) FROM ventes WHERE article_id=a.id),0)
                        FROM articles a ORDER BY a.nom""")
            if pat:
                return [{"id": r[0], "nom": r[1], "pa": r[2], "pv": r[3], "stock": r[4],
                         "seuil": r[5], "vendus": r[6]} for r in rows]
            return [{"id": r[0], "nom": r[1], "pv": r[3], "stock": r[4], "seuil": r[5]} for r in rows]
        reserve()
        with LOCK:
            if meth == "POST":
                d = lire_article(b)
                if q("SELECT 1 FROM articles WHERE lower(nom)=lower(?)", (d[0],), True):
                    raise ValueError("Cet article existe déjà")
                try:
                    run(("INSERT INTO articles(nom,prix_achat,prix_vente,stock,seuil) VALUES(?,?,?,?,?)", d))
                except sqlite3.IntegrityError:
                    raise ValueError("Cet article existe déjà")
                return {"ok": True}
            i = int(P[2])
            if meth == "PUT":
                d = lire_article(b)
                if q("SELECT 1 FROM articles WHERE lower(nom)=lower(?) AND id<>?", (d[0], i), True):
                    raise ValueError("Un autre article porte déjà ce nom")
                try:
                    run(("UPDATE articles SET nom=?,prix_achat=?,prix_vente=?,stock=?,seuil=? WHERE id=?",
                         d + (i,)))
                except sqlite3.IntegrityError:
                    raise ValueError("Un autre article porte déjà ce nom")
                return {"ok": True}
            if meth == "DELETE":
                if q("SELECT COUNT(*) FROM ventes WHERE article_id=?", (i,), True)[0]:
                    raise ValueError("Cet article a déjà des ventes : suppression impossible. "
                                     "Mettez plutôt son stock à 0.")
                run(("DELETE FROM articles WHERE id=?", (i,)),
                    ("DELETE FROM approvisionnements WHERE article_id=?", (i,)))
                return {"ok": True}

    # ---- ventes
    if k == "ventes":
        if meth == "GET":
            rows = q("""SELECT v.id,COALESCE(v.facture,''),v.date,a.nom,v.quantite,v.prix_vente,
                               v.quantite*v.prix_vente,v.paye,v.quantite*v.prix_vente-v.paye,
                               COALESCE(v.client,''),COALESCE(v.mode,'Cash'),COALESCE(v.vendeur,'')
                        FROM ventes v JOIN articles a ON a.id=v.article_id
                        ORDER BY v.date DESC, v.id DESC LIMIT 500""")
            t = qs.get("q", "").strip().lower()
            return [r for r in rows if not t or t in " ".join(str(x) for x in r).lower()]
        if meth == "POST" and len(P) > 2 and P[2] == "annuler":
            reserve()
            with LOCK:
                i = int(b["id"])
                f = q("SELECT facture FROM ventes WHERE id=?", (i,), True)
                if not f:
                    raise ValueError("Vente introuvable")
                lignes = (q("SELECT id,article_id,quantite FROM ventes WHERE facture=?", (f[0],)) if f[0]
                          else q("SELECT id,article_id,quantite FROM ventes WHERE id=?", (i,)))
                ops = []
                for vid, aid, qt in lignes:
                    ops += [("DELETE FROM ventes WHERE id=?", (vid,)),
                            ("DELETE FROM paiements WHERE vente_id=?", (vid,)),
                            ("UPDATE articles SET stock=stock+? WHERE id=?", (qt, aid))]
                run(*ops)
            return {"ok": True}
        if meth == "POST":
            lignes = []
            for l in b.get("lignes", []):
                r = q("SELECT id,nom,prix_achat,prix_vente FROM articles WHERE id=?", (int(l["aid"]),), True)
                if not r:
                    raise ValueError("Article introuvable")
                qt = nb(l.get("qte"), "Quantité")
                if qt <= 0:
                    raise ValueError("Quantité invalide")
                pu = nb(l.get("pu"), "Prix") if pat else r[3]     # le vendeur ne peut pas changer le prix
                if pu < 0 or (not pat and pu <= 0):
                    raise ValueError(f"Prix de vente non défini pour {r[1]} : demandez au patron")
                lignes.append((r[0], r[1], qt, pu, r[2]))
            remise = nb(b.get("remise"), "Remise") if pat else 0.0
            paye = None if b.get("paye") in (None, "") else nb(b.get("paye"), "Montant payé")
            if paye is not None and paye < 0:
                raise ValueError("Le montant payé ne peut pas être négatif")
            d = chk_date(b.get("date") or date.today().isoformat()) if pat else date.today().isoformat()
            mode = b.get("mode") if b.get("mode") in MODES else "Cash"
            client = str(b.get("client", "")).strip()
            with LOCK:
                facture, t = enregistrer_vente(lignes, client, mode, remise, paye, d, u["nom"])
            return {"facture": facture, "recu": recu_texte(facture, d, client, mode, lignes, t)}

    # ---- dettes
    if k == "dettes":
        if meth == "GET":
            cl = q("""SELECT COALESCE(client,''), COUNT(*), SUM(quantite*prix_vente-paye) s FROM ventes
                      WHERE quantite*prix_vente-paye>0.005 GROUP BY COALESCE(client,'') ORDER BY s DESC""")
            det = {}
            for r in q("""SELECT COALESCE(v.client,''),v.id,v.date,COALESCE(v.facture,''),a.nom,
                                 v.quantite*v.prix_vente,v.paye,v.quantite*v.prix_vente-v.paye
                          FROM ventes v JOIN articles a ON a.id=v.article_id
                          WHERE v.quantite*v.prix_vente-v.paye>0.005 ORDER BY v.date,v.id"""):
                det.setdefault(r[0], []).append(r[1:])
            return {"total": sum(r[2] for r in cl),
                    "clients": [{"client": r[0], "n": r[1], "dette": r[2], "lignes": det.get(r[0], [])}
                                for r in cl]}
        if meth == "POST":
            c = str(b.get("client", ""))
            with LOCK:
                du = q("SELECT COALESCE(SUM(quantite*prix_vente-paye),0) FROM ventes WHERE COALESCE(client,'')=?",
                       (c,), True)[0]
                mt = nb(b.get("montant"), "Montant")
                if mt <= 0 or mt > du + 0.005:
                    raise ValueError("Montant invalide (il dépasse la dette ou est nul)")
                payer_client(c, min(mt, du), date.today().isoformat())
            return {"ok": True}

    if m == ("POST", "enregistrer"):
        nom = re.sub(r"[^\w.\- ]", "_", os.path.basename(str(b.get("nom", "export.txt")))) or "export.txt"
        ch = android_save(nom, ("\ufeff" + str(b.get("texte", ""))).encode("utf-8"), "text/plain")
        if ch is None:
            raise Err("Enregistrement direct disponible uniquement dans l'application Android")
        return {"chemin": ch}

    # ---- patron seulement
    reserve()
    if k == "dashboard":
        return dashboard()
    if k == "analyses":
        return analyses(qs)
    if k == "achats":
        if meth == "GET":
            return q("""SELECT s.date,a.nom,s.quantite,s.prix_achat,s.quantite*s.prix_achat
                        FROM approvisionnements s JOIN articles a ON a.id=s.article_id
                        ORDER BY s.date DESC, s.id DESC LIMIT 500""")
        if meth == "POST":
            with LOCK:
                r = q("SELECT id,prix_achat FROM articles WHERE id=?", (int(b["aid"]),), True)
                if not r:
                    raise ValueError("Article introuvable")
                qt = num(b.get("qte"), "Quantité")
                if qt <= 0:
                    raise ValueError("Quantité invalide")
                pa = r[1] if b.get("pa") in (None, "") else nb(b.get("pa"), "Prix d'achat")
                d = chk_date(b.get("date") or date.today().isoformat())
                run(("INSERT INTO approvisionnements(date,article_id,quantite,prix_achat) VALUES(?,?,?,?)",
                     (d, r[0], qt, pa)),
                    ("UPDATE articles SET stock=stock+?, prix_achat=? WHERE id=?", (qt, pa, r[0])))
            return {"ok": True}
    if k == "depenses":
        if meth == "GET":
            return {"rows": q("SELECT id,date,libelle,montant FROM depenses ORDER BY date DESC, id DESC LIMIT 500"),
                    "total": q("SELECT COALESCE(SUM(montant),0) FROM depenses", one=True)[0],
                    "mois": q("SELECT COALESCE(SUM(montant),0) FROM depenses WHERE date>=?",
                              (date.today().replace(day=1).isoformat(),), True)[0]}
        if meth == "POST":
            lib = str(b.get("libelle", "")).strip()
            if not lib:
                raise ValueError("Le libellé est obligatoire")
            run(("INSERT INTO depenses(date,libelle,montant) VALUES(?,?,?)",
                 (chk_date(b.get("date") or date.today().isoformat()), lib, num(b.get("montant"), "Montant"))))
            return {"ok": True}
        if meth == "DELETE":
            run(("DELETE FROM depenses WHERE id=?", (int(P[2]),)))
            return {"ok": True}
    if k == "users":
        if meth == "GET":
            return q("SELECT nom,role FROM utilisateurs ORDER BY role, nom")
        if meth == "POST":
            creer_utilisateur(str(b.get("nom", "")), str(b.get("mdp", "")), str(b.get("role", "")))
            return {"ok": True}
        nom = P[2]
        if meth == "PUT":
            changer_mdp(nom, str(b.get("mdp", "")))
            revoquer(nom)
            return {"ok": True}
        if meth == "DELETE":
            if nom.lower() == u["nom"].lower():
                raise ValueError("Vous ne pouvez pas supprimer votre propre compte")
            supprimer_utilisateur(nom)
            revoquer(nom)
            return {"ok": True}
    if m == ("POST", "params"):
        if str(b.get("devise", "")).strip():
            set_param("devise", str(b["devise"]).strip())
        if str(b.get("boutique", "")).strip():
            set_param("boutique", str(b["boutique"]).strip())
        set_param("tel", str(b.get("tel", "")).strip())
        return {"ok": True}
    if m == ("GET", "sauvegarde"):
        tmp = os.path.join(tempfile.mkdtemp(), "b.db")
        copie_db(tmp)
        with open(tmp, "rb") as fh:
            data = fh.read()
        return Raw(data, "application/octet-stream", f"ekonzo_{date.today():%Y%m%d}.db")
    if m == ("POST", "sauvegarde"):
        tmp = os.path.join(tempfile.mkdtemp(), "b.db")
        copie_db(tmp)
        with open(tmp, "rb") as fh:
            ch = android_save(f"ekonzo_{date.today():%Y%m%d_%H%M}.db", fh.read())
        if ch is None:
            raise Err("Disponible uniquement dans l'application Android")
        return {"chemin": ch}
    raise Err("Introuvable", 404)


# ═════════════════════════ SERVEUR HTTP ═════════════════════════
MANIFEST = {"name": "Ekonzo", "short_name": "Ekonzo", "start_url": "/", "display": "standalone",
            "background_color": "#1e3a8a", "theme_color": "#1e3a8a",
            "icons": [{"src": "/icon.svg", "sizes": "any", "type": "image/svg+xml", "purpose": "any"}]}
ICON = ('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><rect width="100" height="100" rx="22" '
        'fill="#1e3a8a"/><text x="50" y="68" font-size="58" font-family="Arial" font-weight="bold" '
        'text-anchor="middle" fill="#fff">E</text></svg>')


class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="application/json; charset=utf-8", extra=()):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for k, v in extra:
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, code, obj):
        self._send(code, json.dumps(obj, ensure_ascii=False).encode("utf-8"))

    def _go(self, meth):
        try:
            url = urlparse(self.path)
            p = url.path
            n = int(self.headers.get("Content-Length") or 0)
            if n > 2_000_000:
                raise Err("Requête trop grande", 413)
            raw = self.rfile.read(n) if n else b""
            if meth == "GET" and p == "/":
                return self._send(200, PAGE.encode("utf-8"), "text/html; charset=utf-8")
            if meth == "GET" and p == "/manifest.json":
                return self._send(200, json.dumps(MANIFEST).encode(), "application/manifest+json")
            if meth == "GET" and p == "/icon.svg":
                return self._send(200, ICON.encode(), "image/svg+xml")
            if not p.startswith("/api/"):
                return self._json(404, {"erreur": "Introuvable"})
            b = json.loads(raw) if raw else {}
            qs = {k: v[0] for k, v in parse_qs(url.query).items()}
            r = api(meth, p, qs, b, session(self.headers.get("X-Token", "")), self.client_address[0])
            if isinstance(r, Raw):
                return self._send(200, r.data, r.ctype, [("Content-Disposition", f'attachment; filename="{r.nom}"')])
            self._json(200, r)
        except Err as e:
            self._json(e.code, {"erreur": str(e)})
        except KeyError:
            self._json(400, {"erreur": "Données incomplètes"})
        except (ValueError, TypeError, sqlite3.IntegrityError, json.JSONDecodeError) as e:
            self._json(400, {"erreur": str(e) or "Données invalides"})
        except Exception:
            traceback.print_exc()
            self._json(500, {"erreur": "Erreur interne du serveur"})

    def do_GET(self):
        self._go("GET")

    def do_POST(self):
        self._go("POST")

    def do_PUT(self):
        self._go("PUT")

    def do_DELETE(self):
        self._go("DELETE")


def serveur(port=0, local=True):
    """Utilisé par l'application Android (main.py) : serveur local sur un port libre."""
    init_db()
    auto_backup()
    srv = ThreadingHTTPServer(("127.0.0.1" if local else "0.0.0.0", port), H)
    srv.daemon_threads = True
    return srv


def reset_patron():
    import getpass
    init_db()
    nom = input("Nom du patron (existant ou nouveau) : ").strip()
    mdp = getpass.getpass("Nouveau mot de passe : ")
    if mdp != getpass.getpass("Confirmez : "):
        return print("Les mots de passe ne correspondent pas.")
    try:
        if q("SELECT 1 FROM utilisateurs WHERE nom=?", (nom,), True):
            changer_mdp(nom, mdp)
            run(("UPDATE utilisateurs SET role='patron' WHERE nom=?", (nom,)))
        else:
            creer_utilisateur(nom, mdp, "patron")
        print("Compte patron mis à jour. Vous pouvez relancer Ekonzo.")
    except ValueError as e:
        print(e)


def main():
    if "--reset-patron" in sys.argv:
        return reset_patron()
    port = next((int(a) for a in sys.argv[1:] if a.isdigit()), 8000)
    local = "--local" in sys.argv
    init_db()
    auto_backup()
    try:
        srv = ThreadingHTTPServer(("127.0.0.1" if local else "0.0.0.0", port), H)
    except OSError as e:
        return print(f"Impossible de démarrer sur le port {port} ({e}). Essayez : python ekonzo_web.py 8080")
    srv.daemon_threads = True
    print("\n  EKONZO WEB est démarré ✔\n")
    print(f"  Sur cet appareil          : http://localhost:{port}")
    if not local:
        for ip in ips():
            print(f"  Sur le téléphone (Wi-Fi)  : http://{ip}:{port}")
    print("\n  Laissez cette fenêtre ouverte. Ctrl+C pour arrêter.\n")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("Arrêt d'Ekonzo.")


PAGE = r"""<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="theme-color" content="#1e3a8a">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="mobile-web-app-capable" content="yes">
<link rel="manifest" href="/manifest.json">
<link rel="icon" href="/icon.svg">
<title>EKONZO</title>
<style>
:root{--b:#1e3a8a;--a:#2563eb;--g:#16a34a;--r:#b91c1c;--o:#c2410c;--bg:#f1f5f9;--m:#64748b}
*{box-sizing:border-box}
body{margin:0;font:15px/1.4 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;background:var(--bg);color:#0f172a;padding-bottom:78px}
header{background:var(--b);color:#fff;padding:10px 14px;display:flex;align-items:center;gap:10px;position:sticky;top:0;z-index:5}
header b{font-size:20px;letter-spacing:1px}header span{margin-left:auto;font-size:13px;color:#fde68a}
nav{position:fixed;bottom:0;left:0;right:0;background:#fff;border-top:1px solid #cbd5e1;display:flex;overflow-x:auto;z-index:6;padding-bottom:env(safe-area-inset-bottom)}
nav button{flex:1;min-width:62px;border:0;background:none;padding:6px 4px;font-size:11px;color:var(--m);cursor:pointer}
nav button i{display:block;font-style:normal;font-size:20px}nav button.on{color:var(--a);font-weight:700}
main{max-width:1100px;margin:0 auto;padding:10px}
.card{background:#fff;border-radius:12px;padding:12px;margin-bottom:10px;box-shadow:0 1px 3px #0001}
h2,h3{margin:0 0 8px}h3{font-size:15px}
input,select{width:100%;padding:10px;border:1px solid #cbd5e1;border-radius:8px;font-size:16px;background:#fff;color:#0f172a}
input[readonly]{background:#f1f5f9}
label{display:block;font-size:12px;color:var(--m);margin:6px 0 0}
.row{display:flex;gap:8px}.row>*{flex:1}
.btn{background:var(--a);color:#fff;border:0;border-radius:8px;padding:11px 14px;font-size:15px;font-weight:600;margin-top:8px;cursor:pointer}
.btn.sec{background:#e2e8f0;color:#0f172a}.btn.red{background:var(--r)}.btn.big{width:100%;padding:14px;font-size:17px;background:var(--g)}
.btn:disabled{opacity:.5}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:8px}
.kpi{background:#fff;border-radius:12px;padding:10px;box-shadow:0 1px 3px #0001}.kpi small{color:var(--m)}
.kpi b{display:block;font-size:19px;color:var(--a)}
.tw{overflow-x:auto}table{border-collapse:collapse;width:100%;font-size:13px}
th,td{padding:6px 8px;border-bottom:1px solid #e2e8f0;text-align:left;white-space:nowrap}
th{background:#f8fafc;font-size:12px;color:var(--m)}tr[data-id]{cursor:pointer}tr[data-id]:hover{background:#eff6ff}
.neg{color:var(--r)}.warn{color:var(--o)}.ok{color:var(--g)}.muted{color:var(--m);font-size:13px}
.tot{display:flex;justify-content:space-between;padding:3px 0}.tot.net{font-size:20px;font-weight:700;color:var(--a)}
.modal{position:fixed;inset:0;background:#0008;display:flex;align-items:center;justify-content:center;z-index:20;padding:12px}
.mbox{background:#fff;border-radius:14px;padding:16px;width:100%;max-width:420px;max-height:90vh;overflow:auto}
#toast{position:fixed;left:50%;bottom:90px;transform:translateX(-50%);background:#111;color:#fff;padding:10px 16px;border-radius:20px;z-index:30;display:none;max-width:90%;text-align:center}
pre{font:13px/1.35 ui-monospace,Consolas,monospace;white-space:pre;overflow-x:auto;background:#f8fafc;padding:10px;border-radius:8px}
@media(min-width:900px){
 nav{position:sticky;top:46px;bottom:auto;border:0;border-bottom:1px solid #cbd5e1;justify-content:center}
 body{padding-bottom:0}nav button{flex:none;padding:10px 16px;font-size:13px}nav button i{display:inline;margin-right:6px;font-size:15px}
}
.appo{display:none}.app .appo{display:block}.app .noapp{display:none}
@media print{body *{visibility:hidden}#recu,#recu *{visibility:visible}#recu{position:absolute;left:0;top:0}}
</style>
</head>
<body>
<div id="app"></div>
<div id="toast"></div>
<script>
const $=s=>document.querySelector(s);
const esc=s=>String(s??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const n2=x=>{x=parseFloat(String(x).replace(",","."));return isNaN(x)?0:x};
const S={token:localStorage.getItem("ek_t")||"",user:null,dev:"FC",boutique:"EKONZO",panier:[],page:"",timer:0};
const fmt=x=>n2(x).toLocaleString("fr-FR",{maximumFractionDigits:2}).replace(/[\u202f\u00a0]/g," ")+" "+S.dev;
const qte=x=>String(parseFloat(n2(x).toFixed(3)));
const pct=(a,b)=>b?Math.round(a/b*100)+" %":"—";
const evol=(a,b)=>b?(a>=b?"+":"")+Math.round((a-b)/b*100)+" %":"—";
const today=()=>{const d=new Date();return new Date(d-d.getTimezoneOffset()*6e4).toISOString().slice(0,10)};
const R=(a,o)=>Object.assign(a,o);
const PAGES={};
const APP=/EkonzoApp/.test(navigator.userAgent);
document.documentElement.classList.toggle("app",APP);
let tt;
function toast(m){const t=$("#toast");t.textContent=m;t.style.display="block";clearTimeout(tt);tt=setTimeout(()=>t.style.display="none",3500)}
const act=async f=>{try{return await f()}catch(e){toast(e.message)}};

async function api(m,p,b){
  const r=await fetch(p,{method:m,headers:{"Content-Type":"application/json","X-Token":S.token},body:b?JSON.stringify(b):undefined});
  if(r.status===401&&!p.startsWith("/api/login")&&!p.startsWith("/api/setup")){S.token="";localStorage.removeItem("ek_t");setTimeout(boot,0);throw new Error("Session expirée : reconnectez-vous")}
  const d=(r.headers.get("content-type")||"").includes("json")?await r.json():await r.blob();
  if(!r.ok)throw new Error(d.erreur||"Erreur");
  return d;
}
const tbl=(h,rows)=>rows.length?`<div class="tw"><table><tr>${h.map(x=>`<th>${esc(x)}</th>`).join("")}</tr>${rows.map(r=>`<tr${r.id!==undefined?` data-id="${esc(r.id)}"`:""}${r.c?` class="${r.c}"`:""}>${r.map(c=>`<td>${c&&typeof c==="object"?c.h:esc(c)}</td>`).join("")}</tr>`).join("")}</table></div>`:'<div class="muted">Aucune donnée</div>';
function csv(head,rows,name){const l=[head,...rows].map(r=>r.map(c=>'"'+String(c??"").replace(/"/g,'""')+'"').join(";")).join("\r\n");if(APP)return act(async()=>{const r=await api("POST","/api/enregistrer",{nom:name,texte:l});toast("Enregistré : "+r.chemin)});const a=document.createElement("a");a.href=URL.createObjectURL(new Blob(["\ufeff"+l],{type:"text/csv;charset=utf-8"}));a.download=name;a.click()}
function copier(t){const x=document.createElement("textarea");x.value=t;document.body.appendChild(x);x.select();try{document.execCommand("copy");toast("Copié ✔")}catch(e){toast("Copie impossible")}x.remove()}
function askForm(title,fields,ok="OK"){return new Promise(res=>{
  const m=document.createElement("div");m.className="modal";
  m.innerHTML=`<form class="mbox"><h3>${esc(title)}</h3>${fields.map(f=>`<label>${esc(f.l)}${f.o?`<select name="${f.n}">${f.o.map(o=>`<option ${o===f.v?"selected":""}>${esc(o)}</option>`).join("")}</select>`:`<input name="${f.n}" type="${f.t||"text"}" value="${esc(f.v??"")}" ${f.t==="number"?'step="any" inputmode="decimal"':""} autocomplete="off">`}</label>`).join("")}<div class="row"><button type="button" class="btn sec" data-x>Annuler</button><button class="btn">${esc(ok)}</button></div></form>`;
  document.body.appendChild(m);const f=m.querySelector("form");f.querySelector("input,select")?.focus();
  f.querySelector("[data-x]").onclick=()=>{m.remove();res(null)};
  f.onsubmit=e=>{e.preventDefault();const o=Object.fromEntries(new FormData(f));m.remove();res(o)};
})}
const sure=m=>askForm(m,[],"Oui").then(f=>!!f);
function suggest(inp){
  const box=document.createElement("div");box.style.cssText="border:1px solid #cbd5e1;border-radius:8px;background:#fff;max-height:220px;overflow:auto;display:none;margin-top:2px";
  inp.insertAdjacentElement("afterend",box);let skip=false;
  const show=()=>{if(skip){box.style.display="none";return}const t=inp.value.trim().toLowerCase(),m=S.arts.filter(a=>a.nom.toLowerCase().includes(t)).slice(0,30);
    box.innerHTML=m.map(a=>`<div data-n="${esc(a.nom)}" style="padding:10px;border-bottom:1px solid #eef2f7;cursor:pointer">${esc(a.nom)} <span class="muted">· reste ${qte(a.stock)}</span></div>`).join("");
    box.style.display=m.length&&document.activeElement===inp&&!(m.length===1&&m[0].nom.toLowerCase()===t)?"block":"none"};
  inp.addEventListener("input",show);inp.addEventListener("focus",show);inp.addEventListener("blur",()=>setTimeout(()=>box.style.display="none",200));
  box.addEventListener("mousedown",e=>e.preventDefault());
  box.onclick=e=>{const d=e.target.closest("[data-n]");if(!d)return;inp.value=d.dataset.n;box.style.display="none";skip=true;inp.dispatchEvent(new Event("input"));skip=false};
}
function showRecu(t){const m=document.createElement("div");m.className="modal";
  m.innerHTML=`<div class="mbox"><h3>Reçu de vente</h3><pre id="recu">${esc(t)}</pre><div class="row"><button class="btn sec" data-c>Copier</button>${APP?'<button class="btn sec" data-e>Enregistrer</button>':(navigator.share?'<button class="btn sec" data-s>Partager</button>':"")+'<button class="btn sec" data-p>Imprimer</button>'}</div><button class="btn big" data-x>Fermer</button></div>`;
  document.body.appendChild(m);
  m.querySelector("[data-x]").onclick=()=>m.remove();m.querySelector("[data-c]").onclick=()=>copier(t);const pp=m.querySelector("[data-p]");if(pp)pp.onclick=()=>window.print();const en=m.querySelector("[data-e]");if(en)en.onclick=()=>act(async()=>{const r=await api("POST","/api/enregistrer",{nom:"recu_"+today()+".txt",texte:t});toast("Enregistré : "+r.chemin)});
  const s=m.querySelector("[data-s]");if(s)s.onclick=()=>navigator.share({text:t}).catch(()=>{});
}

/* ───────── connexion ───────── */
async function boot(){
  let e;try{e=await api("GET","/api/etat")}catch(x){$("#app").innerHTML='<div class="card" style="margin:30px 12px">Serveur Ekonzo injoignable. Vérifiez qu\'il est lancé.</div>';return}
  S.boutique=e.boutique;
  if(S.token){try{S.user=await api("GET","/api/moi");S.dev=S.user.devise;S.boutique=S.user.boutique;return start()}catch(_){if(!S.token)return}}
  loginUI(e.premier);
}
function loginUI(premier){
  $("#app").innerHTML=`<form class="card" id="lf" style="max-width:380px;margin:40px auto"><h2 style="color:var(--b)">${esc(S.boutique)}</h2><p class="muted">${premier?"Première utilisation : créez le compte PATRON":"Connectez-vous pour continuer"}</p><label>Nom d'utilisateur<input id="ln" autocapitalize="none" autocomplete="username"></label><label>Mot de passe<input id="lp" type="password" autocomplete="current-password"></label>${premier?'<label>Confirmer le mot de passe<input id="lc" type="password"></label>':""}<button class="btn big" style="background:var(--a)">${premier?"Créer le compte":"Se connecter"}</button></form>`;
  $("#ln").focus();
  $("#lf").onsubmit=e=>{e.preventDefault();act(async()=>{
    if(premier&&$("#lp").value!==$("#lc").value)throw new Error("Les deux mots de passe ne correspondent pas");
    const r=await api("POST",premier?"/api/setup":"/api/login",{nom:$("#ln").value,mdp:$("#lp").value});
    S.token=r.token;localStorage.setItem("ek_t",r.token);boot()})};
}
const NAV={patron:[["accueil","🏠","Accueil"],["ventes","🛒","Ventes"],["articles","📦","Articles"],["dettes","💳","Dettes"],["stock","📥","Stock"],["depenses","💸","Dépenses"],["analyses","📊","Analyses"],["plus","⚙️","Plus"]],
 vendeur:[["ventes","🛒","Ventes"],["articles","📦","Articles"],["dettes","💳","Dettes"],["plus","⚙️","Plus"]]};
function start(){
  $("#app").innerHTML=`<header><b id="hb">${esc(S.boutique)}</b><span>👤 ${esc(S.user.nom)} (${S.user.role})</span></header><nav>${NAV[S.user.role].map(n=>`<button data-p="${n[0]}"><i>${n[1]}</i>${n[2]}</button>`).join("")}</nav><main id="main"></main>`;
  document.querySelector("nav").onclick=e=>{const b=e.target.closest("button");if(b)go(b.dataset.p)};
  go(NAV[S.user.role][0][0]);
}
async function go(p){
  clearInterval(S.timer);S.page=p;
  document.querySelectorAll("nav button").forEach(b=>b.classList.toggle("on",b.dataset.p===p));
  $("#main").innerHTML='<div class="muted">Chargement…</div>';
  try{await PAGES[p]()}catch(e){toast(e.message)}
  window.scrollTo(0,0);
}

/* ───────── accueil ───────── */
PAGES.accueil=async()=>{
  const draw=async()=>{
    const d=await api("GET","/api/dashboard");if(S.page!=="accueil")return;const c=d.cards;
    $("#main").innerHTML=`<div class="grid">${[["Ventes du jour",fmt(c.ventes_jour)],["Bénéfice net du jour",fmt(c.benef_jour)],["Dettes clients",fmt(c.dettes)],["Stock (valeur d'achat)",fmt(c.stock)],["Articles en alerte",c.alertes]].map(k=>`<div class="kpi"><small>${k[0]}</small><b>${esc(k[1])}</b></div>`).join("")}</div>
    <div class="card" style="margin-top:10px"><h3>Résultats par période <span class="muted">(évolution vs période précédente)</span></h3>${tbl(["Période","CA","Évol.","Bén. brut","Dépenses","Bén. net","Marge","Caisse"],d.periodes.map(p=>R([p.nom,fmt(p.ca),evol(p.ca,p.ca0),fmt(p.bb),fmt(p.dep),fmt(p.bb-p.dep),pct(p.bb,p.ca),fmt(p.enc)],{c:p.bb-p.dep<0?"neg":""})))}</div>
    <div class="card"><h3>Meilleures ventes du mois</h3>${tbl(["Article","Vendus","CA","Bénéfice"],d.top.map(t=>[t[0],qte(t[1]),fmt(t[2]),fmt(t[3])]))}</div>
    <div class="card"><h3>À réapprovisionner</h3>${d.low.length?tbl(["Article","Reste","Seuil"],d.low.map(t=>R([t[0],qte(t[1]),qte(t[2])],{c:"neg"}))):'<span class="muted">Aucune alerte 👍</span>'}</div>
    <div class="muted" style="text-align:center">Mise à jour automatique toutes les 5 secondes</div>`};
  await draw();S.timer=setInterval(()=>draw().catch(()=>{}),5000);
};

/* ───────── ventes (panier) ───────── */
PAGES.ventes=async()=>{
  S.arts=await api("GET","/api/articles");const pat=S.user.role==="patron";
  $("#main").innerHTML=`<div class="card"><h3>1. Ajouter un article</h3>
   <input id="va" placeholder="Choisir ou taper un article…" autocomplete="off">
   <div class="row"><label>Quantité<input id="vq" type="number" inputmode="decimal" step="any" value="1"></label>
   <label>Prix unitaire<input id="vp" type="number" inputmode="decimal" step="any" ${pat?"":"readonly"}></label></div>
   <div id="vap" class="muted" style="margin-top:6px"></div><button class="btn" id="vadd">➕ Ajouter au panier</button></div>
  <div class="card"><h3>2. Panier</h3><div id="vcart"></div></div>
  <div class="card"><h3>3. Paiement <span class="muted">(calculs en temps réel)</span></h3>
   <div class="row"><label>Client (si crédit)<input id="vc"></label><label>Mode<select id="vm"><option>Cash</option><option>Mobile Money</option><option>Autre</option></select></label></div>
   <div class="row">${pat?'<label>Remise<input id="vr" type="number" inputmode="decimal" step="any"></label>':""}<label>Montant payé (vide = tout)<input id="vpay" type="number" inputmode="decimal" step="any"></label></div>
   ${pat?`<label>Date<input id="vd" type="date" value="${today()}"></label>`:""}
   <div id="vtot" style="margin-top:8px"></div><button class="btn big" id="vok">✔ VALIDER LA VENTE</button></div>
  <div class="card"><h3>Historique</h3><div class="row" style="align-items:center"><input id="vs" placeholder="🔍 Rechercher…"><button class="btn sec" id="vx" style="margin:0;flex:none">CSV</button></div><div id="vh" style="margin-top:8px"></div></div>`;
  const A=()=>S.arts.find(a=>a.nom.toLowerCase()===$("#va").value.trim().toLowerCase());
  const deja=a=>S.panier.filter(l=>l.aid===a.id).reduce((s,l)=>s+l.qte,0);
  const apercu=()=>{const a=A(),q=n2($("#vq").value),p=n2($("#vp").value);if(!a){$("#vap").textContent="";return}
    const reste=a.stock-deja(a)-q;
    $("#vap").innerHTML=`Total ligne : <b>${fmt(q*p)}</b>${pat?` · Bénéfice : <b>${fmt(q*(p-a.pa))}</b>`:""} · Reste après vente : <b class="${reste<0?"neg":"ok"}">${qte(reste)}</b>`};
  const calc=()=>{const sous=S.panier.reduce((s,l)=>s+l.qte*l.pu,0),rem=Math.min(Math.max(pat?n2($("#vr").value):0,0),sous),net=sous-rem,ps=$("#vpay").value.trim(),p=ps===""?net:n2(ps),dette=Math.max(net-p,0),rendu=Math.max(p-net,0),ben=net-S.panier.reduce((s,l)=>s+l.qte*l.pa,0);
    $("#vtot").innerHTML=`<div class="tot"><span>Sous-total</span><span>${fmt(sous)}</span></div>${pat?`<div class="tot"><span>Remise</span><span>${fmt(rem)}</span></div>`:""}<div class="tot net"><span>NET À PAYER</span><span>${fmt(net)}</span></div>${pat?`<div class="tot"><span>Bénéfice estimé</span><b>${fmt(ben)}</b></div>`:""}${rendu>0.005?`<div class="tot ok"><span>Rendu monnaie</span><b>${fmt(rendu)}</b></div>`:`<div class="tot ${dette>0.005?"warn":""}"><span>Reste à payer (dette)</span><b>${fmt(dette)}</b></div>`}`};
  const cart=()=>{$("#vcart").innerHTML=tbl(["Article","Qté","Prix","Total",...(pat?["Bénéf."]:[]),""],S.panier.map((l,i)=>[l.nom,qte(l.qte),fmt(l.pu),fmt(l.qte*l.pu),...(pat?[fmt(l.qte*(l.pu-l.pa))]:[]),{h:`<button class="btn red" style="margin:0;padding:3px 10px" data-rm="${i}">✕</button>`}]));calc();apercu()};
  $("#vcart").onclick=e=>{const i=e.target.dataset.rm;if(i!==undefined){S.panier.splice(+i,1);cart()}};
  $("#va").oninput=()=>{const a=A();if(a)$("#vp").value=a.pv;apercu()};suggest($("#va"));
  $("#vq").oninput=$("#vp").oninput=apercu;
  $("#vpay").oninput=calc;if(pat)$("#vr").oninput=calc;
  const add=()=>{const a=A();if(!a)return toast("Choisissez un article dans la liste");
    const q=n2($("#vq").value),p=n2($("#vp").value);
    if(q<=0||p<0)return toast("Quantité ou prix invalide");
    if(!pat&&p<=0)return toast("Prix de vente non défini : demandez au patron");
    if(q+deja(a)>a.stock)return toast(`Stock insuffisant : il reste ${qte(a.stock-deja(a))} × ${a.nom}`);
    const l=S.panier.find(l=>l.aid===a.id&&l.pu===p);if(l)l.qte+=q;else S.panier.push({aid:a.id,nom:a.nom,qte:q,pu:p,pa:a.pa||0});
    $("#va").value="";$("#vq").value=1;$("#vp").value="";cart();$("#va").focus()};
  $("#vadd").onclick=add;$("#vq").onkeydown=e=>{if(e.key==="Enter")add()};
  $("#vok").onclick=()=>act(async()=>{const b=$("#vok");b.disabled=true;
    try{const ps=$("#vpay").value.trim();
      const r=await api("POST","/api/ventes",{lignes:S.panier.map(l=>({aid:l.aid,qte:l.qte,pu:l.pu})),client:$("#vc").value,mode:$("#vm").value,remise:pat?n2($("#vr").value):0,paye:ps===""?null:n2(ps),date:pat?$("#vd").value:""});
      S.panier=[];showRecu(r.recu);PAGES.ventes()}finally{b.disabled=false}});
  const histo=()=>act(async()=>{const rows=await api("GET","/api/ventes?q="+encodeURIComponent($("#vs").value));S.hist=rows;
    $("#vh").innerHTML=tbl(["Facture","Date","Article","Qté","Total","Payé","Dette","Client","Mode","Vendeur",...(pat?[""]:[])],rows.map(r=>R([r[1],r[2],r[3],qte(r[4]),fmt(r[6]),fmt(r[7]),fmt(r[8]),r[9],r[10],r[11],...(pat?[{h:`<button class="btn red" style="margin:0;padding:3px 8px" data-an="${r[0]}">🗑</button>`}]:[])],{c:r[8]>0.005?"warn":""})))});
  $("#vs").oninput=()=>{clearTimeout(S.dt);S.dt=setTimeout(histo,250)};
  $("#vh").onclick=e=>{const id=e.target.dataset.an;if(id)act(async()=>{if(!await sure("Annuler cette facture ? Le stock sera remis."))return;await api("POST","/api/ventes/annuler",{id:+id});toast("Facture annulée");PAGES.ventes()})};
  $("#vx").onclick=()=>csv(["Facture","Date","Article","Qté","Prix unit.","Total","Payé","Dette","Client","Mode","Vendeur"],(S.hist||[]).map(r=>[r[1],r[2],r[3],r[4],r[5],r[6],r[7],r[8],r[9],r[10],r[11]]),"ventes.csv");
  cart();await histo();
};

/* ───────── articles ───────── */
PAGES.articles=async()=>{
  const pat=S.user.role==="patron";S.arts=await api("GET","/api/articles");let sel=null;
  $("#main").innerHTML=`${pat?`<div class="card"><h3>Article <span class="muted">(touchez une ligne pour la modifier)</span></h3><label>Nom<input id="an"></label>
   <div class="row"><label>Prix d'achat<input id="aa" type="number" inputmode="decimal" step="any"></label><label>Prix de vente<input id="av" type="number" inputmode="decimal" step="any"></label></div>
   <div class="row"><label>Stock<input id="as" type="number" inputmode="decimal" step="any"></label><label>Alerte stock bas<input id="al" type="number" inputmode="decimal" step="any" value="5"></label></div>
   <div id="am" class="muted" style="margin-top:6px"></div>
   <div class="row"><button class="btn" id="aadd">Ajouter</button><button class="btn sec" id="aed">Modifier</button><button class="btn red" id="adel">Supprimer</button></div>
   <button class="btn sec" id="acl" style="width:100%">Vider les champs</button></div>`:""}
  <div class="card"><div class="row" style="align-items:center"><input id="asr" placeholder="🔍 Rechercher…"><button class="btn sec" id="ax" style="margin:0;flex:none">CSV</button></div><div id="alist" style="margin-top:8px"></div></div>`;
  const list=()=>{const t=$("#asr").value.toLowerCase();const rows=S.arts.filter(a=>a.nom.toLowerCase().includes(t));S.shown=rows;
    $("#alist").innerHTML=pat?tbl(["Article","Prix achat","Prix vente","Marge","Vendus","Reste","Alerte","Valeur stock"],rows.map(a=>R([a.nom,fmt(a.pa),fmt(a.pv),pct(a.pv-a.pa,a.pv),qte(a.vendus),qte(a.stock),qte(a.seuil),fmt(a.stock*a.pa)],{id:a.id,c:a.stock<=a.seuil?"neg":""}))):tbl(["Article","Prix de vente","Reste en stock"],rows.map(a=>R([a.nom,fmt(a.pv),qte(a.stock)],{c:a.stock<=a.seuil?"neg":""})))};
  $("#asr").oninput=list;list();
  $("#ax").onclick=()=>csv(pat?["Article","Prix achat","Prix vente","Vendus","Reste","Alerte"]:["Article","Prix de vente","Reste"],S.shown.map(a=>pat?[a.nom,a.pa,a.pv,a.vendus,a.stock,a.seuil]:[a.nom,a.pv,a.stock]),"articles.csv");
  if(!pat)return;
  const marge=()=>{const pa=n2($("#aa").value),pv=n2($("#av").value);$("#am").textContent=pv?`Marge unitaire : ${fmt(pv-pa)} (${pct(pv-pa,pv)} du prix de vente)`:""};
  $("#aa").oninput=$("#av").oninput=marge;
  const body=()=>({nom:$("#an").value,pa:$("#aa").value,pv:$("#av").value,stock:$("#as").value,seuil:$("#al").value});
  $("#alist").onclick=e=>{const tr=e.target.closest("tr[data-id]");if(!tr)return;sel=+tr.dataset.id;const a=S.arts.find(x=>x.id===sel);
    $("#an").value=a.nom;$("#aa").value=a.pa;$("#av").value=a.pv;$("#as").value=a.stock;$("#al").value=a.seuil;marge();window.scrollTo(0,0)};
  $("#acl").onclick=()=>PAGES.articles();
  $("#aadd").onclick=()=>act(async()=>{await api("POST","/api/articles",body());toast("Article ajouté");PAGES.articles()});
  $("#aed").onclick=()=>act(async()=>{if(!sel)throw new Error("Touchez d'abord un article dans la liste");await api("PUT","/api/articles/"+sel,body());toast("Article modifié");PAGES.articles()});
  $("#adel").onclick=()=>act(async()=>{if(!sel)throw new Error("Touchez d'abord un article dans la liste");if(!await sure("Supprimer cet article ?"))return;await api("DELETE","/api/articles/"+sel);toast("Article supprimé");PAGES.articles()});
};

/* ───────── dettes ───────── */
PAGES.dettes=async()=>{
  const d=await api("GET","/api/dettes");
  $("#main").innerHTML=`<div class="card"><div class="kpi"><small>Total des dettes</small><b class="warn">${fmt(d.total)}</b></div><div class="row" style="align-items:center;margin-top:8px"><input id="ds" placeholder="🔍 Rechercher un client…"><button class="btn sec" id="dx" style="margin:0;flex:none">CSV</button></div></div><div id="dl2"></div>`;
  const draw=()=>{const t=$("#ds").value.toLowerCase();
    $("#dl2").innerHTML=d.clients.filter(c=>(c.client||"(sans nom)").toLowerCase().includes(t)).map(c=>`<div class="card"><div class="row" style="align-items:center"><div><b>${esc(c.client||"(sans nom)")}</b><div class="muted">${c.n} ligne(s)</div></div><div style="text-align:right"><b class="warn">${fmt(c.dette)}</b></div></div><details><summary class="muted">Détail</summary>${tbl(["Date","Facture","Article","Total","Payé","Reste"],c.lignes.map(l=>[l[1],l[2],l[3],fmt(l[4]),fmt(l[5]),fmt(l[6])]))}</details><button class="btn" data-pay="${d.clients.indexOf(c)}">💰 Encaisser un paiement</button></div>`).join("")||'<div class="card muted">Aucune dette 🎉</div>'};
  $("#ds").oninput=draw;draw();
  $("#dl2").onclick=e=>{const i=e.target.dataset.pay;if(i===undefined)return;const c=d.clients[+i];
    act(async()=>{const f=await askForm("Encaisser — "+(c.client||"(sans nom)"),[{n:"m",l:`Montant reçu (dette : ${fmt(c.dette)})`,t:"number"}],"Encaisser");
      if(!f)return;await api("POST","/api/dettes",{client:c.client,montant:f.m});toast("Paiement enregistré ✔");PAGES.dettes()})};
  $("#dx").onclick=()=>csv(["Client","Date","Facture","Article","Total","Payé","Reste"],d.clients.flatMap(c=>c.lignes.map(l=>[c.client||"(sans nom)",l[1],l[2],l[3],l[4],l[5],l[6]])),"dettes.csv");
};

/* ───────── stock / achats ───────── */
PAGES.stock=async()=>{
  S.arts=await api("GET","/api/articles");
  $("#main").innerHTML=`<div class="card"><h3>Entrée de marchandise</h3><input id="sa" placeholder="Article…" autocomplete="off">
  <div class="row"><label>Quantité reçue<input id="sq" type="number" inputmode="decimal" step="any"></label><label>Prix d'achat unitaire (vide = inchangé)<input id="sp" type="number" inputmode="decimal" step="any"></label></div>
  <label>Date<input id="sd" type="date" value="${today()}"></label><div id="si" class="muted" style="margin-top:6px"></div><button class="btn" id="sok">Ajouter au stock</button></div>
  <div class="card"><h3>Historique</h3><input id="ss" placeholder="🔍 Rechercher…"><div id="sh" style="margin-top:8px"></div></div>`;
  const A=()=>S.arts.find(a=>a.nom.toLowerCase()===$("#sa").value.trim().toLowerCase());
  const info=()=>{const a=A(),q=n2($("#sq").value),ps=$("#sp").value.trim(),p=ps===""?(a?a.pa:0):n2(ps);$("#si").textContent=a&&q?`Stock après entrée : ${qte(a.stock+q)} · Coût total : ${fmt(q*p)}`:""};
  $("#sa").oninput=$("#sq").oninput=$("#sp").oninput=info;suggest($("#sa"));
  $("#sok").onclick=()=>act(async()=>{const a=A();if(!a)throw new Error("Choisissez un article dans la liste");await api("POST","/api/achats",{aid:a.id,qte:$("#sq").value,pa:$("#sp").value,date:$("#sd").value});toast("Stock mis à jour ✔");PAGES.stock()});
  const rows=await api("GET","/api/achats");
  const draw=()=>{const t=$("#ss").value.toLowerCase();$("#sh").innerHTML=tbl(["Date","Article","Quantité","Prix d'achat","Coût total"],rows.filter(r=>!t||r.join(" ").toLowerCase().includes(t)).map(r=>[r[0],r[1],qte(r[2]),fmt(r[3]),fmt(r[4])]))};
  $("#ss").oninput=draw;draw();
};

/* ───────── dépenses ───────── */
PAGES.depenses=async()=>{
  const d=await api("GET","/api/depenses");
  $("#main").innerHTML=`<div class="card"><h3>Nouvelle dépense</h3><label>Libellé (transport, loyer, salaire…)<input id="dg"></label><div class="row"><label>Montant<input id="dm" type="number" inputmode="decimal" step="any"></label><label>Date<input id="dd" type="date" value="${today()}"></label></div><button class="btn" id="dok">Ajouter</button></div>
  <div class="card"><div class="kpi"><small>Total des dépenses · ce mois : ${fmt(d.mois)}</small><b class="warn">${fmt(d.total)}</b></div><div id="dlst" style="margin-top:8px">${tbl(["Date","Libellé","Montant",""],d.rows.map(r=>[r[1],r[2],fmt(r[3]),{h:`<button class="btn red" style="margin:0;padding:3px 8px" data-del="${r[0]}">🗑</button>`}]))}</div></div>`;
  $("#dok").onclick=()=>act(async()=>{await api("POST","/api/depenses",{libelle:$("#dg").value,montant:$("#dm").value,date:$("#dd").value});toast("Dépense ajoutée");PAGES.depenses()});
  $("#dlst").onclick=e=>{const id=e.target.dataset.del;if(id)act(async()=>{if(!await sure("Supprimer cette dépense ?"))return;await api("DELETE","/api/depenses/"+id);PAGES.depenses()})};
};

/* ───────── analyses ───────── */
PAGES.analyses=async()=>{
  $("#main").innerHTML=`<div class="card"><div class="row"><label>Analyse par<select id="ap"><option>Jour</option><option>Semaine</option><option>Mois</option><option>Année</option></select></label><label>Du<input id="ad" type="date"></label><label>Au<input id="au" type="date"></label></div>
  <div class="row"><button class="btn sec" data-j="7">7 jours</button><button class="btn sec" data-j="30">30 jours</button><button class="btn sec" data-j="0">Tout</button></div></div>
  <div class="card"><div class="row" style="align-items:center"><h3 style="margin:0">Par période</h3><button class="btn sec" id="ax1" style="margin:0;flex:none">CSV</button></div><div id="at"></div><div id="ac"></div></div>
  <div class="card"><div class="row" style="align-items:center"><h3 style="margin:0">Par article : vendus et restants</h3><button class="btn sec" id="ax2" style="margin:0;flex:none">CSV</button></div><div id="aar"></div></div>`;
  const load=()=>act(async()=>{const d=await api("GET",`/api/analyses?per=${$("#ap").value}&du=${$("#ad").value}&au=${$("#au").value}`);S.an=d;
    const P=d.periodes;S.anRows=P.map((p,i)=>[p.p,p.n,qte(p.qt),fmt(p.ca),evol(p.ca,P[i+1]?P[i+1].ca:0),fmt(p.bb),fmt(p.dep),fmt(p.bb-p.dep),pct(p.bb,p.ca),fmt(p.pay),fmt(p.ca-p.pay)]);
    $("#at").innerHTML=tbl(["Période","Ventes","Qté","CA","Évol.","Bén. brut","Dépenses","Bén. net","Marge","Payé","Dettes"],S.anRows.map((r,i)=>R(r.slice(),{c:P[i].bb-P[i].dep<0?"neg":""})));
    const ch=P.slice(0,12).reverse(),m=Math.max(1,...ch.map(p=>Math.max(p.ca,p.bb-p.dep))),W=600,H=170,sl=W/Math.max(ch.length,1);
    $("#ac").innerHTML=ch.length?`<svg viewBox="0 0 ${W} ${H}" width="100%" style="margin-top:8px"><text x="4" y="10" font-size="10" fill="#2563eb">■ Chiffre d'affaires</text><text x="110" y="10" font-size="10" fill="#16a34a">■ Bénéfice net</text>${ch.map((p,i)=>{const x=i*sl+sl*.12,w=sl*.36,h1=p.ca/m*(H-50),h2=Math.max(p.bb-p.dep,0)/m*(H-50);return `<rect x="${x}" y="${H-20-h1}" width="${w}" height="${h1}" fill="#2563eb"/><rect x="${x+w}" y="${H-20-h2}" width="${w}" height="${h2}" fill="#16a34a"/><text x="${x+w}" y="${H-6}" font-size="9" text-anchor="middle">${esc(p.p.length>7?p.p.slice(5):p.p)}</text>`}).join("")}</svg>`:"";
    $("#aar").innerHTML=tbl(["Article","Vendus","Reste","CA","Bénéfice","Marge"],d.articles.map(a=>[a.nom,qte(a.vendus),qte(a.stock),fmt(a.ca),fmt(a.b),pct(a.b,a.ca)]))});
  $("#ap").onchange=$("#ad").onchange=$("#au").onchange=load;
  $("#main").querySelectorAll("[data-j]").forEach(b=>b.onclick=()=>{const j=+b.dataset.j,t=new Date();$("#au").value=j?today():"";$("#ad").value=j?new Date(t-(j-1)*864e5-t.getTimezoneOffset()*6e4).toISOString().slice(0,10):"";load()});
  $("#ax1").onclick=()=>csv(["Période","Ventes","Qté","CA","Évol.","Bén. brut","Dépenses","Bén. net","Marge","Payé","Dettes"],S.anRows||[],"analyse.csv");
  $("#ax2").onclick=()=>csv(["Article","Vendus","Reste","CA","Bénéfice"],((S.an||{}).articles||[]).map(a=>[a.nom,a.vendus,a.stock,a.ca,a.b]),"articles_analyse.csv");
  await load();
};

/* ───────── plus (compte, utilisateurs, réglages) ───────── */
PAGES.plus=async()=>{
  const pat=S.user.role==="patron";const u=S.user;
  $("#main").innerHTML=`<div class="card"><h3>👤 ${esc(u.nom)} <span class="muted">(${u.role})</span></h3><div class="row"><button class="btn sec" id="pm">Mon mot de passe</button><button class="btn red" id="plo">Déconnexion</button></div></div>
  ${pat?`<div class="card"><h3>Boutique et devise</h3><button class="btn sec" id="pp">Modifier (devise, nom, téléphone)</button><button class="btn sec" id="ps" style="margin-left:8px">💾 Sauvegarder la base</button></div>
  <div class="card"><h3>Utilisateurs</h3><div id="pu"></div><button class="btn" id="pua">➕ Ajouter un utilisateur</button></div>
  <div class="card appo"><h3>📱 Application Android</h3><p class="muted" style="margin:0">Vos données sont enregistrées sur ce téléphone. « Sauvegarder la base » en garde une copie dans Téléchargements/Ekonzo.</p></div><div class="card noapp"><h3>📱 Utiliser sur téléphone</h3><p class="muted" style="margin-top:0">Connectez le téléphone au même Wi-Fi que cet ordinateur, puis ouvrez dans son navigateur :</p>${(u.adresses||[]).map(a=>`<pre>http://${esc(a)}:${esc(location.port||80)}</pre>`).join("")||'<p class="muted">Adresse introuvable : lancez « ipconfig » (Windows) ou « ifconfig » pour connaître l\'IP du PC.</p>'}<p class="muted">Astuce : menu du navigateur → « Ajouter à l'écran d'accueil » pour l'installer comme une application.</p></div>`:""}`;
  $("#plo").onclick=()=>act(async()=>{await api("POST","/api/logout");S.token="";localStorage.removeItem("ek_t");S.panier=[];boot()});
  $("#pm").onclick=()=>act(async()=>{const f=await askForm("Changer mon mot de passe",[{n:"a",l:"Mot de passe actuel",t:"password"},{n:"n",l:"Nouveau mot de passe",t:"password"},{n:"c",l:"Confirmer",t:"password"}],"Modifier");
    if(!f)return;if(f.n!==f.c)throw new Error("Les deux mots de passe ne correspondent pas");await api("POST","/api/mdp",{ancien:f.a,nouveau:f.n});toast("Mot de passe modifié ✔")});
  if(!pat)return;
  $("#pp").onclick=()=>act(async()=>{const f=await askForm("Boutique",[{n:"devise",l:"Devise (FC, $, USD…)",v:S.dev},{n:"boutique",l:"Nom de la boutique (reçus)",v:S.boutique},{n:"tel",l:"Téléphone (reçus)",v:u.tel||""}],"Enregistrer");
    if(!f)return;await api("POST","/api/params",f);S.dev=f.devise.trim()||S.dev;S.boutique=f.boutique.trim()||S.boutique;u.tel=f.tel;$("#hb").textContent=S.boutique;toast("Enregistré ✔")});
  $("#ps").onclick=()=>act(async()=>{if(APP){const r=await api("POST","/api/sauvegarde");return toast("Sauvegarde enregistrée : "+r.chemin)}const b=await api("GET","/api/sauvegarde");const a=document.createElement("a");a.href=URL.createObjectURL(b);a.download=`ekonzo_${today().replace(/-/g,"")}.db`;a.click()});
  const users=async()=>{const rows=await api("GET","/api/users");$("#pu").innerHTML=tbl(["Nom","Rôle",""],rows.map(r=>[r[0],r[1],{h:`<button class="btn sec" style="margin:0;padding:3px 8px" data-k="${esc(r[0])}">🔑</button> <button class="btn red" style="margin:0;padding:3px 8px" data-d="${esc(r[0])}">🗑</button>`}]))};
  $("#pu").onclick=e=>{const k=e.target.dataset.k,d=e.target.dataset.d;
    if(k)act(async()=>{const f=await askForm("Nouveau mot de passe pour "+k,[{n:"m",l:"Mot de passe",t:"password"}],"Modifier");if(f){await api("PUT","/api/users/"+encodeURIComponent(k),{mdp:f.m});toast("Mot de passe modifié ✔")}});
    if(d)act(async()=>{if(!await sure("Supprimer l'utilisateur "+d+" ?"))return;await api("DELETE","/api/users/"+encodeURIComponent(d));users()})};
  $("#pua").onclick=()=>act(async()=>{const f=await askForm("Nouvel utilisateur",[{n:"nom",l:"Nom"},{n:"mdp",l:"Mot de passe",t:"password"},{n:"role",l:"Rôle",o:["vendeur","patron"],v:"vendeur"}],"Ajouter");
    if(!f)return;await api("POST","/api/users",f);toast("Utilisateur ajouté ✔");users()});
  await users();
};
boot();
</script>
</body>
</html>
"""

if __name__ == "__main__":
    main()
