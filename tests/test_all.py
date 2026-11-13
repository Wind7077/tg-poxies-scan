import base64
import json
from datetime import timedelta

import pytest

from scanner import dedup, extract, out, wl
from scanner.cfg import _norm_mode, load
from scanner.extract import now_utc
from scanner.parse import parse, sanitize, validate
from scanner.pipeline import _l3_pass, _mark


def b64(s):
    return base64.b64encode(s.encode()).decode().rstrip('=')


CFG = load('config.yaml')

VLESS_REALITY = ('vless://11111111-2222-3333-4444-555555555555@1.2.3.4:443?type=tcp'
                 '&security=reality&pbk=K&sid=abcd&fp=chrome&flow=xtls-rprx-vision'
                 '&sni=api-maps.yandex.ru#DE')
VLESS_WS = ('vless://11111111-2222-3333-4444-555555555555@h.com:8443?type=ws&path=%2Fws'
            '&host=cdn.com&security=tls&ed=2048#ws')
VLESS_V6 = 'vless://11111111-2222-3333-4444-555555555555@[2001:db8::1]:443?security=tls#v6'
SS_SIP = f"ss://{b64('aes-256-gcm:Pass')}@5.6.7.8:8388#ss"
SS_LEGACY = 'ss://' + b64('chacha20-ietf-poly1305:Legacy@9.9.9.9:8388') + '#legacy'
HY2 = 'hy2://pw@hy.com:443?insecure=1&sni=hy.com&obfs=salamander&obfs-password=o#hy'
TROJAN = 'trojan://p%40ss@tr.com:443?type=ws&path=%2Ftr&security=tls&sni=tr.com&allowInsecure=1#tr'
TUIC = ('tuic://11111111-2222-3333-4444-555555555555:tp@tu.com:443?sni=tu.com&alpn=h3'
        '&allow_insecure=1#tuic')
VMESS = 'vmess://' + b64(json.dumps({
    'ps': 'vm', 'add': 'vm.com', 'port': '443',
    'id': '11111111-2222-3333-4444-555555555555', 'aid': '0', 'scy': 'auto',
    'net': 'ws', 'host': 'cdn.vm.com', 'path': '/vmws', 'tls': 'tls', 'sni': 'sni.vm.com'}))


@pytest.mark.parametrize('uri,check', [
    (VLESS_REALITY, lambda p: p['reality-opts']['public-key'] == 'K' and p['flow']),
    (VLESS_WS, lambda p: p['ws-opts']['path'] == '/ws' and p['ws-opts']['max-early-data'] == 2048),
    (VLESS_V6, lambda p: p['server'] == '2001:db8::1' and p['port'] == 443),
    (SS_SIP, lambda p: p['cipher'] == 'aes-256-gcm' and p['password'] == 'Pass'),
    (SS_LEGACY, lambda p: p['password'] == 'Legacy' and p['server'] == '9.9.9.9'),
    (HY2, lambda p: p['skip-cert-verify'] and p['obfs'] == 'salamander'),
    (TROJAN, lambda p: p['password'] == 'p@ss' and p['ws-opts']['path'] == '/tr'),
    (TUIC, lambda p: p['alpn'] == ['h3'] and p['skip-cert-verify']),
    (VMESS, lambda p: p['ws-opts']['path'] == '/vmws' and p['server-name'] == 'sni.vm.com'),
])
def test_parse(uri, check):
    p = sanitize(parse(uri))
    assert p and check(p)
    assert validate(p)[0], validate(p)


# ---------- расклейка ----------
def test_glue_split_only_in_name():
    uri = ('vless://11111111-2222-3333-4444-555555555555@h.com:443?type=ws'
           '&path=/wss://x&security=tls#name')
    variants, tails = dedup.split_uri(uri)
    assert variants == [uri] and tails == []


def test_glue_split_real():
    a = 'vless://11111111-2222-3333-4444-555555555555@a.com:443?security=tls#A'
    b = 'vless://11111111-2222-3333-4444-555555555555@b.com:443?security=tls#B'
    variants, tails = dedup.split_uri(a + b)
    assert variants[0] == a and variants[1] == a + b
    assert tails == [b]


def test_glue_no_overlap_inside_scheme():
    a = 'vless://11111111-2222-3333-4444-555555555555@a.com:443?security=tls#A'
    b = 'vless://11111111-2222-3333-4444-555555555555@b.com:443?security=tls#B'
    variants, tails = dedup.split_uri(a + b)
    assert tails == [b]
    assert all(t.startswith('vless://') for t in tails)
    assert all(parse(t) for t in tails)


def test_glue_wss_in_name_not_split():
    uri = ('vless://11111111-2222-3333-4444-555555555555@a.com:443'
           '?security=tls#name-wss://x')
    variants, tails = dedup.split_uri(uri)
    assert variants == [uri] and tails == []


def test_glue_head_always_parses():
    glued = VLESS_REALITY + VLESS_WS
    assert parse(glued) is not None
    variants, _ = dedup.split_uri(glued)
    assert parse(variants[0]) is not None


# ---------- URL / фильтры ----------
def test_clean_url_keeps_vless():
    uri = 'vless://11111111-2222-3333-4444-555555555555@h:443?type=ws&path=wshttps://x#n'
    assert extract.clean_url(uri) == uri


def test_blacklist_boundary():
    assert extract.is_valid_url('https://netflix.com/sub', CFG)
    assert not extract.is_valid_url('https://x.com/a', CFG)
    assert not extract.is_valid_url('https://sub.x.com/a', CFG)
    assert not extract.is_valid_url('https://play.google.com/x', CFG)


def test_normalize_utm_and_mirrors():
    assert extract.normalize_sub_url('https://x.com/s?utm_source=tg&id=5') == 'https://x.com/s?id=5'
    assert (extract.normalize_sub_url('https://hub.mos.ru/a/-/raw/main/wl') ==
            extract.normalize_sub_url('https://hub.mos.ru/a/raw/main/wl'))
    keep = 'https://s.com/sub?key=abc'
    assert extract.normalize_sub_url(keep) == keep


def test_dedupe_raw_vs_tcp():
    a = 'vless://11111111-2222-3333-4444-555555555555@h.com:443?type=raw&security=tls#x'
    b = 'vless://11111111-2222-3333-4444-555555555555@h.com:443?type=tcp&security=tls#y'
    reps, members = dedup.dedupe([a, b], CFG)
    assert len(reps) == 1 and len(members[reps[0]]) == 2


def test_wl_roots():
    assert wl.roots_match({'name': 'Телефон / Роутер'}, CFG)
    assert wl.roots_match({'name': 'Автовыбор'}, CFG)
    assert wl.roots_match({'name': 'Белые списки | МТС'}, CFG)
    assert not wl.roots_match({'name': 'Filter'}, CFG)
    assert not wl.roots_match({'name': 'обслуживание'}, CFG)


def test_issue_glue():
    parts = extract.split_issues('csqtt://aaaaXXXXqwdtt://bbbbYYYYolcrtc://ccccZZZZ')
    assert len(parts) == 2 and parts[1].startswith('olcrtc://')


# ---------- конфиг ----------
def test_yaml_off_is_bool_normalized():
    """YAML 1.1: require_mode: off -> False. Должно стать строкой 'off'."""
    assert _norm_mode(False, 'both') == 'off'
    assert _norm_mode(True, 'both') == 'any'
    assert _norm_mode('both', 'off') == 'both'
    assert _norm_mode('мусор', 'off') == 'off'
    assert isinstance(CFG.verify.l3.require_mode_all, str)
    assert isinstance(CFG.verify.l3.require_mode_wl, str)


def test_env_overrides_telegram(monkeypatch, tmp_path):
    """Секреты из env должны попадать в cfg.telegram."""
    monkeypatch.setenv('TELEGRAM_API_ID', '12345678')
    monkeypatch.setenv('TELEGRAM_API_HASH', 'h' * 32)
    monkeypatch.setenv('TELEGRAM_SESSION', 'c2Vzc2lvbg==')
    cfg = load(str(tmp_path / 'absent.yaml'))
    assert cfg.telegram.api_id == 12345678
    assert cfg.telegram.api_hash == 'h' * 32
    assert cfg.telegram.session_b64 == 'c2Vzc2lvbg=='


def test_defaults_have_telegram(monkeypatch, tmp_path):
    for k in ('TELEGRAM_API_ID', 'TELEGRAM_API_HASH', 'TELEGRAM_SESSION'):
        monkeypatch.delenv(k, raising=False)
    cfg = load(str(tmp_path / 'absent.yaml'))
    assert cfg.telegram.api_id == 0
    assert cfg.telegram.api_hash == ''
    assert cfg.telegram.session_b64 == ''


def test_defaults_not_mutated_by_env(monkeypatch, tmp_path):
    """РЕГРЕССИЯ: _deep_merge делал浅 копию, и _env_override писал в _DEFAULTS."""
    absent = str(tmp_path / 'absent.yaml')
    monkeypatch.setenv('TELEGRAM_API_ID', '99999999')
    monkeypatch.setenv('VERIFY_LEVEL', '0')
    monkeypatch.setenv('CORE_MAX', '7')
    c1 = load(absent)
    assert c1.telegram.api_id == 99999999
    assert c1.verify.level == 0
    assert c1.limits.core_max == 7

    for k in ('TELEGRAM_API_ID', 'VERIFY_LEVEL', 'CORE_MAX'):
        monkeypatch.delenv(k, raising=False)
    c2 = load(absent)
    assert c2.telegram.api_id == 0, 'дефолты протекли между load()'
    assert c2.verify.level == 2
    assert c2.limits.core_max == 1500


def test_legacy_require_mode_migrates(tmp_path):
    p = tmp_path / 'c.yaml'
    p.write_text('verify:\n  l3:\n    require_mode: both\n', encoding='utf-8')
    cfg = load(str(p))
    assert cfg.verify.l3.require_mode_all == 'both'


# ---------- L3 логика ----------
@pytest.mark.parametrize('mode,tg,yt,expected', [
    ('both', True, True, True),
    ('both', True, False, False),
    ('both', False, True, False),
    ('any', True, False, True),
    ('any', False, False, False),
    ('telegram', True, False, True),
    ('telegram', False, True, False),
    ('youtube', False, True, True),
    ('off', False, False, True),
    ('both', None, None, True),   # не проверялось — не отсеиваем
    ('both', True, None, False),
])
def test_l3_pass(mode, tg, yt, expected):
    assert _l3_pass(mode, tg, yt) is expected


def test_l3_marks():
    assert _mark(True, True) == '🟢'
    assert _mark(True, False) == '🟡'
    assert _mark(False, True) == '🔵'
    assert _mark(False, False) == '⚪️'
    assert _mark(None, None) == ''


# ---------- вывод / guard ----------
def test_write_if_changed(tmp_path):
    f = tmp_path / 'p.txt'
    assert out.write_txt(str(f), ['a'], 1) is True
    assert out.write_txt(str(f), ['a'], 1) is False
    assert out.write_txt(str(f), ['b'], 1) is True


def test_guard_blocks_empty_wl():
    stats = {'candidates': 100, 'parsed': 95, 'wl': 0, 'all': 500}
    problems = out.guard(CFG, stats, {'wl': 500, 'all': 500})
    assert any('WL=0' in p for p in problems)


def test_guard_blocks_low_parse_rate():
    stats = {'candidates': 100, 'parsed': 10, 'wl': 5, 'all': 10}
    assert any('parse_rate' in p for p in out.guard(CFG, stats, {'wl': 5, 'all': 10}))


def test_guard_ok():
    stats = {'candidates': 100, 'parsed': 95, 'wl': 400, 'all': 900}
    assert out.guard(CFG, stats, {'wl': 500, 'all': 1000}) == []


def test_guard_uses_attempts_not_candidates():
    """parse_rate от попыток после дедупа, не от сырых кандидатов."""
    stats = {'candidates': 52384, 'reps': 24369, 'parsed': 23503,
             'parse_fails': {'x': 854}, 'wl': 500, 'all': 10000}
    out.guard(CFG, stats, {'wl': 500, 'all': 10000})
    assert stats['parse_attempts'] == 24357
    assert stats['parse_rate'] > 0.96


def test_guard_fallback_to_reps():
    """Нет parse_fails — берём reps, а не схлопываем в parsed."""
    stats = {'candidates': 5000, 'reps': 1000, 'parsed': 100, 'wl': 5, 'all': 100}
    problems = out.guard(CFG, stats, {'wl': 5, 'all': 100})
    assert stats['parse_attempts'] == 1000
    assert any('parse_rate' in p for p in problems)


def test_messages_dates():
    now = now_utc()
    old = (now - timedelta(days=30)).isoformat()
    new = (now - timedelta(days=1)).isoformat()
    html = f'''<div class="tgme_widget_message" data-post="c/10"><time datetime="{new}"></time>
    <div class="tgme_widget_message_text">{VLESS_REALITY}</div></div>
    <div class="tgme_widget_message" data-post="c/5"><time datetime="{old}"></time>
    <div class="tgme_widget_message_text">{VLESS_WS}</div></div>'''
    p, u, mid = extract.messages(html, now - timedelta(days=50), CFG)
    assert mid == 5 and len(p) == 2
    assert (now - p[1][1]).days >= 29
