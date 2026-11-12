import base64
import json
from datetime import timedelta

import pytest

from scanner import dedup, extract, out, wl
from scanner.cfg import load
from scanner.extract import now_utc
from scanner.parse import parse, sanitize, validate


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


def test_glue_split_only_in_name():
    """РЕГРЕССИЯ: wss:// внутри path содержит ss:// — резать там нельзя."""
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
    """РЕГРЕССИЯ: 'vless://' содержит 'ss://' — хвост не должен терять схему."""
    a = 'vless://11111111-2222-3333-4444-555555555555@a.com:443?security=tls#A'
    b = 'vless://11111111-2222-3333-4444-555555555555@b.com:443?security=tls#B'
    variants, tails = dedup.split_uri(a + b)
    assert tails == [b]
    assert all(t.startswith('vless://') for t in tails)
    assert all(parse(t) for t in tails)


def test_glue_wss_in_name_not_split():
    """'wss://' внутри имени — не ссылка, резать нечего."""
    uri = ('vless://11111111-2222-3333-4444-555555555555@a.com:443'
           '?security=tls#name-wss://x')
    variants, tails = dedup.split_uri(uri)
    assert variants == [uri] and tails == []


def test_glue_head_always_parses():
    """Голова склейки обязана парситься так же, как исходная ссылка."""
    glued = VLESS_REALITY + VLESS_WS
    assert parse(glued) is not None
    variants, _ = dedup.split_uri(glued)
    assert parse(variants[0]) is not None


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


def test_wl_sni_and_roots():
    clf = wl.Classifier(CFG)
    p = sanitize(parse(VLESS_REALITY))          # sni=api-maps.yandex.ru
    ok, why = clf.classify(p)
    assert ok and why.startswith('sni')
    assert wl.roots_match({'name': 'Телефон / Роутер'}, CFG)   # теле — как задумано
    assert wl.roots_match({'name': 'Автовыбор'}, CFG)          # авто — как задумано
    assert wl.roots_match({'name': 'Белые списки | МТС'}, CFG)
    assert not wl.roots_match({'name': 'Filter'}, CFG)         # ложное 'lte' не ловится
    assert not wl.roots_match({'name': 'обслуживание'}, CFG)   # ложное 'бс' не ловится


def test_issue_glue():
    parts = extract.split_issues('csqtt://aaaaXXXXqwdtt://bbbbYYYYolcrtc://ccccZZZZ')
    assert len(parts) == 2 and parts[1].startswith('olcrtc://')


def test_write_if_changed(tmp_path):
    f = tmp_path / 'p.txt'
    assert out.write_txt(str(f), ['a'], 1) is True
    assert out.write_txt(str(f), ['a'], 1) is False
    assert out.write_txt(str(f), ['b'], 1) is True


def test_guard_blocks_empty_wl():
    cfg = load('config.yaml')
    stats = {'candidates': 100, 'parsed': 95, 'wl': 0, 'all': 500}
    problems = out.guard(cfg, stats, {'wl': 500, 'all': 500})
    assert any('WL=0' in p for p in problems)


def test_guard_blocks_low_parse_rate():
    cfg = load('config.yaml')
    stats = {'candidates': 100, 'parsed': 10, 'wl': 5, 'all': 10}
    assert any('parse_rate' in p for p in out.guard(cfg, stats, {'wl': 5, 'all': 10}))


def test_guard_ok():
    cfg = load('config.yaml')
    stats = {'candidates': 100, 'parsed': 95, 'wl': 400, 'all': 900}
    assert out.guard(cfg, stats, {'wl': 500, 'all': 1000}) == []


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
