import json, sqlite3, sys
from cryptography.fernet import InvalidToken
from sentinel.config import load as load_config
from sentinel.triage.store import require_fernet
from sentinel.triage.scoring import compute_raw_score

config = load_config()
print(repr(config.evidence_encryption_key), len(config.evidence_encryption_key or ""))
fernet = require_fernet(config)
conn = sqlite3.connect('data/evidence.db')
rows = conn.execute('SELECT message_hash, verdict_json FROM evidence_records ORDER BY created_at ASC').fetchall()
conn.close()

shown = 0
for message_hash, blob in rows:
    try:
        plaintext = fernet.decrypt(blob)
    except InvalidToken:
        print(f'  [skip] hash={message_hash}: could not decrypt with the current SENTINEL_EVIDENCE_KEY', file=sys.stderr)
        continue
    record = json.loads(plaintext)
    report = record['report']
    if any(e['direction'] == 'malicious' for e in report['evidence']) and shown < 3:
        shown += 1
        print(f'--- {message_hash} ---')
        print(f"verdict={report['verdict']}  calibrated_confidence={report['calibrated_confidence']}")
        for e in report['evidence']:
            print(f"  {e['direction']:9s} weight={e['weight']:.3f}  {e['name']}: {e['finding'][:70]}")
        print(f"  recomputed raw_score = {compute_raw_score(report['evidence']):.4f}")
