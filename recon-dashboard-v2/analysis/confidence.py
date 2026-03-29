"""Confidence scoring for infrastructure changes."""
from models import get_db


def score_change(change_id: int, censys_result: dict | None = None, nmap_result: dict | None = None) -> float:
    """Update a change's confidence score based on cross-source validation."""
    db = get_db()
    row = db.execute("SELECT * FROM changes WHERE id = ?", (change_id,)).fetchone()
    if not row:
        return 0.0

    score = row['confidence']  # base from readings_present / total_readings

    if censys_result:
        if censys_result.get('found'):
            port = row['port']
            if port in censys_result.get('ports', []):
                score += 0.2  # confirmed by Censys
        else:
            # Censys doesn't see it — if it "appeared" in Shodan, lower confidence
            if row['change_type'] == 'appeared':
                score -= 0.1

    if nmap_result:
        if row['change_type'] == 'disappeared':
            if nmap_result.get('state') in ('closed', 'filtered'):
                score += 0.2  # nmap confirms it's gone
            elif nmap_result.get('state') == 'open':
                score -= 0.3  # still alive, Shodan just missed it
        db.execute(
            "UPDATE changes SET nmap_verified = 1, nmap_state = ? WHERE id = ?",
            (nmap_result.get('state', ''), change_id),
        )

    score = max(0.0, min(1.0, score))
    db.execute("UPDATE changes SET confidence = ? WHERE id = ?", (round(score, 2), change_id))
    db.commit()
    return score
