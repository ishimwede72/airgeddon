"""Bounded offline classic-PCAP beacon parser; no data/EAP/credential decoding."""
import hashlib
import struct
from pathlib import Path

from .assess import ValidationError, _object, _text

MAX_CAPTURE_BYTES = 64 * 1024 * 1024
MAX_PACKETS = 100000
MAX_IDENTITIES = 4096


def _rsn(value):
    """Only parse advertised RSN AKM suites and PMF capability bits."""
    if len(value) < 8 or value[:2] != b'\x01\x00':
        raise ValidationError('Invalid RSN element')
    offset = 6
    count = struct.unpack_from('<H', value, offset)[0]
    if count == 0:
        raise ValidationError('Empty RSN pairwise suites')
    offset += 2 + count * 4
    if offset + 2 > len(value):
        raise ValidationError('Truncated RSN pairwise suites')
    count = struct.unpack_from('<H', value, offset)[0]
    offset += 2
    if count == 0 or offset + count * 4 > len(value):
        raise ValidationError('Truncated RSN AKM suites')
    suites = {value[i:i + 4] for i in range(offset, offset + count * 4, 4)}
    offset += count * 4
    if len(value) - offset == 1:
        raise ValidationError('Truncated RSN capabilities')
    caps = struct.unpack_from('<H', value, offset)[0] if len(value) >= offset + 2 else 0
    # Do not infer WPA3-Enterprise from EAP alone, or personal modes from exotic AKMs.
    psk, sae = b'\x00\x0f\xac\x02', b'\x00\x0f\xac\x08'
    if suites == {psk, sae}:
        security = 'wpa2-wpa3-personal'
    elif suites == {psk}:
        security = 'wpa2-personal'
    elif suites == {sae}:
        security = 'wpa3-personal'
    elif suites == {b'\x00\x0f\xac\x01'}:
        security = 'rsn-enterprise'
    else:
        security = 'unknown'
    if caps & 0x40 and not caps & 0x80:
        raise ValidationError('Inconsistent PMF bits')
    return security, 'required' if caps & 0x40 else 'optional' if caps & 0x80 else 'disabled'


def _radiotap(packet):
    if len(packet) < 8 or packet[0] != 0:
        raise ValidationError('Invalid radiotap header')
    size = struct.unpack_from('<H', packet, 2)[0]
    if not 8 <= size <= len(packet):
        raise ValidationError('Truncated radiotap header')
    presence = struct.unpack_from('<I', packet, 4)[0]
    word, offset = presence, 8
    while word & 0x80000000:
        if offset + 4 > size or offset >= 64:
            raise ValidationError('Unsupported radiotap presence map')
        word = struct.unpack_from('<I', packet, offset)[0]
        offset += 4
    if presence & 1:  # TSFT precedes flags and is aligned to eight bytes.
        offset = (offset + 7) // 8 * 8 + 8
    if offset > size:
        raise ValidationError('Truncated radiotap fields')
    frame = packet[size:]
    if presence & 2:
        if offset >= size:
            raise ValidationError('Missing radiotap flags')
        flags = packet[offset]
        if flags & 0x40:
            raise ValidationError('Bad-FCS frame')
        if flags & 0x10:
            if len(frame) < 4:
                raise ValidationError('Missing FCS')
            frame = frame[:-4]
    return frame


def _beacon(frame):
    if len(frame) < 2 or struct.unpack_from('<H', frame)[0] & 0xFC != 0x80:
        return None  # Beacons only. Never decode data, authentication, or EAP frames.
    if len(frame) < 36:
        raise ValidationError('Truncated beacon')
    # Reject protected management frames rather than interpreting encrypted bytes.
    if frame[0] & 3 or frame[1] & 0xC3:
        raise ValidationError('Protected beacon unsupported')
    bssid = ':'.join(f'{byte:02x}' for byte in frame[16:22])
    capability = struct.unpack_from('<H', frame, 34)[0]
    elements, offset = {}, 36
    while offset < len(frame):
        if offset + 2 > len(frame):
            raise ValidationError('Truncated information element')
        tag, size = frame[offset:offset + 2]
        offset += 2
        if offset + size > len(frame):
            raise ValidationError('Invalid information element length')
        if tag in (0, 48) and tag in elements:
            raise ValidationError('Duplicate SSID or RSN')
        if tag in (0, 48):
            elements[tag] = frame[offset:offset + size]
        offset += size
    ssid = elements.get(0)
    if ssid is None or len(ssid) > 32:
        raise ValidationError('Missing or invalid SSID')
    security, pmf = ('legacy-protected', 'unknown') if capability & 0x10 else ('open', 'disabled')
    if 48 in elements:
        if not capability & 0x10:
            raise ValidationError('RSN advertisement without privacy capability')
        security, pmf = _rsn(elements[48])
    return dict(bssid=bssid, ssid_hex=ssid.hex(), security=security, pmf=pmf)


def analyze_capture(path):
    """Strict framing errors abort; malformed beacons are counted, not trusted."""
    from .resources import regular_file
    path = Path(path)
    regular_file(path, MAX_CAPTURE_BYTES)
    identities, malformed, ignored, packets = {}, 0, 0, 0
    digest = hashlib.sha256()
    total = 0
    with path.open('rb') as source:
        def read(size):
            nonlocal total
            value = source.read(size)
            total += len(value)
            if total > MAX_CAPTURE_BYTES:
                raise ValidationError('Capture exceeds size limit')
            digest.update(value)
            return value
        header = read(24)
        formats = {b'\xd4\xc3\xb2\xa1': '<', b'\xa1\xb2\xc3\xd4': '>',
                   b'\x4d\x3c\xb2\xa1': '<', b'\xa1\xb2\x3c\x4d': '>'}
        if len(header) != 24 or header[:4] not in formats:
            raise ValidationError('Only classic PCAP is supported, not PCAPNG')
        endian = formats[header[:4]]
        major, minor, _, _, snaplen, linktype = struct.unpack(endian + 'HHIIII', header[4:])
        if (major, minor) != (2, 4) or not 1 <= snaplen <= 65535 or linktype not in (105, 127):
            raise ValidationError('Unsupported PCAP version, snaplen, or linktype')
        while True:
            record = read(16)
            if not record:
                break
            packets += 1
            if packets > MAX_PACKETS or len(record) != 16:
                raise ValidationError('Invalid PCAP record or packet limit exceeded')
            _, _, captured, original = struct.unpack(endian + 'IIII', record)
            if captured > snaplen or captured > original:
                raise ValidationError('Invalid PCAP packet size')
            packet = read(captured)
            if len(packet) != captured:
                raise ValidationError('Truncated PCAP packet')
            if captured < original:
                malformed += 1
                continue
            try:
                beacon = _beacon(_radiotap(packet) if linktype == 127 else packet)
            except ValidationError:
                malformed += 1
                continue
            if beacon is None:
                ignored += 1
                continue
            key = tuple(beacon.values())
            if key not in identities:
                if len(identities) >= MAX_IDENTITIES:
                    raise ValidationError('Too many advertised identities')
                identities[key] = dict(beacon, beacon_count=0)
            identities[key]['beacon_count'] += 1
    return dict(schema_version=1, assessment_type='offline-beacon-analysis', capture_sha256=digest.hexdigest(),
                packet_count=packets, ignored_packets=ignored, malformed_or_truncated=malformed,
                observations=sorted(identities.values(), key=lambda item: tuple(str(v) for v in item.values())),
                limitations=['Advertised beacon settings only; no client behavior or identity authenticity verified.',
                             'No data/authentication payloads are decoded. BSSID and SSID bytes remain sensitive.',
                             'Unsupported suites remain unknown; legacy-protected does not distinguish WEP from WPA1.'])


def compare_baseline(capture, baseline):
    import re
    _object(baseline, {'schema_version', 'scope', 'approved_aps'}, {'schema_version', 'scope', 'approved_aps'}, 'baseline')
    if type(baseline['schema_version']) is not int or baseline['schema_version'] != 1:
        raise ValidationError('Invalid baseline version')
    _object(baseline['scope'], {'label', 'authorized'}, {'label', 'authorized'}, 'scope')
    _text(baseline['scope']['label'], 'scope.label')
    if baseline['scope']['authorized'] is not True:
        raise ValidationError('Explicit authorization required')
    aps = baseline['approved_aps']
    if not isinstance(aps, list) or not 1 <= len(aps) <= MAX_IDENTITIES:
        raise ValidationError('Invalid approved AP list')
    approved = {}
    for ap in aps:
        _object(ap, {'bssid', 'ssid_hex', 'security', 'pmf'}, {'bssid', 'ssid_hex', 'security', 'pmf'}, 'approved AP')
        if not isinstance(ap['bssid'], str) or not re.fullmatch(r'(?:[0-9a-f]{2}:){5}[0-9a-f]{2}', ap['bssid']):
            raise ValidationError('BSSID must be lowercase hexadecimal')
        if not isinstance(ap['ssid_hex'], str) or not re.fullmatch(r'(?:[0-9a-f]{2}){0,32}', ap['ssid_hex']):
            raise ValidationError('Invalid SSID hex')
        if ap['security'] not in ('open', 'legacy-protected', 'wpa2-personal', 'wpa3-personal', 'wpa2-wpa3-personal', 'rsn-enterprise') or ap['pmf'] not in ('disabled', 'optional', 'required'):
            raise ValidationError('Baseline needs known security/PMF expectations')
        if ap['bssid'] in approved:
            raise ValidationError('Duplicate baseline BSSID')
        approved[ap['bssid']] = ap
    findings = []
    observed = set()
    for ap in capture['observations']:
        observed.add(ap['bssid'])
        expected = approved.get(ap['bssid'])
        changed = [field for field in ('ssid_hex', 'security', 'pmf') if expected and ap[field] != expected[field]]
        if expected is None or changed:
            findings.append(dict(bssid=ap['bssid'], status='review', check_id='AP-UNEXPECTED' if expected is None else 'AP-POLICY-CHANGED', changed_fields=changed))
    for bssid in sorted(set(approved) - observed):
        findings.append(dict(bssid=bssid, status='unknown', check_id='AP-NOT-OBSERVED', changed_fields=[]))
    return dict(schema_version=1, assessment_type='offline-ap-baseline', scope=baseline['scope']['label'],
                capture_sha256=capture['capture_sha256'], findings=findings,
                limitations=['Differences require investigation, not proof of a rogue AP.',
                             'Matching BSSIDs can be spoofed; a match does not establish trust.',
                             'Absence from a capture does not establish that an AP is offline.'])
