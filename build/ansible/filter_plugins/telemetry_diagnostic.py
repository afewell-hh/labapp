"""Pure, bounded telemetry diagnostics; never return raw command output."""
import json
import re


def _redact(value):
    text = value if isinstance(value, str) else ''
    if len(text) > 262144:
        return '[OVERSIZED DIAGNOSTIC REDACTED]'
    text = re.sub(r'(?:\x1b\]|\x9d).*?(?:\x07|\x1b\\|\x9c|$)', '', text, flags=re.S)
    text = re.sub(r'(?:\x1b\[|\x9b)[0-?]*[ -/]*[@-~]', '', text)
    text = re.sub(r'\x1b[@-_]|[\x00-\x1f\x7f-\x9f]', '', text)
    text = re.sub(r'-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|$)',
                  '[REDACTED PRIVATE KEY]', text, flags=re.S)
    text = re.sub(r'\$(?:5|6)\$(?:rounds=\d+\$)?[^\s$"\']+\$[A-Za-z0-9./]+', '[REDACTED]', text)
    text = re.sub(r'\b(?:github_pat_|gh[pousr]_)[A-Za-z0-9_]{12,}', '[REDACTED]', text)
    text = re.sub(r'\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+', r'\1 [REDACTED]', text, flags=re.I)
    keyed = r'''(?<![A-Za-z0-9_-])(["']?(?:password|passwd|token|joinToken|join_token|client-key-data|client_key_data|authorization|api_key)["']?\s*[:=]\s*)(?:"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|[^\r\n,;}\]]+)'''
    text = re.sub(keyed, r'\1[REDACTED]', text, flags=re.I)
    return re.sub(r'[A-Za-z0-9+/_-]{64,}={0,2}', '[REDACTED]', text)


def _rc(result):
    value = result.get('rc', -1) if isinstance(result, dict) else -1
    return value if type(value) is int else -1


def labapp_telemetry_diagnostic(result):
    result = result if isinstance(result, dict) else {}
    stderr, msg = _redact(result.get('stderr')), _redact(result.get('msg'))
    text, rc = (stderr + '\n' + msg).lower(), _rc(result)
    failed = any(result.get(key, False) is not False for key in ('failed', 'unreachable'))
    category = 'success' if rc == 0 and not failed else 'unclassified'
    if rc == 0 and failed:
        category = 'unreachable' if result.get('unreachable') is not False and 'unreachable' in result else 'task_failed'
    rules = [
        ('admission_unavailable', ['failed calling webhook', 'no endpoints available']),
        ('admission_rejected', ['denied the request']),
        ('unauthorized', ['unauthorized']), ('forbidden', ['forbidden']),
        ('requested_resource_missing', ['could not find the requested resource', 'requested resource was not found']),
        ('no_such_file', ['no such file']), ('permission_denied', ['permission denied']),
        ('not_found', ['notfound', 'not found']), ('invalid', ['invalid']),
        ('tls', ['x509', 'tls']), ('connection', ['connection refused', 'unable to connect']),
        ('timeout', ['timeout', 'timed out', 'deadline exceeded']),
    ]
    if rc != 0 or failed:
        category = next((name for name, terms in rules if any(term in text for term in terms)), category)
    # Redact the complete value first: a secret crossing the excerpt boundary
    # must not leave its prefix behind. Excerpts are Unicode character bounds.
    return {'rc': rc, 'category': category, 'stderr_excerpt': stderr[:512], 'msg_excerpt': msg[:512]}


def _name(value):
    if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,252}', value):
        return 'Unknown'
    return _redact(value)[:96]


def _number(value):
    return value if type(value) is int and 0 <= value <= 2**63 - 1 else 0


def _rows(value, limit=100):
    return value[:limit] if isinstance(value, list) else []


def _dict(value):
    return value if isinstance(value, dict) else {}


def _document(result):
    if not isinstance(result, dict):
        return None, {'rc': -1, 'category': 'malformed_result'}
    summary = labapp_telemetry_diagnostic(result)
    closed = {'rc': summary['rc'], 'category': summary['category']}
    if closed['category'] != 'success':
        return None, closed
    try:
        value = json.loads(result.get('stdout', ''))
    except (TypeError, ValueError):
        return None, {'rc': closed['rc'], 'category': 'malformed_json'}
    if not isinstance(value, dict):
        return None, {'rc': closed['rc'], 'category': 'malformed_json'}
    return value, closed


def labapp_telemetry_cluster_state(results):
    results = results if isinstance(results, list) else []
    output = {}
    for index, kind in enumerate(('pods', 'endpoints', 'fabricator')):
        value, summary = _document(results[index] if index < len(results) else None)
        output[kind] = summary
        if kind == 'fabricator':
            summary.update({'generation': 0, 'conditions': []})
        else:
            summary['items'] = []
        if value is None:
            continue
        if kind != 'fabricator' and not isinstance(value.get('items'), list):
            summary['category'] = 'malformed_json'
            continue
        if ((kind == 'fabricator' and not isinstance(value.get('metadata'), dict)) or
                (kind != 'fabricator' and any(not isinstance(item, dict) for item in value['items']))):
            summary['category'] = 'malformed_json'
            continue
        if kind == 'pods':
            for raw in _rows(value['items']):
                item = _dict(raw)
                status = _dict(item.get('status'))
                containers = [_dict(c) for c in _rows(status.get('containerStatuses'))]
                phase = status.get('phase')
                summary['items'].append({
                    'name': _name(_dict(item.get('metadata')).get('name')),
                    'phase': phase if phase in ('Pending', 'Running', 'Succeeded', 'Failed', 'Unknown') else 'Unknown',
                    'ready': sum(c.get('ready') is True for c in containers),
                    'total': len(containers),
                    'restarts': min(2**63 - 1, sum(_number(c.get('restartCount')) for c in containers)),
                })
        elif kind == 'endpoints':
            for raw in _rows(value['items']):
                item, ready_count, not_ready_count, ports = _dict(raw), 0, 0, []
                for subset in _rows(item.get('subsets')):
                    subset = _dict(subset)
                    ready_count += len(_rows(subset.get('addresses')))
                    not_ready_count += len(_rows(subset.get('notReadyAddresses')))
                    for raw_port in _rows(subset.get('ports')):
                        port = _dict(raw_port)
                        if type(port.get('port')) is int and 1 <= port['port'] <= 65535:
                            protocol = port.get('protocol', 'TCP')
                            ports.append({'name': _name(port.get('name')),
                                          'port': port['port'],
                                          'protocol': protocol if protocol in ('TCP', 'UDP', 'SCTP') else 'Unknown'})
                summary['items'].append({'name': _name(_dict(item.get('metadata')).get('name')),
                                         'address_count': ready_count + not_ready_count,
                                         'ready_address_count': ready_count,
                                         'not_ready_address_count': not_ready_count, 'ports': ports[:100]})
        else:
            summary['generation'] = _number(_dict(value.get('metadata')).get('generation'))
            for raw in _rows(_dict(value.get('status')).get('conditions'), 20):
                condition = _dict(raw)
                status = condition.get('status')
                summary['conditions'].append({'type': _name(condition.get('type')),
                                              'status': status if status in ('True', 'False', 'Unknown') else 'Unknown',
                                              'reason': _name(condition.get('reason'))})
    return output


class FilterModule:
    def filters(self):
        return {'labapp_telemetry_diagnostic': labapp_telemetry_diagnostic,
                'labapp_telemetry_cluster_state': labapp_telemetry_cluster_state}
